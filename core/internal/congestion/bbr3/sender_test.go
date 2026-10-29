// SPDX-License-Identifier: MIT-0

package bbr3

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func senderSend(s *Sender, pn int, at time.Duration, flight int, probe bool) {
	s.OnPacketSentContext(congestion.SentPacketContext{
		Time: monotime.Time(at), Space: congestion.SpaceApplication,
		PacketNumber: congestion.PacketNumber(pn), Bytes: 1200, BytesInFlight: congestion.ByteCount(flight),
		ApplicationBytesInFlight: congestion.ByteCount(flight), AckEliciting: true, MTUProbe: probe,
	})
}

func senderAck(s *Sender, at time.Duration, flight int, pns ...int) {
	e := congestion.CongestionEventContext{
		Time: monotime.Time(at), Space: congestion.SpaceApplication,
		BytesInFlight: congestion.ByteCount(flight), ApplicationBytesInFlight: congestion.ByteCount(flight), RTT: 100 * time.Millisecond, RTTUpdated: true,
	}
	for _, pn := range pns {
		e.Acked = append(e.Acked, congestion.AckedPacketInfo{PacketNumber: congestion.PacketNumber(pn), BytesAcked: 1200})
	}
	s.OnCongestionEventContext(e)
}

func senderLoss(s *Sender, at time.Duration, flight int, pns ...int) {
	e := congestion.CongestionEventContext{Time: monotime.Time(at), Space: congestion.SpaceApplication, ApplicationBytesInFlight: congestion.ByteCount(flight)}
	for _, pn := range pns {
		e.Lost = append(e.Lost, congestion.LostPacketInfo{PacketNumber: congestion.PacketNumber(pn), BytesLost: 1200})
	}
	s.OnCongestionEventContext(e)
}

func TestSenderStartupPlateauAndProbeCycle(t *testing.T) {
	s := NewSender(1200)
	for i := range 4 {
		senderSend(s, i, time.Duration(i)*100*time.Millisecond, 1200, false)
		senderAck(s, time.Duration(i+1)*100*time.Millisecond, 0, i)
	}
	require.True(t, s.fullReached)
	require.Equal(t, probeDown, s.state)
	require.Equal(t, uint64(12000), s.maxBandwidth())
	// Do not reuse the ACK that entered DOWN as its round boundary.
	require.Equal(t, acksStopping, s.phase)
	s.roundsSinceProbe = 0
	s.probeWait = 3 * time.Second
	// Keep the BDP sufficiently large so the Reno timescale doesn't end CRUISE immediately.
	s.bwCurrent = 120000
	senderSend(s, 4, 400*time.Millisecond, 1200, false)
	senderAck(s, 500*time.Millisecond, 0, 4)
	require.Equal(t, probeCruise, s.state)
	require.Equal(t, acksInit, s.phase)
	s.cycleStamp = monotime.Time(-4 * time.Second)
	senderSend(s, 5, 500*time.Millisecond, 1200, false)
	senderAck(s, 600*time.Millisecond, 0, 5)
	require.Equal(t, probeRefill, s.state)
	senderSend(s, 6, 600*time.Millisecond, 1200, false)
	senderAck(s, 700*time.Millisecond, 0, 6)
	require.Equal(t, probeUp, s.state)
	require.True(t, s.probeSamples)
	require.Equal(t, acksStarting, s.phase)
	senderSend(s, 7, 700*time.Millisecond, 1200, false)
	senderAck(s, 800*time.Millisecond, 0, 7)
	require.Equal(t, acksFeedback, s.phase)
	require.Zero(t, s.Snapshot().SamplingErrors)
}

func TestSenderApplicationLimitedCannotEndStartup(t *testing.T) {
	s := NewSender(1200)
	s.OnApplicationLimited(0, 0)
	for i := range 4 {
		senderSend(s, i, time.Duration(i)*time.Second, 1200, false)
		senderAck(s, time.Duration(i)*time.Second+100*time.Millisecond, 0, i)
		s.OnApplicationLimited(monotime.Time(time.Duration(i)*time.Second+200*time.Millisecond), 0)
	}
	require.Equal(t, startup, s.state)
	require.False(t, s.fullReached)
	require.Equal(t, uint64(12000), s.maxBandwidth())
}

func TestSenderShortTermLossRoundIsIndependentOfRecoveryRound(t *testing.T) {
	s := NewSender(1200)
	s.state = probeCruise
	s.fullReached = true
	s.bwCurrent = 120000
	s.minRTT = 100 * time.Millisecond
	s.hasMin = true
	s.cycleStamp = 0
	s.probeWait = 3 * time.Second
	senderSend(s, 0, 0, 1200, false)
	senderSend(s, 1, time.Millisecond, 2400, false)
	senderLoss(s, 50*time.Millisecond, 1200, 0)
	require.Equal(t, unlimited, s.bwShort) // loss-only doesn't invent a completed round
	senderAck(s, 101*time.Millisecond, 0, 1)
	require.NotEqual(t, unlimited, s.bwShort)
	require.Equal(t, uint64(84000), s.bwShort)
	require.False(t, s.lossInRound)
	require.Less(t, s.flightShort, uint64(38400))
	before := s.bwShort
	senderAck(s, 110*time.Millisecond, 0) // no data, no additional reduction
	require.Equal(t, before, s.bwShort)
}

func TestSenderStartupRequiresFullRecoveryRoundAndSixRanges(t *testing.T) {
	for _, separated := range []bool{false, true} {
		t.Run(map[bool]string{false: "one-burst", true: "six-ranges"}[separated], func(t *testing.T) {
			s := NewSender(1200)
			for i := range 16 {
				senderSend(s, i, time.Duration(i)*time.Millisecond, (i+1)*1200, false)
			}
			senderLoss(s, 20*time.Millisecond, 18000, 0)
			senderAck(s, 120*time.Millisecond, 16800, 1)
			require.Equal(t, startup, s.state)
			// Data sent after the first recovery ACK establishes a full recovery round.
			for i := 16; i < 30; i++ {
				senderSend(s, i, 121*time.Millisecond+time.Duration(i-16)*time.Millisecond, (i-1)*1200, false)
			}
			if separated {
				senderLoss(s, 160*time.Millisecond, 18000, 2, 4, 6, 8, 10, 12)
			} else {
				senderLoss(s, 160*time.Millisecond, 18000, 2, 3, 4, 5, 6, 7)
			}
			senderAck(s, 240*time.Millisecond, 18000, 29)
			if separated {
				require.True(t, s.fullReached)
				require.NotEqual(t, startup, s.state)
				require.NotEqual(t, unlimited, s.flightLong)
			} else {
				require.False(t, s.fullReached)
				require.Equal(t, startup, s.state)
			}
		})
	}
}

func TestSenderProbeLossAndCompleteSpuriousUndo(t *testing.T) {
	s := NewSender(1200)
	s.fullReached = true
	s.state = probeUp
	s.probeSamples = true
	s.bwCurrent = 120000
	s.hasMin = true
	s.minRTT = 100 * time.Millisecond
	before := s.cwnd
	senderSend(s, 0, 0, 1200, false)
	senderSend(s, 1, time.Millisecond, 2400, false)
	senderLoss(s, 20*time.Millisecond, 0, 0, 1)
	require.Equal(t, probeDown, s.state)
	require.NotEqual(t, unlimited, s.flightLong)
	s.OnSpuriousPacket(0, monotime.Time(100*time.Millisecond))
	require.Zero(t, s.undoCount)
	require.Equal(t, probeDown, s.state)
	s.OnSpuriousPacket(1, monotime.Time(101*time.Millisecond))
	require.Equal(t, uint64(1), s.undoCount)
	require.Equal(t, probeRefill, s.state)
	require.Equal(t, unlimited, s.flightLong)
	require.GreaterOrEqual(t, s.cwnd, before)
	require.Equal(t, uint64(2400), s.sampler.totals.delivered)
	s.OnSpuriousPacket(1, monotime.Time(102*time.Millisecond))
	require.Equal(t, uint64(2400), s.sampler.totals.delivered)
}

func TestSenderRetiredLossAndCEPreventUndo(t *testing.T) {
	for _, ce := range []bool{false, true} {
		t.Run(map[bool]string{false: "retired", true: "CE"}[ce], func(t *testing.T) {
			s := NewSender(1200)
			senderSend(s, 0, 0, 1200, false)
			senderSend(s, 1, time.Millisecond, 2400, false)
			senderLoss(s, 20*time.Millisecond, 0, 0, 1)
			if ce {
				s.OnCongestionEventContext(congestion.CongestionEventContext{Time: monotime.Time(30 * time.Millisecond), Space: congestion.SpaceApplication, ECNCongestion: true})
			} else {
				s.OnPacketRemoved(congestion.SpaceApplication, 0, congestion.RemovalHistory)
			}
			s.OnSpuriousPacket(1, monotime.Time(100*time.Millisecond))
			require.Zero(t, s.undoCount)
		})
	}
}

func TestSenderPMTUDiscardPacketSpacesAndPathReset(t *testing.T) {
	s := NewSender(1200)
	s.OnPacketSentContext(congestion.SentPacketContext{Space: congestion.SpaceInitial, Bytes: 1200, AckEliciting: true})
	require.Zero(t, s.sampler.totals.sent)
	senderSend(s, 0, 0, 1400, true)
	senderLoss(s, 10*time.Millisecond, 0, 0)
	require.False(t, s.inRecovery)
	require.Zero(t, s.sampler.totals.congestionLost)
	s.OnPacketRemoved(congestion.SpaceHandshake, 0, congestion.RemovalKeys)
	require.Len(t, s.sampler.packets, 1)
	s.OnPacketRemoved(congestion.SpaceApplication, 0, congestion.RemovalPTO)
	require.Empty(t, s.sampler.packets)
	s.SetMaxDatagramSize(1400)
	require.Equal(t, uint64(1400), s.size)
	require.Panics(t, func() { s.SetMaxDatagramSize(1300) })
	s.OnPathReset(monotime.Time(time.Second), 1200)
	require.Equal(t, uint64(1), s.resets)
	require.Equal(t, startup, s.state)
	require.Zero(t, s.sampler.totals.sent)
	senderAck(s, 2*time.Second, 0, 0)
	require.Equal(t, uint64(1), s.unknown)
	require.Zero(t, s.faults)
}

func TestSenderProbeRTTDurationRoundAndIdle(t *testing.T) {
	s := NewSender(1200)
	s.setClock(0)
	s.fullReached = true
	s.state = probeCruise
	s.bwCurrent = 120000
	s.minRTT = 100 * time.Millisecond
	s.hasMin = true
	s.now = monotime.Time(6 * time.Second)
	s.updateMinRTT(120 * time.Millisecond)
	require.Equal(t, probeRTT, s.state)
	s.inFlight = 0
	s.handleProbeRTT(rateSample{}, false)
	s.updateControls(0)
	require.True(t, s.probeTimer)
	require.LessOrEqual(t, s.cwnd, s.probeWindow())
	s.round++
	s.now = s.probeDone.Add(-time.Millisecond)
	s.handleProbeRTT(rateSample{}, true)
	require.Equal(t, probeRTT, s.state)
	// The full round may finish before the 200ms wall-clock duration. A later
	// ACK in that same round must be able to finish ProbeRTT.
	s.now = s.probeDone
	s.handleProbeRTT(rateSample{}, false)
	require.Equal(t, probeCruise, s.state)
	s.now = s.now.Add(6 * time.Second)
	s.idleRestart = true
	s.updateMinRTT(130 * time.Millisecond)
	require.NotEqual(t, probeRTT, s.state)
	s.idleRestart = false
	s.now = s.now.Add(11 * time.Second)
	s.updateMinRTT(150 * time.Millisecond)
	require.Equal(t, 150*time.Millisecond, s.minRTT)
}

func TestSenderAggregationCEAndResourceBounds(t *testing.T) {
	s := NewSender(1200)
	s.bwCurrent = 120000
	s.setClock(0)
	s.updateAggregation(2400)
	require.Equal(t, uint64(2400), s.extraAcked)
	s.round = 1
	s.now = monotime.Time(time.Second)
	s.updateAggregation(1200)
	require.Equal(t, uint64(1200), s.extraAcked)
	s.fullReached = true
	s.round = 11
	s.updateAggregation(0)
	require.LessOrEqual(t, s.extraAcked, s.cwnd)
	s.respondCE()
	cwnd := s.cwnd
	s.respondCE()
	require.Equal(t, cwnd, s.cwnd)
	s.round++
	s.respondCE()
	require.Less(t, s.cwnd, cwnd)
	s.cwnd = math.MaxUint64
	s.flightShort = unlimited
	s.flightLong = unlimited
	s.updateControls(math.MaxUint64)
	require.LessOrEqual(t, s.cwnd, s.maximum())
	require.GreaterOrEqual(t, s.cwnd, s.floor())
	s.sampler.capacity = 1
	senderSend(s, 0, time.Second, 1200, false)
	senderSend(s, 1, time.Second, 2400, false)
	require.Equal(t, uint64(1), s.faults)
	require.Empty(t, s.sampler.packets)
	// Legacy callbacks are harmless even if transport invokes both contracts.
	s.OnPacketSent(0, 1200, 0, 1200, true)
	s.OnPacketAcked(0, 1200, 1200, 1)
	s.OnCongestionEvent(0, 1200, 1200)
	s.OnRetransmissionTimeout(true)
	s.MaybeExitSlowStart()
	require.Empty(t, s.sampler.packets)
}

func TestSenderSnapshotConcurrent(t *testing.T) {
	s := NewSender(1200)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 1000 {
			snap := s.Snapshot()
			if snap.Cwnd < 4800 {
				t.Errorf("invalid cwnd: %d", snap.Cwnd)
				return
			}
			s.GetCongestionWindow()
			s.InSlowStart()
			s.InRecovery()
			s.TimeUntilSend(0)
			s.HasPacingBudget(monotime.Time(time.Second))
			s.SendQuantum()
			s.CanSend(0)
		}
	}()
	for i := range 1000 {
		senderSend(s, i, time.Duration(i)*time.Millisecond, 1200, false)
		senderAck(s, time.Duration(i+1)*time.Millisecond, 0, i)
	}
	wg.Wait()
	require.Zero(t, s.faults)
}

func TestPacerArithmeticAndDeadlines(t *testing.T) {
	require.Equal(t, uint64(math.MaxUint64), mulDiv(math.MaxUint64, math.MaxUint64, 1))
	require.Equal(t, uint64(math.MaxUint64), mulDiv(1, 1, 0))
	require.Equal(t, uint64(math.MaxUint64), addBounded(math.MaxUint64, 1))
	require.Zero(t, durationBytes(100, -1))
	var p pacer
	require.Equal(t, int64(2400), p.budget(0, 12000, 2400))
	require.Zero(t, p.deadline(1200, 12000))
	p.sent(0, 2400, 12000, 2400)
	deadline := p.deadline(1200, 12000)
	require.GreaterOrEqual(t, deadline, monotime.Time(100*time.Millisecond))
	require.Less(t, p.budget(deadline.Add(-time.Millisecond), 12000, 2400), int64(1200))
	require.GreaterOrEqual(t, p.budget(deadline, 12000, 2400), int64(1200))
	require.Zero(t, p.budget(-1, 12000, 2400))
	p.sent(deadline, 65536, 12000, 2400)
	require.GreaterOrEqual(t, p.credit, int64(-65536))
	require.LessOrEqual(t, p.budget(monotime.Time(math.MaxInt64), math.MaxUint64, 65536), int64(65536))
}

func TestSenderProbeUpperBoundGrowthAndPrecaution(t *testing.T) {
	s := NewSender(1200)
	s.fullReached = true
	s.state = probeUp
	s.flightLong = 12000
	s.cwnd = 12000
	s.bwCurrent = 120000
	s.hasMin = true
	s.minRTT = 100 * time.Millisecond
	s.limitedPrevious = true
	s.upPerIncrease = 1200
	s.advanceProbe(rateSample{hasData: true, inFlightAtSend: 12000, newlyAcked: 2400, rate: 120000}, true)
	require.Equal(t, uint64(14400), s.flightLong)
	require.Greater(t, s.upRounds, uint(0))
	s.prevHigh = true
	s.inFlight = 14400
	s.advanceProbe(rateSample{hasData: true, inFlightAtSend: 14400}, false)
	require.Equal(t, probeDown, s.state)
	require.True(t, s.prevPrecaution)
	s.advanceProbe(rateSample{hasData: true, inFlightAtSend: 12000}, true)
	require.Equal(t, probeRefill, s.state) // no high loss: immediately retry after the precaution
	s.enterUp(120000)
	s.probeSamples = true
	s.advanceProbe(rateSample{hasData: true, inFlightAtSend: 12000, congestionLostSinceSent: 1200}, false)
	require.Equal(t, probeDown, s.state)
	require.True(t, s.prevHigh)
	// A low, application-limited sample must not age the max-bandwidth filter.
	s.bwPrevious = 240000
	s.bwCurrent = 120000
	s.prevPrecaution = false
	s.advanceProbe(rateSample{hasData: true, appLimited: true}, true)
	require.Equal(t, uint64(240000), s.maxBandwidth())
	s.state = probeUp
	s.fullNow = true
	s.limitedCurrent = false
	s.limitedPrevious = false
	s.advanceProbe(rateSample{hasData: true}, false)
	require.Equal(t, probeDown, s.state)
	s.state = probeCruise
	s.flightLong = 24000
	s.inFlight = 12000
	require.Equal(t, uint64(20400), s.withHeadroom())
	s.state = probeUp
	require.GreaterOrEqual(t, s.inflightTarget(100), s.floor()+2400)
}

func TestSenderStartupUndoAndNoUndoForPlateauExit(t *testing.T) {
	for _, lossExit := range []bool{false, true} {
		t.Run(map[bool]string{false: "plateau", true: "loss"}[lossExit], func(t *testing.T) {
			s := NewSender(1200)
			senderSend(s, 0, 0, 1200, false)
			senderLoss(s, 10*time.Millisecond, 0, 0)
			s.fullReached = true
			s.enterDrain()
			s.undo.restoreState = lossExit
			s.OnSpuriousPacket(0, monotime.Time(100*time.Millisecond))
			if lossExit {
				require.Equal(t, startup, s.state)
				require.False(t, s.fullReached)
			} else {
				require.Equal(t, drain, s.state)
				require.True(t, s.fullReached)
			}
		})
	}
}

func TestSenderIdlePacingResetAndProbeRTTStartupExit(t *testing.T) {
	s := NewSender(0)
	s.OnApplicationLimited(0, 0)
	s.state = probeCruise
	s.bwCurrent = 120000
	senderSend(s, 0, time.Second, 1200, false)
	require.True(t, s.idleRestart)
	require.Equal(t, uint64(120000), s.rate)
	s.state = probeRTT
	s.fullReached = false
	s.probeTimer = true
	s.probeRound = 0
	s.probeDone = 0
	senderSend(s, 1, 2*time.Second, 1200, false)
	require.Equal(t, startup, s.state)
	// No optional debug goroutine; serialization is the same as congestion events.
	s.debug = true
	s.trace()
	s.trace()
	s.now = s.now.Add(2 * time.Second)
	s.trace()
	require.True(t, s.debugStarted)
	require.False(t, s.CanSend(s.GetCongestionWindow()))
}
