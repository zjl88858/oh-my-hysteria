// SPDX-License-Identifier: MIT-0

package geodesic

import (
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func send(s *Sender, pn int, at time.Duration, flight int, mtu bool) {
	s.OnPacketSentContext(congestion.SentPacketContext{
		Time: monotime.Time(at), Space: congestion.SpaceApplication,
		PacketNumber: congestion.PacketNumber(pn), Bytes: 1200, BytesInFlight: congestion.ByteCount(flight), ApplicationBytesInFlight: congestion.ByteCount(flight), AckEliciting: true, MTUProbe: mtu,
	})
}

func ack(s *Sender, at, rtt time.Duration, flight int, numbers ...int) {
	e := congestion.CongestionEventContext{
		Time: monotime.Time(at), Space: congestion.SpaceApplication,
		ApplicationBytesInFlight: congestion.ByteCount(flight), RTT: rtt, RTTUpdated: rtt > 0,
	}
	for _, pn := range numbers {
		e.Acked = append(e.Acked, congestion.AckedPacketInfo{PacketNumber: congestion.PacketNumber(pn), BytesAcked: 999999})
	}
	s.OnCongestionEventContext(e)
}

func lose(s *Sender, at time.Duration, flight int, numbers ...int) {
	e := congestion.CongestionEventContext{Time: monotime.Time(at), Space: congestion.SpaceApplication, ApplicationBytesInFlight: congestion.ByteCount(flight)}
	for _, pn := range numbers {
		e.Lost = append(e.Lost, congestion.LostPacketInfo{PacketNumber: congestion.PacketNumber(pn), BytesLost: 999999})
	}
	s.OnCongestionEventContext(e)
}

func TestSenderStartupDrainAndBoundedProbePhases(t *testing.T) {
	s := NewSender(1200)
	require.True(t, s.InSlowStart())
	require.False(t, s.InRecovery())
	require.Equal(t, congestion.ByteCount(38400), s.GetCongestionWindow())
	for i := range 4 {
		send(s, i, time.Duration(i)*100*time.Millisecond, 1200, false)
		ack(s, time.Duration(i+1)*100*time.Millisecond, 100*time.Millisecond, 0, i)
	}
	require.True(t, s.fullReached)
	require.Equal(t, drain, s.state)
	send(s, 4, 400*time.Millisecond, 1200, false)
	ack(s, 601*time.Millisecond, 100*time.Millisecond, 0, 4)
	require.Equal(t, probeBW, s.state)
	// Probe-up's target can be unreachable; it must still end by 2 RTTs.
	s.phase = 0
	s.cycleStamp = s.now
	s.inFlight = 0
	s.now = s.now.Add(201 * time.Millisecond)
	s.advance(rateSample{hasData: true}, false, false)
	require.Equal(t, uint8(1), s.phase)
	s.now = s.now.Add(401 * time.Millisecond)
	s.inFlight = s.maximum()
	s.advance(rateSample{hasData: true}, false, false)
	require.Equal(t, uint8(2), s.phase)
	for phase := uint8(3); phase <= 7; phase++ {
		s.now = s.now.Add(101 * time.Millisecond)
		s.advance(rateSample{hasData: true}, false, false)
		require.Equal(t, phase, s.phase)
	}
	s.now = s.now.Add(101 * time.Millisecond)
	s.advance(rateSample{hasData: true}, false, false)
	require.Zero(t, s.phase)
	require.Zero(t, s.faults)
}

func TestSenderApplicationLimitedAndRealDeliveryRound(t *testing.T) {
	s := NewSender(1200)
	s.OnApplicationLimited(0, 0)
	for i := range 6 {
		send(s, i, time.Duration(i)*time.Second, 1200, false)
		ack(s, time.Duration(i)*time.Second+100*time.Millisecond, 100*time.Millisecond, 0, i)
		s.OnApplicationLimited(monotime.Time(time.Duration(i)*time.Second+200*time.Millisecond), 0)
	}
	require.False(t, s.fullReached)
	require.Equal(t, startup, s.state)
	// One ACK for a hundred packets is one fresh RTT, not 100 rounds.
	s = NewSender(1200)
	var numbers []int
	for i := range 100 {
		send(s, i, time.Duration(i)*time.Microsecond, (i+1)*1200, false)
		numbers = append(numbers, i)
	}
	ack(s, 100*time.Millisecond, 100*time.Millisecond, 0, numbers...)
	require.Equal(t, uint64(1), s.round)
	require.Equal(t, uint64(1), s.geo.samples)
	require.Equal(t, uint64(120000), s.sampler.totals.delivered)
}

func TestSenderLossOnlySpuriousAndRetirement(t *testing.T) {
	s := NewSender(1200)
	send(s, 0, 0, 1200, false)
	send(s, 1, time.Millisecond, 2400, false)
	initial := s.cwnd
	lose(s, 50*time.Millisecond, 0, 0, 1, 0)
	require.Equal(t, initial-2400, s.cwnd)
	require.Equal(t, uint64(2400), s.sampler.totals.congestionLost)
	require.True(t, s.InRecovery())
	require.Zero(t, s.round)
	require.Zero(t, s.geo.samples)
	s.OnSpuriousPacket(0, monotime.Time(100*time.Millisecond))
	require.True(t, s.InRecovery())
	require.Less(t, s.cwnd, initial)
	s.OnSpuriousPacket(1, monotime.Time(100*time.Millisecond))
	require.False(t, s.InRecovery())
	require.Equal(t, initial, s.cwnd)
	require.Equal(t, uint64(1), s.undoCount)
	send(s, 2, 101*time.Millisecond, 1200, false)
	lose(s, 102*time.Millisecond, 0, 2)
	s.OnPacketRemoved(congestion.SpaceApplication, 2, congestion.RemovalHistory)
	s.OnSpuriousPacket(2, monotime.Time(110*time.Millisecond))
	require.Equal(t, uint64(1), s.undoCount)
}

func TestSenderPMTUUnknownAndOtherSpaceDoNotFakeRTT(t *testing.T) {
	s := NewSender(1200)
	send(s, 0, 0, 1200, true)
	s.OnCongestionEventContext(congestion.CongestionEventContext{
		Time: 1, Space: congestion.SpaceApplication, RTTUpdated: true, RTT: time.Nanosecond,
		Acked: []congestion.AckedPacketInfo{{PacketNumber: 0, MTUProbe: true}}, Lost: []congestion.LostPacketInfo{{PacketNumber: 0, MTUProbe: true}},
	})
	require.Zero(t, s.geo.samples)
	require.Zero(t, s.sampler.totals.congestionLost)
	require.Zero(t, s.unknown)
	ack(s, 2, time.Nanosecond, 0, 999)
	require.Zero(t, s.geo.samples)
	before := s.Snapshot()
	s.OnCongestionEventContext(congestion.CongestionEventContext{Time: 3, Space: congestion.SpaceHandshake, ECNCongestion: true, RTTUpdated: true, RTT: time.Nanosecond})
	require.Equal(t, before, s.Snapshot())
	send(s, 1, time.Millisecond, 1200, false)
	s.OnPacketRemoved(congestion.SpaceHandshake, 1, congestion.RemovalKeys)
	require.Len(t, s.sampler.packets, 1)
	s.OnPacketRemoved(congestion.SpaceApplication, 1, congestion.RemovalPTO)
	require.Empty(t, s.sampler.packets)
}

func TestSenderInterleavedReceiveTimeAndDuplicateACK(t *testing.T) {
	s := NewSender(1200)
	send(s, 0, 0, 1200, false)
	send(s, 1, 200*time.Millisecond, 2400, false)
	ack(s, 100*time.Millisecond, 100*time.Millisecond, 1200, 0)
	require.Zero(t, s.faults)
	require.Equal(t, uint64(1200), s.sampler.totals.delivered)
	require.Equal(t, monotime.Time(200*time.Millisecond), s.now)
	ack(s, 300*time.Millisecond, 100*time.Millisecond, 0, 1)
	samples, delivered := s.geo.samples, s.sampler.totals.delivered
	ack(s, 301*time.Millisecond, time.Nanosecond, 0, 1, 1)
	require.Equal(t, samples, s.geo.samples)
	require.Equal(t, delivered, s.sampler.totals.delivered)
}

func TestSenderCEAndPathReset(t *testing.T) {
	s := NewSender(1200)
	send(s, 0, 0, 1200, false)
	e := congestion.CongestionEventContext{Time: 1, Space: congestion.SpaceApplication, ECNCongestion: true, ApplicationBytesInFlight: 1200}
	s.OnCongestionEventContext(e)
	require.Equal(t, uint64(26880), s.cwnd)
	require.Equal(t, drain, s.state)
	e.Time = 2
	s.OnCongestionEventContext(e)
	require.Equal(t, uint64(26880), s.cwnd)
	require.Equal(t, uint64(1), s.ceCount)
	s.SetMaxDatagramSize(1400)
	require.GreaterOrEqual(t, s.cwnd, s.floor())
	require.Panics(t, func() { s.SetMaxDatagramSize(1300) })
	s.OnPathReset(3, 1280)
	require.Equal(t, uint64(40960), s.cwnd)
	require.Equal(t, uint64(1), s.resets)
	require.True(t, s.InSlowStart())
	require.Empty(t, s.sampler.packets)
	require.Zero(t, s.geo.samples)
	s = NewSender(1200)
	s.SetMaxDatagramSize(1400)
	require.Equal(t, uint64(44800), s.cwnd)
}

func TestLegacyPacingFaultsAndConcurrentSnapshot(t *testing.T) {
	s := NewSender(0)
	before := s.Snapshot()
	s.OnPacketSent(0, 1200, 0, 1200, true)
	s.OnPacketAcked(0, 1200, 1200, 1)
	s.OnCongestionEvent(0, 1200, 1200)
	s.MaybeExitSlowStart()
	s.OnRetransmissionTimeout(true)
	require.Equal(t, before, s.Snapshot())
	s = NewSender(1200)
	require.True(t, s.CanSend(0))
	require.False(t, s.CanSend(-1))
	require.False(t, s.CanSend(38400))
	require.True(t, s.HasPacingBudget(0))
	require.Zero(t, s.TimeUntilSend(0))
	for i := range 10 {
		send(s, i, 0, (i+1)*1200, false)
	}
	require.False(t, s.HasPacingBudget(0))
	require.Positive(t, s.TimeUntilSend(0))
	require.True(t, s.HasPacingBudget(monotime.Time(time.Second)))
	require.GreaterOrEqual(t, s.SendQuantum(), congestion.ByteCount(1200))
	require.LessOrEqual(t, s.SendQuantum(), congestion.ByteCount(65536))
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 200 {
			_ = s.Snapshot()
			_ = s.GetCongestionWindow()
		}
	})
	for i := 10; i < 210; i++ {
		send(s, i, time.Duration(i)*time.Millisecond, 1200, false)
		ack(s, time.Duration(i)*time.Millisecond+time.Nanosecond, time.Millisecond, 0, i)
	}
	wg.Wait()
	s.sampler.capacity = 1
	s.OnPathReset(monotime.Time(time.Second), 1200)
	s.sampler.capacity = 1
	send(s, 0, 2*time.Second, 1200, false)
	send(s, 1, 2*time.Second, 2400, false)
	require.Equal(t, uint64(1), s.faults)
	require.Empty(t, s.sampler.packets)
	s.OnApplicationLimited(monotime.Time(3*time.Second), -1)
	require.Equal(t, uint64(2), s.faults)
}
