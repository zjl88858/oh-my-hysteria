// SPDX-License-Identifier: MIT-0

package copa

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func send(s *Sender, pn int, at time.Duration, mtu bool) {
	s.OnPacketSentContext(congestion.SentPacketContext{
		Time: monotime.Time(at), Space: congestion.SpaceApplication,
		PacketNumber: congestion.PacketNumber(pn), Bytes: 1200, BytesInFlight: 1200, ApplicationBytesInFlight: 1200, AckEliciting: true, MTUProbe: mtu,
	})
}

func ack(s *Sender, at, rtt time.Duration, numbers ...int) {
	e := congestion.CongestionEventContext{Time: monotime.Time(at), Space: congestion.SpaceApplication, RTT: rtt, RTTUpdated: rtt > 0}
	for _, n := range numbers {
		e.Acked = append(e.Acked, congestion.AckedPacketInfo{PacketNumber: congestion.PacketNumber(n), BytesAcked: 999999})
	}
	s.OnCongestionEventContext(e)
}

func TestStartupAndDelayExit(t *testing.T) {
	s := NewSender(1200)
	require.True(t, s.InSlowStart())
	require.False(t, s.InRecovery())
	require.Equal(t, congestion.ByteCount(38400), s.GetCongestionWindow())
	require.True(t, s.CanSend(38399))
	require.False(t, s.CanSend(38400))
	require.False(t, s.CanSend(-1))
	var numbers []int
	for i := range 32 {
		send(s, i, 0, false)
		numbers = append(numbers, i)
	}
	ack(s, 100*time.Millisecond, 100*time.Millisecond, numbers...)
	require.Equal(t, uint64(76800), s.cwnd)                  // one RTT's ACKs double startup
	require.Equal(t, uint64(38400), s.Snapshot().AckedBytes) // not callback byte claims
	send(s, 32, 101*time.Millisecond, false)
	ack(s, 400*time.Millisecond, 300*time.Millisecond, 32)
	require.False(t, s.InSlowStart())
	require.Less(t, s.cwnd, uint64(76800))
	require.Equal(t, 200*time.Millisecond, s.queue)
	require.Equal(t, "Steady", s.Snapshot().State)
	require.Equal(t, mulDiv(s.cwnd, 2*uint64(time.Second), uint64(300*time.Millisecond)), s.rate)
	// The same ACK cannot grow the window, refresh RTT or start a round twice.
	before := s.Snapshot()
	ack(s, 401*time.Millisecond, time.Nanosecond, 32)
	after := s.Snapshot()
	require.Equal(t, before.Cwnd, after.Cwnd)
	require.Equal(t, before.Round, after.Round)
	require.Equal(t, before.MinRTT, after.MinRTT)
	require.Equal(t, uint64(1), after.UnknownACKs)
}

func TestVelocityRationalStepAndGrowthBound(t *testing.T) {
	s := NewSender(1200)
	s.slowStart = false
	s.updateVelocity(true, true)
	for range 3 {
		s.cwnd += 1200
		s.updateVelocity(true, true)
	}
	require.Equal(t, uint64(2), s.velocity)
	s.updateVelocity(false, false)
	require.Equal(t, uint64(1), s.velocity)
	for scale := uint64(1); scale <= 16; scale *= 2 {
		s.lossScale = scale
		s.cwnd = 100000
		s.velocity = 1
		n, d := s.inverseDelta()
		require.Equal(t, uint64(1200*1200)*n/(100000*d), s.step(1200))
	}
	s.velocity = math.MaxUint64
	s.lossScale = 1
	s.cwnd = 100000
	require.LessOrEqual(t, s.step(s.cwnd), s.cwnd)
	s.roundWindow = 100000
	s.roundGrowth = 0
	s.changeWindow(math.MaxUint64, true)
	s.changeWindow(math.MaxUint64, true)
	require.Equal(t, uint64(200000), s.cwnd)
	s.changeWindow(math.MaxUint64, false)
	require.Equal(t, s.floor(), s.cwnd)
	s.changeWindow(0, false)
}

func TestLossGuardOncePerRoundAndLossOnly(t *testing.T) {
	s := NewSender(1200)
	for i := range 10 {
		send(s, i, 0, false)
	}
	s.OnCongestionEventContext(congestion.CongestionEventContext{
		Space: congestion.SpaceApplication, Time: monotime.Time(time.Millisecond),
		Lost: []congestion.LostPacketInfo{{PacketNumber: 0}, {PacketNumber: 0}},
	})
	require.Equal(t, uint64(1200), s.lost)
	require.Equal(t, uint64(0), s.round)
	require.Zero(t, s.minRTT)
	ack(s, 100*time.Millisecond, 100*time.Millisecond, 1)
	require.True(t, s.lossGuard)
	require.Equal(t, .08, s.Snapshot().Delta)
	for i := 2; i < 10; i++ {
		ack(s, time.Duration(100+i)*time.Millisecond, 100*time.Millisecond, i)
	}
	require.Equal(t, .08, s.Snapshot().Delta) // ACK frequency must not repeatedly double delta
	send(s, 10, 120*time.Millisecond, false)
	ack(s, 220*time.Millisecond, 100*time.Millisecond, 10)
	require.False(t, s.lossGuard)
	require.Equal(t, .04, s.Snapshot().Delta)
	// No cwnd cut is performed for a single ordinary loss, unlike Reno.
	before := s.cwnd
	send(s, 11, 230*time.Millisecond, false)
	s.OnCongestionEventContext(congestion.CongestionEventContext{Space: congestion.SpaceApplication, Time: monotime.Time(240 * time.Millisecond), Lost: []congestion.LostPacketInfo{{PacketNumber: 11}}})
	require.Equal(t, before, s.cwnd)
	s.OnSpuriousPacket(11, monotime.Time(250*time.Millisecond))
	require.Equal(t, before, s.cwnd)
}

func TestCEOncePerFlightAndNoStaleRTT(t *testing.T) {
	s := NewSender(1200)
	send(s, 0, 0, false)
	send(s, 1, 0, false)
	e := congestion.CongestionEventContext{Space: congestion.SpaceApplication, Time: 1, ECNCongestion: true, RTTUpdated: true, RTT: time.Nanosecond}
	s.OnCongestionEventContext(e)
	first := s.cwnd
	require.Equal(t, uint64(26880), first)
	require.Zero(t, s.minRTT)
	send(s, 2, 2, false)
	e.Time = 3
	s.OnCongestionEventContext(e)
	require.Equal(t, first, s.cwnd)
	require.Equal(t, uint64(1), s.ceCount)
	e.Time = 4
	e.Acked = []congestion.AckedPacketInfo{{PacketNumber: 2}}
	s.OnCongestionEventContext(e)
	require.Equal(t, mulDiv(first, 7, 10), s.cwnd)
	require.Equal(t, uint64(2), s.ceCount)
	// Handshake callbacks cannot import RTT or a CE cut into the application model.
	before := s.Snapshot()
	e.Space = congestion.SpaceHandshake
	e.Time = 5
	s.OnCongestionEventContext(e)
	require.Equal(t, before, s.Snapshot())
}

func TestAppLimitedMTUAndRetirement(t *testing.T) {
	s := NewSender(1200)
	s.OnPacketSentContext(congestion.SentPacketContext{Space: congestion.SpaceInitial, Time: 0, Bytes: 1200, AckEliciting: true})
	send(s, 0, time.Millisecond, false)
	s.OnApplicationLimited(monotime.Time(2*time.Millisecond), 1200)
	before := s.cwnd
	ack(s, 100*time.Millisecond, 100*time.Millisecond, 0)
	require.Equal(t, before, s.cwnd)
	require.Equal(t, uint64(1200), s.acked)
	send(s, 1, 101*time.Millisecond, true)
	ack(s, 102*time.Millisecond, time.Nanosecond, 1)
	require.Equal(t, 100*time.Millisecond, s.minRTT)
	require.Equal(t, uint64(1200), s.acked)
	send(s, 2, 103*time.Millisecond, true)
	s.OnCongestionEventContext(congestion.CongestionEventContext{Space: congestion.SpaceApplication, Time: monotime.Time(104 * time.Millisecond), Lost: []congestion.LostPacketInfo{{PacketNumber: 2}}})
	require.Zero(t, s.lost)
	send(s, 3, 105*time.Millisecond, false)
	s.OnPacketRemoved(congestion.SpaceHandshake, 3, congestion.RemovalKeys)
	require.Len(t, s.packets, 1)
	s.OnPacketRemoved(congestion.SpaceApplication, 3, congestion.RemovalPTO)
	ack(s, 200*time.Millisecond, time.Nanosecond, 3)
	require.Equal(t, uint64(1200), s.acked)
	require.Equal(t, before, s.cwnd)
	s.SetMaxDatagramSize(1400)
	require.Equal(t, uint64(44800), s.cwnd)
	require.Panics(t, func() { s.SetMaxDatagramSize(1300) })
	s.OnPathReset(monotime.Time(time.Second), 1280)
	require.True(t, s.slowStart)
	require.Equal(t, uint64(40960), s.cwnd)
	require.Empty(t, s.packets)
	require.Zero(t, s.minRTT)
	require.Equal(t, uint64(1), s.resets)
	require.Equal(t, uint64(1), s.velocity)
}

func TestLegacyCallbacksAndInvalidEvents(t *testing.T) {
	s := NewSender(0)
	before := s.Snapshot()
	s.OnPacketSent(0, 1200, 0, 1200, true)
	s.OnPacketAcked(0, 1200, 1200, 1)
	s.OnCongestionEvent(0, 1200, 1200)
	s.MaybeExitSlowStart()
	s.OnRetransmissionTimeout(true)
	require.Equal(t, before, s.Snapshot())
	send(s, 0, time.Second, false)
	send(s, 1, 0, false)
	require.Zero(t, s.faults)
	require.Len(t, s.packets, 2)
	send(s, 0, 2*time.Second, false) // duplicate send fails closed, not duplicate credit
	require.Equal(t, uint64(1), s.faults)
	require.Empty(t, s.packets)
	require.Equal(t, uint64(0), s.resets)
}

func TestConcurrentSnapshotAndPacing(t *testing.T) {
	s := NewSender(1200)
	require.True(t, s.HasPacingBudget(0))
	require.Zero(t, s.TimeUntilSend(0))
	for i := range 10 {
		send(s, i, 0, false)
	}
	require.False(t, s.HasPacingBudget(0))
	require.Greater(t, s.TimeUntilSend(0), monotime.Time(0))
	require.True(t, s.HasPacingBudget(monotime.Time(time.Second)))
	require.GreaterOrEqual(t, s.SendQuantum(), congestion.ByteCount(1200))
	require.LessOrEqual(t, s.SendQuantum(), congestion.ByteCount(65536))
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 200 {
			_ = s.Snapshot()
			_ = s.GetCongestionWindow()
			_ = s.InSlowStart()
		}
	})
	for i := 10; i < 210; i++ {
		send(s, i, time.Duration(i)*time.Millisecond, false)
		ack(s, time.Duration(i)*time.Millisecond, time.Millisecond, i)
	}
	wg.Wait()
}
