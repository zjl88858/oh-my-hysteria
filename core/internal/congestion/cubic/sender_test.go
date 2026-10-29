// SPDX-License-Identifier: MIT-0

package cubic

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

type testRTT struct {
	congestion.RTTStatsProvider // Only the read methods below are used by Sender.
	latest, minimum             time.Duration
}

func (r *testRTT) LatestRTT() time.Duration   { return r.latest }
func (r *testRTT) MinRTT() time.Duration      { return r.minimum }
func (r *testRTT) SmoothedRTT() time.Duration { return r.latest }

func newTestSender(hyStart bool) *Sender {
	s := NewSender(1200, false, hyStart)
	s.SetRTTStatsProvider(&testRTT{latest: 100 * time.Millisecond, minimum: 100 * time.Millisecond})
	return s
}

func TestCubicGrowthAndFastConvergence(t *testing.T) {
	c := cubic{maxDatagramSize: 1200}
	require.Equal(t, congestion.ByteCount(84000), c.afterLoss(120000))
	require.Equal(t, congestion.ByteCount(120000), c.lastMax)
	require.Equal(t, congestion.ByteCount(58800), c.afterLoss(84000))
	require.Equal(t, congestion.ByteCount(71400), c.lastMax)
	previous := congestion.ByteCount(58800)
	start := monotime.Time(time.Second)
	for i := range 1000 {
		next := c.afterAck(1200, previous, 100*time.Millisecond, start.Add(time.Duration(i)*time.Millisecond))
		require.GreaterOrEqual(t, next, previous)
		require.LessOrEqual(t, next, previous+600)
		previous = next
	}
	require.Greater(t, previous, congestion.ByteCount(58800))
	// Very large elapsed time must be clamped before integer conversion.
	next := c.afterAck(1200, previous, time.Millisecond, start.Add(100*365*24*time.Hour))
	require.GreaterOrEqual(t, next, previous)
	require.LessOrEqual(t, next, previous+600)
}

func TestCubicCurveUsesActualDatagramSize(t *testing.T) {
	small := cubic{maxDatagramSize: 1200}
	large := cubic{maxDatagramSize: 2400}
	now := monotime.Time(time.Second)
	w1, w2 := congestion.ByteCount(120000), congestion.ByteCount(240000)
	for i := range 100 {
		when := now.Add(time.Duration(i) * 10 * time.Millisecond)
		w1 = small.afterAck(1200, w1, 100*time.Millisecond, when)
		w2 = large.afterAck(2400, w2, 100*time.Millisecond, when)
	}
	require.InDelta(t, float64(w1)*2, float64(w2), 2)
}

func TestSenderLossRecoveryECNAndRTO(t *testing.T) {
	s := newTestSender(true)
	now := monotime.Time(time.Second)
	s.OnPacketSent(now, s.window, 100, 1200, true)
	initial := s.window
	s.hyStart.css = true
	s.OnCongestionEvent(50, 0, s.window) // Zero lost bytes represents ECN.
	require.Equal(t, initial*7/10, s.window)
	require.False(t, s.InSlowStart())
	require.True(t, s.hyStart.disabled)
	require.False(t, s.hyStart.css)
	cutback := s.window
	s.OnCongestionEvent(99, 1200, s.window)
	require.Equal(t, cutback, s.window, "do not reduce twice in one recovery window")
	s.OnPacketAcked(99, 1200, s.window, now)
	require.True(t, s.InRecovery())
	require.Equal(t, cutback, s.window)
	s.OnPacketAcked(101, 1200, s.window, now.Add(time.Second))
	require.False(t, s.InRecovery())
	require.GreaterOrEqual(t, s.window, cutback)
	beforeRTO := s.window
	s.OnRetransmissionTimeout(false)
	require.Equal(t, beforeRTO, s.window)
	s.OnRetransmissionTimeout(true)
	require.Equal(t, congestion.ByteCount(2400), s.window)
	require.True(t, s.InSlowStart())
	require.True(t, s.hyStart.disabled, "HyStart++ is initial-startup only")
	s.MaybeExitSlowStart()
	require.Zero(t, s.pendingRTT)
	s.OnPacketAcked(102, 1200, s.window, now.Add(2*time.Second))
	require.Equal(t, congestion.ByteCount(3600), s.window, "ordinary slow start after RTO")
}

func TestSenderApplicationLimitedAndPacing(t *testing.T) {
	s := newTestSender(false)
	now := monotime.Time(time.Second)
	window := s.window
	s.OnPacketAcked(1, 1200, 1200, now)
	require.Equal(t, window, s.window)
	require.True(t, s.CanSend(window-1))
	require.False(t, s.CanSend(window))
	for i := range 10 {
		s.OnPacketSent(now, 0, congestion.PacketNumber(i), 1200, true)
	}
	require.False(t, s.HasPacingBudget(now))
	next := s.TimeUntilSend(0)
	require.True(t, next.After(now))
	require.True(t, s.HasPacingBudget(next))
	require.GreaterOrEqual(t, s.pacer.available(now.Add(-time.Millisecond)), congestion.ByteCount(0))
}

func TestSenderMTUAndMinimumWindow(t *testing.T) {
	s := newTestSender(true)
	s.SetMaxDatagramSize(1400)
	require.Equal(t, congestion.ByteCount(1400), s.cubic.maxDatagramSize)
	require.Equal(t, congestion.ByteCount(1400), s.pacer.size)
	s.OnRetransmissionTimeout(true)
	require.Equal(t, congestion.ByteCount(2800), s.window)
	s.SetMaxDatagramSize(1500)
	require.Equal(t, congestion.ByteCount(3000), s.window)
	require.Panics(t, func() { s.SetMaxDatagramSize(1200) })
}

func TestSenderLegacySlowStartRemainsAvailable(t *testing.T) {
	s := newTestSender(false)
	s.rtt.(*testRTT).latest = 120 * time.Millisecond
	for range 7 {
		s.MaybeExitSlowStart()
		require.True(t, s.InSlowStart())
	}
	s.MaybeExitSlowStart()
	require.False(t, s.InSlowStart())
	s = newTestSender(false)
	window := s.window
	s.OnPacketAcked(1, 10, window, monotime.Time(time.Second))
	require.Equal(t, window+1200, s.window, "retain the upstream legacy per-packet increase")
}

func TestSenderSamplesOncePerACKFrame(t *testing.T) {
	s := newTestSender(true)
	now := monotime.Time(time.Second)
	for i := congestion.PacketNumber(1); i <= 32; i++ {
		s.OnPacketSent(now, s.window, i, 1200, true)
	}
	s.MaybeExitSlowStart()
	var acked []congestion.AckedPacketInfo
	for i := congestion.PacketNumber(1); i <= 16; i++ {
		if i == 15 {
			continue // Leave a genuine hole for the later reordered ACK.
		}
		s.OnPacketAcked(i, 1200, s.window, now.Add(time.Second))
		acked = append(acked, congestion.AckedPacketInfo{PacketNumber: i, BytesAcked: 1200})
	}
	s.OnCongestionEventEx(s.window, now, acked, nil)
	require.Equal(t, 1, s.hyStart.samples)
	s.OnPacketAcked(17, 1200, s.window, now.Add(2*time.Second))
	s.OnCongestionEventEx(s.window, now, []congestion.AckedPacketInfo{{PacketNumber: 17}}, nil) // No RTT callback for this ACK.
	require.Equal(t, 1, s.hyStart.samples, "must not reuse the previous frame's sample")
	require.Zero(t, s.pendingRTT)
	s.MaybeExitSlowStart()
	s.OnPacketAcked(15, 1200, s.window, now.Add(3*time.Second))
	s.OnCongestionEventEx(s.window, now, []congestion.AckedPacketInfo{{PacketNumber: 15}}, nil)
	require.Equal(t, 1, s.hyStart.samples, "a reordered ACK must not count a stale RTT")
}

func TestSenderCSSGrowthAndExit(t *testing.T) {
	s := newTestSender(true)
	runRound(&s.hyStart, samples(100*time.Millisecond)...)
	runRound(&s.hyStart, samples(120*time.Millisecond)...)
	require.True(t, s.hyStart.css)
	before := s.window
	s.OnPacketAcked(1, 1200, s.window, monotime.Time(time.Second))
	require.Equal(t, before+300, s.window)
	// Exercise the transport-facing end-of-round callback at the CSS limit.
	s.hyStart.cssRounds = 4
	s.largestSent = s.hyStart.endPacket + 8
	s.largestAcked = s.hyStart.endPacket
	s.OnCongestionEventEx(s.window, monotime.Time(time.Second), []congestion.AckedPacketInfo{{PacketNumber: s.largestAcked}}, nil)
	require.False(t, s.InSlowStart())
	require.Equal(t, s.window, s.threshold)
}

func TestRenoHyStartCongestionAvoidance(t *testing.T) {
	s := NewSender(1200, true, true)
	s.threshold = s.window
	before := s.window
	for i := congestion.PacketNumber(1); i <= 32; i++ {
		s.OnPacketAcked(i, 1200, s.window, monotime.Time(time.Second))
	}
	require.Equal(t, before+1200, s.window)
	s.largestSent = 64
	s.OnCongestionEvent(33, 1200, s.window)
	require.Equal(t, (before+1200)*7/10, s.window)
}

func TestSenderNoStaleSampleAfterEmptyBatch(t *testing.T) {
	s := newTestSender(true)
	s.MaybeExitSlowStart()
	s.OnCongestionEventEx(s.window, monotime.Time(time.Second), nil, nil)
	require.Zero(t, s.pendingRTT)
	s.largestSent = 32
	s.OnPacketAcked(1, 1200, s.window, monotime.Time(time.Second))
	s.OnCongestionEventEx(s.window, monotime.Time(time.Second), []congestion.AckedPacketInfo{{PacketNumber: 1}}, nil)
	require.Zero(t, s.hyStart.samples)
}

func TestSenderLossBeforeFirstNewSend(t *testing.T) {
	s := newTestSender(true)
	s.OnCongestionEvent(5, 1200, s.window)
	afterLoss := s.window
	s.OnCongestionEvent(5, 1200, s.window)
	require.Equal(t, afterLoss, s.window)
}

func TestSenderReorderedBatchDoesNotAdvanceCSSRound(t *testing.T) {
	s := newTestSender(true)
	s.largestSent, s.largestAcked = 32, 32
	s.hyStart = hyStartPlusPlus{started: true, css: true, cssRounds: 1, endPacket: 32}
	// Packet 32 ended the previous round; an ACK now fills an old hole without
	// acknowledging any packet sent in a new round.
	s.OnPacketAcked(16, 1200, s.window, monotime.Time(time.Second))
	s.OnCongestionEventEx(s.window, monotime.Time(time.Second), []congestion.AckedPacketInfo{{PacketNumber: 16}}, nil)
	require.Equal(t, 1, s.hyStart.cssRounds)
	require.True(t, s.InSlowStart())
}

func TestSenderHyStartGrowthAccountsForBytesNotACKCount(t *testing.T) {
	for _, css := range []bool{false, true} {
		for _, chunks := range [][]congestion.ByteCount{
			{1200},
			{200, 300, 700},
			{1, 2, 3, 1194},
		} {
			s := newTestSender(true)
			s.hyStart.css = css
			before := s.window
			for i, bytes := range chunks {
				s.OnPacketAcked(congestion.PacketNumber(i+1), bytes, s.window, monotime.Time(time.Second))
			}
			want := congestion.ByteCount(1200)
			if css {
				want /= cssGrowthDivisor
			}
			require.Equal(t, before+want, s.window, "CSS=%v, ACK chunks=%v", css, chunks)
		}
	}
}

func TestSenderRepeatedLossPreservesMinimumWindow(t *testing.T) {
	for _, size := range []congestion.ByteCount{1200, 1500} {
		for _, reno := range []bool{false, true} {
			s := NewSender(size, reno, true)
			now := monotime.Time(time.Second)
			for i := congestion.PacketNumber(0); i < 64; i++ {
				packet := 2 * i
				s.OnPacketSent(now, size, packet, size, true)
				s.OnPacketSent(now, 2*size, packet+1, size, true)
				s.OnCongestionEvent(packet, size, 2*size)
				require.GreaterOrEqual(t, s.window, 2*size)
				// This ACK is still inside the cutback boundary: no extra growth.
				s.OnPacketAcked(packet+1, size, 2*size, now)
			}
			require.Equal(t, 2*size, s.window)
			require.False(t, s.InSlowStart())
			require.True(t, s.hyStart.disabled)
		}
	}
}
