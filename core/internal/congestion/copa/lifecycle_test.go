// SPDX-License-Identifier: MIT-0

package copa

import (
	"math"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

type fixedRTT struct {
	congestion.RTTStatsProvider
	smoothed time.Duration
}

func (r fixedRTT) SmoothedRTT() time.Duration { return r.smoothed }

func TestRTTProviderAndStandingWindow(t *testing.T) {
	s := NewSender(1200)
	s.SetRTTStatsProvider(fixedRTT{smoothed: 200 * time.Millisecond})
	require.Equal(t, uint64(384000), s.rate)
	send(s, 0, 0, false)
	ack(s, 200*time.Millisecond, 100*time.Millisecond, 0)
	send(s, 1, 201*time.Millisecond, false)
	ack(s, 275*time.Millisecond, 400*time.Millisecond, 1)
	require.Equal(t, 100*time.Millisecond, s.standingRTT) // srtt/2 = 100ms, not latest or srtt
	send(s, 2, 276*time.Millisecond, false)
	ack(s, 301*time.Millisecond, 400*time.Millisecond, 2)
	require.Equal(t, 400*time.Millisecond, s.standingRTT)
	send(s, 3, 302*time.Millisecond, true)
	send(s, 4, 302*time.Millisecond, false)
	ack(s, 303*time.Millisecond, time.Nanosecond, 3, 4)
	require.Equal(t, 100*time.Millisecond, s.minRTT) // mixed PMTU RTT cannot contaminate baseline
	s.SetRTTStatsProvider(nil)
	require.Equal(t, 100*time.Millisecond, s.srtt())
}

func TestHistoryBoundAndResetCounters(t *testing.T) {
	s := NewSender(1200)
	for i := range historyCapacity {
		s.packets[congestion.PacketNumber(i)] = packet{1200, false}
	}
	s.lastSent = historyCapacity - 1
	send(s, historyCapacity, time.Millisecond, false)
	require.Empty(t, s.packets)
	require.Equal(t, uint64(1), s.faults)
	s.OnPathReset(0, 0)
	require.Equal(t, uint64(1), s.faults)
	require.Equal(t, uint64(1), s.resets)
	s.OnPacketSentContext(congestion.SentPacketContext{Time: 1, Space: congestion.SpaceApplication, Bytes: 0, AckEliciting: true})
	s.OnPacketSentContext(congestion.SentPacketContext{Time: 2, Space: congestion.SpaceApplication, Bytes: 1200, AckEliciting: false})
	require.Empty(t, s.packets)
	s.OnApplicationLimited(0, 0)
	require.Equal(t, uint64(1), s.faults)
}

func TestHighLossDeltaCapAndExtremeRTT(t *testing.T) {
	s := NewSender(1200)
	for i := range 8 {
		now := time.Duration(i) * time.Second
		send(s, 2*i, now, false)
		send(s, 2*i+1, now, false)
		s.OnCongestionEventContext(congestion.CongestionEventContext{
			Time: monotime.Time(now + time.Millisecond), Space: congestion.SpaceApplication,
			Lost:  []congestion.LostPacketInfo{{PacketNumber: congestion.PacketNumber(2 * i)}},
			Acked: []congestion.AckedPacketInfo{{PacketNumber: congestion.PacketNumber(2*i + 1)}}, RTTUpdated: true, RTT: time.Duration(math.MaxInt64),
		})
	}
	require.Equal(t, .5, s.Snapshot().Delta)
	require.Equal(t, uint64(16), s.lossScale)
	require.Greater(t, s.rate, uint64(0))
	require.GreaterOrEqual(t, s.cwnd, s.floor())
	s.SetMaxDatagramSize(1400)
	require.GreaterOrEqual(t, s.cwnd, s.floor())
	require.Panics(t, func() { s.SetMaxDatagramSize(65528) })
	require.Equal(t, uint64(65527), NewSender(1000000).size)
}

func TestVelocityPlateauAndDecreaseAcceleration(t *testing.T) {
	s := NewSender(1200)
	s.slowStart = false
	s.updateVelocity(true, false)
	s.updateVelocity(true, false)
	require.Equal(t, uint64(1), s.velocity)
	for range 4 {
		s.cwnd--
		s.updateVelocity(true, false)
	}
	require.Equal(t, uint64(4), s.velocity)
	s.updateVelocity(false, true)
	require.Equal(t, uint64(1), s.velocity)
}

func TestDebugSnapshot(t *testing.T) {
	t.Setenv("OH_MY_HYSTERIA_COPA_DEBUG", "1")
	s := NewSender(1200)
	send(s, 0, 0, false)
	ack(s, time.Millisecond, time.Millisecond, 0)
	require.True(t, s.debugStarted)
	stamp := s.debugStamp
	s.trace()
	require.Equal(t, stamp, s.debugStamp)
	s.now = monotime.Time(2 * time.Second)
	s.trace()
	require.Equal(t, s.now, s.debugStamp)
}

func TestFractionalWindowStepsDoNotStall(t *testing.T) {
	s := NewSender(1200)
	s.cwnd = s.maximum()
	s.lossScale = 16
	require.Zero(t, s.step(1200))
	var total uint64
	for range 100 {
		total += s.windowStep(1200, true)
	}
	require.Greater(t, total, uint64(0))
	s.windowStep(1200, false)
	require.False(t, s.fractionUp)
}

func TestInterleavedReceiveTimestampStillAccountsACK(t *testing.T) {
	s := NewSender(1200)
	send(s, 0, 0, false)
	send(s, 1, 200*time.Millisecond, false)
	ack(s, 100*time.Millisecond, 100*time.Millisecond, 0)
	require.Equal(t, uint64(1200), s.acked)
	require.Equal(t, monotime.Time(200*time.Millisecond), s.now)
	require.Equal(t, 100*time.Millisecond, s.minRTT)
	ack(s, 90*time.Millisecond, time.Nanosecond, 1)
	require.Equal(t, uint64(2400), s.acked)
	require.Equal(t, 100*time.Millisecond, s.minRTT) // reordered RTT is not a fresh minimum
	require.Empty(t, s.packets)
	require.Zero(t, s.faults)
}
