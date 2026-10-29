// SPDX-License-Identifier: MIT-0

package geodesic

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
func (r fixedRTT) MinRTT() time.Duration      { return 0 }

func TestBandwidthRoundWindowAndACKAggregationUnits(t *testing.T) {
	s := NewSender(1200)
	s.round = 1
	s.noteBandwidth(rateSample{valid: true, rate: 1000000, delivered: 1200})
	for range 100 {
		s.noteBandwidth(rateSample{valid: true, rate: 1000, delivered: 1200})
	}
	require.Equal(t, uint64(1000000), s.maxBandwidth(), "a round max cannot be overwritten by ten ACKs")
	s.noteBandwidth(rateSample{valid: true, rate: 2000000, delivered: 1200, appLimited: true})
	require.Equal(t, uint64(2000000), s.maxBandwidth())
	s.round = 11
	require.Equal(t, uint64(2000000), s.maxBandwidth(), "delivery rounds alone do not age capacity")
	require.Equal(t, uint64(2000000), s.bandwidth())
	for range 10 {
		s.round++
		s.noteBandwidth(rateSample{valid: true, rate: 10000, delivered: 1200})
	}
	require.Equal(t, uint64(10000), s.bandwidth())
	s.fullReached = true
	s.geo.minimum = 100000
	s.cwnd = 100000
	s.aggSet = true
	s.aggStamp = 0
	s.aggAcked = 12000
	s.now = 1
	s.aggregation(12000, false)
	require.Equal(t, uint64(24000), s.extra[0], "extra ACK bytes are not capped at cwnd/MSS packets")
	for range 10 {
		s.aggregation(0, true)
	}
	require.Zero(t, max(s.extra[0], s.extra[1]))
}

func TestLongTermPolicerTwoWindowsAndExpiry(t *testing.T) {
	s := NewSender(1200)
	s.geo.minimum = 100000
	s.geo.samples = 5
	s.state = probeBW
	s.round = 1
	s.noteBandwidth(rateSample{valid: true, rate: 100000, delivered: 1200})
	s.longTerm(rateSample{}, false, true)
	require.True(t, s.ltSampling)
	for i := 1; i <= 8; i++ {
		s.now = monotime.Time(time.Duration(i) * 100 * time.Millisecond)
		s.sampler.totals.delivered += 10000
		s.sampler.totals.congestionLost += 2500
		s.longTerm(rateSample{hasData: true}, true, true)
	}
	require.True(t, s.ltUse)
	require.Equal(t, uint64(100000), s.ltRate)
	pg, _ := s.gains()
	require.Equal(t, uint64(256), pg)
	for range 48 {
		s.longTerm(rateSample{}, true, false)
	}
	require.False(t, s.ltUse)
	require.Zero(t, s.ltRate)
	s.longTerm(rateSample{}, false, true)
	s.longTerm(rateSample{appLimited: true}, false, true)
	require.False(t, s.ltSampling)
}

func TestModelRecoveryCEAndNoFabricatedSendBudget(t *testing.T) {
	s := NewSender(1200)
	s.SetRTTStatsProvider(fixedRTT{smoothed: 200 * time.Millisecond})
	require.Equal(t, 200*time.Millisecond, s.initialRTT())
	s.SetRTTStatsProvider(nil)
	send(s, 0, 0, 1200, false)
	lose(s, 50*time.Millisecond, 0, 0)
	send(s, 1, 51*time.Millisecond, 1200, false)
	ack(s, 151*time.Millisecond, 100*time.Millisecond, 0, 1)
	require.False(t, s.inRecovery)
	send(s, 2, 152*time.Millisecond, 1200, false)
	lose(s, 153*time.Millisecond, 0, 2)
	e := congestion.CongestionEventContext{Time: monotime.Time(154 * time.Millisecond), Space: congestion.SpaceApplication, ECNCongestion: true}
	s.OnCongestionEventContext(e)
	before := s.cwnd
	s.OnSpuriousPacket(2, monotime.Time(155*time.Millisecond))
	require.Equal(t, before, s.cwnd, "loss undo cannot undo CE")
	require.Zero(t, s.undoCount)
	s.OnApplicationLimited(monotime.Time(200*time.Millisecond), 0)
	s.state = probeBW
	s.cycleStamp = 0
	send(s, 3, time.Second, 1200, false)
	require.Equal(t, monotime.Time(time.Second), s.cycleStamp)
}

func TestCapsAndDebug(t *testing.T) {
	s := NewSender(1200)
	s.rate = math.MaxUint64
	s.geo.jitter = 5000
	require.LessOrEqual(t, s.SendQuantum(), congestion.ByteCount(65536))
	s.cwnd = s.maximum()
	s.fullReached = true
	s.state = probeBW
	s.phase = 0
	s.round = 1
	s.noteBandwidth(rateSample{valid: true, rate: math.MaxUint64, delivered: 1200})
	s.updateControls(math.MaxUint64, false, false)
	require.Equal(t, s.maximum(), s.cwnd)
	require.Panics(t, func() { s.SetMaxDatagramSize(65528) })
	t.Setenv("OH_MY_HYSTERIA_GEODESIC_DEBUG", "1")
	s = NewSender(1200)
	send(s, 0, 0, 1200, false)
	ack(s, 100*time.Millisecond, 100*time.Millisecond, 0, 0)
	require.True(t, s.debugStarted)
	stamp := s.debugStamp
	s.trace()
	require.Equal(t, stamp, s.debugStamp)
}
