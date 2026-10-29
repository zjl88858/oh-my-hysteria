// SPDX-License-Identifier: MIT-0

package geodesic

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func TestBandwidthControlAndAppLimitedRoundsCannotExpireCapacity(t *testing.T) {
	s := NewSender(1200)
	s.state = probeBW
	s.round = 1
	s.noteBandwidth(rateSample{valid: true, delivered: 1200, rate: 600000})
	for r := uint64(2); r <= 40; r++ {
		s.round = r
		s.roundQualified = false
		// Even a mistakenly non-app-limited 80-byte control round cannot
		// replace capacity or grant upward path-change evidence.
		s.noteBandwidth(rateSample{valid: true, delivered: 80, rate: 228})
		s.noteBandwidth(rateSample{valid: true, delivered: 2400, rate: 1000, appLimited: true})
		require.Equal(t, uint64(600000), s.bandwidth())
		require.False(t, s.roundQualified)
	}
	require.Equal(t, uint64(1), s.bwRound)
	require.Equal(t, uint64(78), s.rejectedBW)
	s.updateControls(0, true, false)
	require.GreaterOrEqual(t, s.rate, uint64(445500))
	// A genuine capacity decrease is still learned within ten loaded rounds.
	for range 10 {
		s.round++
		s.noteBandwidth(rateSample{valid: true, delivered: 1200, rate: 30000})
	}
	require.Equal(t, uint64(30000), s.bandwidth())
	require.True(t, s.roundQualified)
	// High app-limited samples can increase capacity without advancing age.
	s.round++
	s.noteBandwidth(rateSample{valid: true, delivered: 1200, rate: 90000, appLimited: true})
	require.Equal(t, uint64(90000), s.bandwidth())
	require.Equal(t, uint64(11), s.bwRound)
}

func TestSenderReverseControlTrafficKeepsDataRate(t *testing.T) {
	s := NewSender(1200)
	s.state, s.fullReached = probeBW, true
	s.round = 1
	s.noteBandwidth(rateSample{valid: true, delivered: 1200, rate: 600000})
	for i := range 30 {
		at := time.Duration(i+1) * time.Second
		s.OnPacketSentContext(congestion.SentPacketContext{
			Time: monotime.Time(at), Space: congestion.SpaceApplication,
			PacketNumber: congestion.PacketNumber(i), Bytes: 80, ApplicationBytesInFlight: 80, AckEliciting: true,
		})
		ack(s, at+350*time.Millisecond, 350*time.Millisecond, 0, i)
	}
	require.Greater(t, s.round, uint64(10))
	require.Equal(t, uint64(600000), s.Snapshot().Bandwidth)
	require.Equal(t, uint64(1), s.Snapshot().BandwidthRound)
	require.Equal(t, uint64(30), s.Snapshot().RejectedBandwidthSamples)
	require.Zero(t, s.faults)
	require.Zero(t, s.geo.g3)
}

func TestSenderG3RequiresProbeBWLoadedRounds(t *testing.T) {
	for _, tc := range []struct {
		name             string
		state            mode
		size             congestion.ByteCount
		limited, confirm bool
	}{
		{"startup-data", startup, 1200, false, false},
		{"drain-data", drain, 1200, false, false},
		{"probe-control", probeBW, 80, false, false},
		{"probe-app-limited", probeBW, 1200, true, false},
		{"probe-data", probeBW, 1200, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSender(1200)
			s.geo.observe(100000, 0, true)
			for i := range 12 {
				s.state = tc.state
				at := time.Duration(i) * 200 * time.Millisecond
				if tc.limited {
					require.NoError(t, s.sampler.markAppLimited(0))
				}
				s.OnPacketSentContext(congestion.SentPacketContext{
					Time: monotime.Time(at), Space: congestion.SpaceApplication,
					PacketNumber: congestion.PacketNumber(i), Bytes: tc.size, ApplicationBytesInFlight: tc.size, AckEliciting: true,
				})
				ack(s, at+120*time.Millisecond, 120*time.Millisecond, 0, i)
			}
			if tc.confirm {
				require.Equal(t, uint64(1), s.geo.g3)
				require.Equal(t, uint64(120000), s.geo.minimum)
			} else {
				require.Zero(t, s.geo.g3)
				require.Equal(t, uint64(100000), s.geo.minimum)
			}
			require.Zero(t, s.faults)
		})
	}
}

func TestEstimatorDisqualifiedRoundsBreakUpwardEvidenceButAllowFall(t *testing.T) {
	var g estimator
	g.observe(100000, 0, true)
	for r := uint64(1); r <= 5; r++ {
		g.completeRoundWithPolicy(r, 120000, 120000, true)
	}
	g.completeRoundWithPolicy(6, 120000, 120000, false)
	require.Zero(t, g.fast)
	require.Zero(t, g.slow)
	g.completeRoundWithPolicy(7, 120000, 120000, true)
	require.Equal(t, uint64(1), g.fast)
	require.Zero(t, g.g3)
	for r := uint64(8); r <= 12; r++ {
		g.completeRoundWithPolicy(r, 70000, 70000, false)
	}
	require.Equal(t, uint64(70000), g.minimum)
	var locked estimator
	locked.observe(1000, 0, true)
	for r := uint64(1); r <= 10; r++ {
		locked.completeRoundWithPolicy(r, 20000, 20000, false)
	}
	require.True(t, locked.locked)
	require.Zero(t, locked.unlock)
	for r := uint64(11); r <= 17; r++ {
		locked.completeRoundWithPolicy(r, 20000, 20000, true)
	}
	require.False(t, locked.locked)
}
