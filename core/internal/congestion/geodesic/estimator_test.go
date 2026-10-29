// SPDX-License-Identifier: MIT-0

package geodesic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEstimatorG1G2AndQueueReference(t *testing.T) {
	var g estimator
	g.observe(100000, 0, true)
	require.Equal(t, uint64(100000<<10), g.x)
	require.Equal(t, uint64(100000), g.minimum)
	g.observe(200000, 1, true)
	require.Equal(t, uint64(112200<<10), g.x)
	require.Equal(t, uint64(100000), g.queue) // against confirmed baseline, not x
	for range 100 {
		g.observe(200000, 1, false)
	}
	require.Equal(t, uint64(112200<<10), g.x, "G2 must not run once per ACK")
	g.observe(90000, 1, false)
	require.Equal(t, uint64(90000<<10), g.x)
	require.Equal(t, uint64(100000), g.minimum, "unconfirmed x cannot cut BDP")
	require.Equal(t, uint64(1), g.g2)
	require.Greater(t, g.g1, uint64(0))
}

func TestEstimatorG3FastSlowGrayAndGap(t *testing.T) {
	for _, tc := range []struct {
		name               string
		base, step, rounds uint64
	}{
		{"fast", 100000, 120000, 6}, {"slow", 100000, 106000, 7}, {"gray", 5000, 5500, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var g estimator
			g.observe(tc.base, 0, true)
			for r := uint64(1); r < tc.rounds; r++ {
				g.completeRound(r, tc.step, tc.step)
				require.Equal(t, tc.base, g.minimum)
			}
			g.completeRound(tc.rounds, tc.step, tc.step)
			require.Equal(t, tc.step, g.minimum)
			require.Equal(t, uint64(1), g.g3)
			// Lagging srtt cannot immediately undo a confirmed path increase.
			g.completeRound(tc.rounds+1, tc.step, tc.base/2)
			require.Equal(t, tc.step, g.minimum)
		})
	}
	var g estimator
	g.observe(100000, 0, true)
	for r := uint64(1); r <= 5; r++ {
		g.completeRound(r, 120000, 100000)
	}
	g.completeRound(6, 0, 100000)
	require.Zero(t, g.fast)
	require.Zero(t, g.slow)
	g.completeRound(7, 120000, 100000)
	require.Equal(t, uint64(1), g.fast)
	require.Equal(t, uint64(100000), g.minimum)
	g.completeRound(8, 100000, 100000)
	require.Zero(t, g.fast)
	require.Zero(t, g.slow)
}

func TestEstimatorLockCanReleaseAndDownwardConfirmation(t *testing.T) {
	var g estimator
	g.observe(1000, 0, true)
	require.True(t, g.locked)
	for r := uint64(1); r <= 6; r++ {
		g.completeRound(r, 20000, 1000)
		require.True(t, g.locked)
		require.Equal(t, uint64(1000), g.minimum)
	}
	g.completeRound(7, 20000, 1000)
	require.False(t, g.locked)
	require.Equal(t, uint64(20000), g.minimum)
	require.Equal(t, uint64(1), g.lockReleases)
	g.completeRound(8, 1000, 1000)
	require.Equal(t, uint64(20000), g.minimum)
	g.completeRound(9, 20000, 20000)
	require.Equal(t, uint64(20000), g.minimum)
	g.completeRound(10, 1000, 1000)
	g.completeRound(11, 1000, 1000)
	require.Equal(t, uint64(1000), g.minimum)
	var h estimator
	h.observe(100000, 0, true)
	for r := uint64(1); r <= 4; r++ {
		h.completeRound(r, 70000, 100000)
		require.Equal(t, uint64(100000), h.minimum)
	}
	h.completeRound(5, 70000, 100000)
	require.Equal(t, uint64(70000), h.minimum)
}

func TestEstimatorOutlierAndStalenessFloor(t *testing.T) {
	var g estimator
	g.observe(100000, 0, true)
	g.observe(1000, 1, false)
	g.completeRound(2, 1000, 100000)
	require.Equal(t, uint64(100000), g.minimum)
	require.False(t, g.locked)
	g.completeRound(3, 100000, 100000)
	require.Zero(t, g.fall)
	for r := uint64(4); r < 20; r++ {
		g.observe(100000, r, true)
		g.completeRound(r, 100000, 100000)
	}
	require.Equal(t, uint64(100000), g.minimum)
	var h estimator
	h.observe(1, 0, true)
	h.observe(1, 128, true)
	require.GreaterOrEqual(t, h.x, uint64(1024))
	require.Equal(t, uint64(1), rttMicros(time.Nanosecond))
	require.Equal(t, maxRTTUs, rttMicros(24*time.Hour))
}

func TestProbeQueueDoesNotBecomeG3PathChange(t *testing.T) {
	var g estimator
	g.observe(100000, 0, true)
	for r := uint64(1); r <= 320; r++ {
		us := uint64(100000)
		if r%8 < 2 {
			us = 125000
		}
		g.completeRound(r, us, 100000)
		g.observe(us, r, true)
		for range 50 {
			g.observe(us, r, false)
		}
		require.Equal(t, uint64(100000), g.minimum)
	}
	require.Zero(t, g.g3)
	// Preserve the pinned short-path lock limitation rather than claiming
	// that every upward path change is identifiable from end-to-end RTT.
	var h estimator
	h.observe(1000, 0, true)
	for r := uint64(1); r <= 20; r++ {
		h.completeRound(r, 6000, 6000)
	}
	require.True(t, h.locked)
	require.Equal(t, uint64(1000), h.minimum)
}
