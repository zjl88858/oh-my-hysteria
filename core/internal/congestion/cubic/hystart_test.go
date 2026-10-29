// SPDX-License-Identifier: MIT-0

package cubic

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/stretchr/testify/require"
)

func runRound(h *hyStartPlusPlus, rtts ...time.Duration) bool {
	end := h.endPacket
	if !h.started {
		end = congestion.PacketNumber(len(rtts))
	}
	start := end - congestion.PacketNumber(len(rtts))
	for i, rtt := range rtts {
		lastSent := end + congestion.PacketNumber(len(rtts))
		if !h.started {
			lastSent = end
		}
		if h.onAckBatch(rtt, start+congestion.PacketNumber(i)+1, lastSent) {
			return true
		}
	}
	return false
}

func samples(rtt time.Duration) []time.Duration {
	result := make([]time.Duration, hyStartMinSamples)
	for i := range result {
		result[i] = rtt
	}
	return result
}

func TestHyStartCSSAndFiveRounds(t *testing.T) {
	h := &hyStartPlusPlus{}
	require.False(t, runRound(h, samples(100*time.Millisecond)...))
	require.False(t, runRound(h, samples(120*time.Millisecond)...))
	require.True(t, h.css)
	require.Equal(t, 1, h.cssRounds, "the partial entry round counts")
	require.Equal(t, congestion.ByteCount(300), h.growth(1200))
	for range 3 {
		require.False(t, runRound(h, samples(120*time.Millisecond)...))
	}
	require.True(t, runRound(h, samples(120*time.Millisecond)...))
	require.True(t, h.disabled)
}

func TestHyStartJitterResumesSlowStart(t *testing.T) {
	h := &hyStartPlusPlus{}
	runRound(h, samples(100*time.Millisecond)...)
	runRound(h, samples(120*time.Millisecond)...)
	require.True(t, h.css)
	end := h.endPacket
	for i := congestion.PacketNumber(1); i <= 7; i++ {
		h.onAckBatch(110*time.Millisecond, end-8+i, end+8)
		require.True(t, h.css, "must wait for eight RTT observations")
	}
	require.False(t, h.onAckBatch(110*time.Millisecond, end, end+8))
	require.False(t, h.css)
	require.False(t, h.disabled)
	require.Equal(t, congestion.ByteCount(1200), h.growth(1200))
	// A subsequent sustained delay increase must still be detectable.
	runRound(h, samples(140*time.Millisecond)...)
	require.True(t, h.css)
}

func TestHyStartThresholds(t *testing.T) {
	for _, tc := range []struct {
		name            string
		base, threshold time.Duration
	}{
		{"minimum", time.Millisecond, 4 * time.Millisecond},
		{"fraction", 100 * time.Millisecond, 12500 * time.Microsecond},
		{"maximum", time.Second, 16 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &hyStartPlusPlus{}
			runRound(h, samples(tc.base)...)
			runRound(h, samples(tc.base+tc.threshold-time.Microsecond)...)
			require.False(t, h.css)
			h = &hyStartPlusPlus{}
			runRound(h, samples(tc.base)...)
			runRound(h, samples(tc.base+tc.threshold)...)
			require.True(t, h.css, "RFC 9406 uses >= at the threshold")
		})
	}
}

func TestHyStartUsesPreviousRoundNotLifetimeMinimum(t *testing.T) {
	h := &hyStartPlusPlus{}
	for _, rtt := range []time.Duration{100, 105, 110, 115} {
		runRound(h, samples(rtt*time.Millisecond)...)
		require.False(t, h.css)
	}
}

func TestHyStartMissingSamplesAndFractionalGrowth(t *testing.T) {
	h := &hyStartPlusPlus{}
	runRound(h, samples(0)...)
	runRound(h, samples(120*time.Millisecond)...)
	require.False(t, h.css, "no valid previous-round RTT")
	runRound(h, 200*time.Millisecond, 0, 0, 0, 0, 0, 0, 0)
	require.False(t, h.css, "one RTT observation cannot count as eight")
	h.css = true
	var growth congestion.ByteCount
	for range 4 {
		growth += h.growth(1)
	}
	require.Equal(t, congestion.ByteCount(1), growth)
	h.stop()
	require.False(t, h.css)
	require.False(t, runRound(h, samples(time.Second)...))
}

func TestHyStartPartialRoundCountsOnlyAtItsBoundary(t *testing.T) {
	h := &hyStartPlusPlus{started: true, endPacket: 16, lastMinRTT: 100 * time.Millisecond}
	for packet := congestion.PacketNumber(1); packet <= 8; packet++ {
		require.False(t, h.onAckBatch(120*time.Millisecond, packet, 32))
	}
	require.True(t, h.css)
	require.Zero(t, h.cssRounds, "entering CSS is not itself a completed round")
	require.False(t, h.onAckBatch(0, 16, 32))
	require.Equal(t, 1, h.cssRounds)
}
