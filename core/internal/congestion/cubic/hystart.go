// SPDX-License-Identifier: MIT-0

package cubic

import (
	"time"

	"github.com/apernet/quic-go/congestion"
)

const (
	hyStartMinSamples = 8
	hyStartCSSRounds  = 5
	cssGrowthDivisor  = 4
)

// hyStartPlusPlus implements RFC 9406's delay detection and Conservative Slow
// Start (CSS). Rounds are packet-number delimited, not wall-clock timers. Zero
// RTT means no measurement; it must never be mistaken for a low RTT sample.
type hyStartPlusPlus struct {
	disabled                  bool
	started                   bool
	endPacket                 congestion.PacketNumber
	lastMinRTT, currentMinRTT time.Duration
	samples                   int
	css                       bool
	baseline                  time.Duration
	cssRounds                 int
	cssRemainder              congestion.ByteCount
}

func (h *hyStartPlusPlus) growth(acked congestion.ByteCount) congestion.ByteCount {
	if !h.css {
		return acked // Pacing is always enabled: RFC 9406's L = infinity.
	}
	// Retain fractional bytes, so small acknowledgments cannot stall CSS.
	n := acked + h.cssRemainder
	h.cssRemainder = n % cssGrowthDivisor
	return n / cssGrowthDivisor
}

// onAckBatch is called once per ACK frame, AFTER its window increase. A QUIC
// ACK frame may acknowledge many packets, but provides at most one RTT sample.
func (h *hyStartPlusPlus) onAckBatch(rtt time.Duration, acked, lastSent congestion.PacketNumber) (exit bool) {
	if h.disabled {
		return false
	}
	if !h.started {
		h.started = true
		h.endPacket = lastSent
	}
	if rtt > 0 {
		h.samples++
		if h.currentMinRTT == 0 || rtt < h.currentMinRTT {
			h.currentMinRTT = rtt
		}
		if h.samples >= hyStartMinSamples {
			if h.css {
				if h.currentMinRTT < h.baseline {
					// A delay spike was spurious: return to ordinary slow start.
					h.css = false
					h.cssRounds = 0
					h.cssRemainder = 0
					h.baseline = 0
				}
			} else if h.lastMinRTT > 0 {
				threshold := min(16*time.Millisecond, max(4*time.Millisecond, h.lastMinRTT/8))
				if h.currentMinRTT >= h.lastMinRTT+threshold {
					h.css = true
					h.baseline = h.currentMinRTT
					h.cssRounds = 0
				}
			}
		}
	}
	if acked >= h.endPacket {
		if h.css {
			h.cssRounds++ // The partial round entering CSS counts, per RFC 9406.
			if h.cssRounds >= hyStartCSSRounds {
				h.stop()
				return true
			}
		}
		h.endPacket = lastSent
		h.lastMinRTT = h.currentMinRTT
		h.currentMinRTT = 0
		h.samples = 0
	}
	return false
}

func (h *hyStartPlusPlus) stop() {
	h.disabled = true
	h.css = false
	h.cssRemainder = 0
}
