// SPDX-License-Identifier: MIT-0

package geodesic

import (
	"math"
	"math/bits"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

func mulDiv(a, b, divisor uint64) uint64 {
	if divisor == 0 {
		return math.MaxUint64
	}
	hi, lo := bits.Mul64(a, b)
	if hi >= divisor {
		return math.MaxUint64
	}
	q, _ := bits.Div64(hi, lo, divisor)
	return q
}

func addBounded(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}

func durationBytes(rate uint64, duration time.Duration) uint64 {
	if duration <= 0 {
		return 0
	}
	return mulDiv(rate, uint64(duration), uint64(time.Second))
}

type pacer struct {
	credit  int64
	last    monotime.Time
	started bool
}

func (p *pacer) budget(now monotime.Time, rate, burst uint64) int64 {
	cap := int64(min(burst, math.MaxInt64/2))
	if !p.started {
		return cap
	}
	elapsed, ok := sampleElapsed(now, p.last)
	if !ok {
		return p.credit
	}
	refill := int64(min(durationBytes(rate, elapsed), math.MaxInt64))
	if p.credit >= cap || refill >= cap-p.credit {
		return cap
	}
	return p.credit + refill
}

func (p *pacer) sent(now monotime.Time, bytes, rate, burst uint64) {
	p.credit = max(-int64(65536), p.budget(now, rate, burst)-int64(min(bytes, math.MaxInt64/2)))
	p.last, p.started = now, true
}

func (p *pacer) deadline(size, rate uint64) monotime.Time {
	if !p.started || p.credit >= int64(size) {
		return 0
	}
	missing := uint64(int64(size) - p.credit)
	ns := mulDiv(missing, uint64(time.Second), max(1, rate))
	if ns < math.MaxInt64 {
		ns++
	} // Ceiling, including the integer division's boundary.
	delay := max(congestion.MinPacingDelay, time.Duration(min(ns, math.MaxInt64/2)))
	return p.last.Add(delay)
}
