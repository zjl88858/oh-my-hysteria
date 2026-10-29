// SPDX-License-Identifier: MIT-0

package copa

import (
	"math"
	"math/bits"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// Saturating full-width arithmetic also works on 32-bit targets.
func mulDiv(a, b, d uint64) uint64 {
	if d == 0 {
		return math.MaxUint64
	}
	hi, lo := bits.Mul64(a, b)
	if hi >= d {
		return math.MaxUint64
	}
	q, _ := bits.Div64(hi, lo, d)
	return q
}

func add(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}

type pacer struct {
	credit  int64
	last    monotime.Time
	started bool
}

func (p *pacer) budget(now monotime.Time, rate, burst uint64) int64 {
	if !p.started {
		return int64(burst)
	}
	if now < p.last {
		return p.credit
	}
	refill := min(mulDiv(rate, uint64(now.Sub(p.last)), uint64(time.Second)), math.MaxInt64/2)
	return min(int64(burst), p.credit+int64(refill))
}

func (p *pacer) sent(now monotime.Time, bytes, rate, burst uint64) {
	p.credit = max(-65536, p.budget(now, rate, burst)-int64(min(bytes, math.MaxInt64/2)))
	if !p.started || now > p.last {
		p.last = now
	}
	p.started = true
}

func (p *pacer) deadline(size, rate uint64) monotime.Time {
	if !p.started || p.credit >= int64(size) {
		return 0
	}
	ns := mulDiv(uint64(int64(size)-p.credit), uint64(time.Second), max(1, rate))
	delay := max(congestion.MinPacingDelay, time.Duration(min(ns, math.MaxInt64/2))+1)
	return p.last.Add(delay)
}
