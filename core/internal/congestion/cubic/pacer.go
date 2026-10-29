// SPDX-License-Identifier: MIT
// Adapted from quic-go internal/congestion/pacer.go.
// Copyright (c) 2016 the quic-go authors & Google, Inc.
// See LICENSE-THIRD-PARTY.md. Fork-specific changes are licensed under MIT-0.

package cubic

import (
	"math"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

type pacer struct {
	budget, size congestion.ByteCount
	lastSent     monotime.Time
	bandwidth    func() uint64 // Already adjusted by 5/4, in bytes/s.
}

func (p *pacer) scaled(ns uint64) congestion.ByteCount {
	bw := p.bandwidth()
	if bw == 0 {
		return 0
	}
	if ns > math.MaxUint64/bw {
		return 10 * p.size
	}
	// Clamp before the signed conversion (also handles multi-year idle gaps).
	return congestion.ByteCount(min(bw*ns/1e9, uint64(math.MaxInt64)))
}

func (p *pacer) maxBurst() congestion.ByteCount {
	return max(10*p.size, p.scaled(uint64((congestion.MinPacingDelay + time.Millisecond).Nanoseconds())))
}

func (p *pacer) available(now monotime.Time) congestion.ByteCount {
	if p.lastSent.IsZero() {
		return p.maxBurst()
	}
	added := p.scaled(uint64(max(0, now.Sub(p.lastSent).Nanoseconds())))
	if added > congestion.ByteCount(math.MaxInt64)-p.budget {
		return p.maxBurst()
	}
	return min(p.maxBurst(), p.budget+added)
}

func (p *pacer) sent(now monotime.Time, bytes congestion.ByteCount) {
	p.budget = max(0, p.available(now)-bytes)
	p.lastSent = now
}

func (p *pacer) timeUntilSend() monotime.Time {
	if p.budget >= p.size || p.lastSent.IsZero() {
		return 0
	}
	diff := uint64(p.size-p.budget) * 1e9
	bw := max(1, p.bandwidth())
	delay := diff / bw
	if diff%bw != 0 {
		delay++
	}
	return p.lastSent.Add(max(congestion.MinPacingDelay, time.Duration(delay)))
}
