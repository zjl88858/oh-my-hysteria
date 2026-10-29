// SPDX-License-Identifier: MIT
// Adapted from quic-go internal/congestion/hybrid_slow_start.go.
// Copyright (c) 2016 the quic-go authors & Google, Inc.
// See LICENSE-THIRD-PARTY.md. Fork-specific changes are licensed under MIT-0.

package cubic

import (
	"time"

	"github.com/apernet/quic-go/congestion"
)

// legacySlowStart retains upstream's delay-based HyStart (not HyStart++).
type legacySlowStart struct {
	endPacket, lastSent congestion.PacketNumber
	started, found      bool
	minRTT              time.Duration
	samples             uint32
}

func (s *legacySlowStart) shouldExit(latest, minimum time.Duration, windowPackets congestion.ByteCount) bool {
	if latest <= 0 || minimum <= 0 {
		return false
	}
	if !s.started {
		s.endPacket = s.lastSent
		s.minRTT = 0
		s.samples = 0
		s.started = true
	}
	if s.found {
		return true
	}
	s.samples++
	if s.samples <= 8 && (s.minRTT == 0 || latest < s.minRTT) {
		s.minRTT = latest
	}
	if s.samples == 8 {
		threshold := min(16*time.Millisecond, max(4*time.Millisecond, minimum/8))
		s.found = s.minRTT > minimum+threshold
	}
	return windowPackets >= 16 && s.found
}

func (s *legacySlowStart) onAck(packet congestion.PacketNumber) {
	if packet > s.endPacket {
		s.started = false
	}
}

func (s *legacySlowStart) restart() {
	s.started = false
	s.found = false
}
