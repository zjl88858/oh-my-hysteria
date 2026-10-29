// SPDX-License-Identifier: MIT
// Adapted from quic-go internal/congestion/cubic_sender.go.
// Copyright (c) 2016 the quic-go authors & Google, Inc.
// See LICENSE-THIRD-PARTY.md. Fork-specific changes are licensed under MIT-0.

package cubic

import (
	"fmt"
	"math"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const initialWindowPackets = 32

var _ congestion.CongestionControlEx = (*Sender)(nil)

// Sender adapts upstream CUBIC / Reno to quic-go's public congestion API.
// Reno with legacy slow start is left entirely to quic-go by the caller.
type Sender struct {
	rtt                                    congestion.RTTStatsProvider
	window, threshold, maxDatagramSize     congestion.ByteCount
	largestSent, largestAcked, lastCutback congestion.PacketNumber
	reno                                   bool
	ackedPackets                           uint64
	useHyStart                             bool
	pendingRTT                             time.Duration
	pendingAckFloor                        congestion.PacketNumber
	legacy                                 legacySlowStart
	hyStart                                hyStartPlusPlus
	cubic                                  cubic
	pacer                                  pacer
}

func NewSender(size congestion.ByteCount, reno, hyStart bool) *Sender {
	if size <= 0 {
		size = congestion.InitialPacketSize
	}
	s := &Sender{
		window:          initialWindowPackets * size,
		threshold:       congestion.ByteCount(math.MaxInt64),
		maxDatagramSize: size,
		largestSent:     -1,
		largestAcked:    -1,
		lastCutback:     -1,
		reno:            reno,
		useHyStart:      hyStart,
		cubic:           cubic{maxDatagramSize: size},
	}
	s.pacer = pacer{size: size, bandwidth: func() uint64 {
		rtt := 100 * time.Millisecond
		if s.rtt != nil && s.rtt.SmoothedRTT() > 0 {
			rtt = s.rtt.SmoothedRTT()
		}
		return uint64(float64(s.window) / rtt.Seconds() * 1.25)
	}}
	s.pacer.budget = s.pacer.maxBurst()
	return s
}

func (s *Sender) SetRTTStatsProvider(provider congestion.RTTStatsProvider) { s.rtt = provider }
func (s *Sender) TimeUntilSend(_ congestion.ByteCount) monotime.Time       { return s.pacer.timeUntilSend() }
func (s *Sender) HasPacingBudget(now monotime.Time) bool {
	return s.pacer.available(now) >= s.maxDatagramSize
}
func (s *Sender) CanSend(inFlight congestion.ByteCount) bool { return inFlight < s.window }
func (s *Sender) GetCongestionWindow() congestion.ByteCount  { return s.window }
func (s *Sender) InSlowStart() bool                          { return s.window < s.threshold }
func (s *Sender) InRecovery() bool                           { return s.largestAcked >= 0 && s.largestAcked <= s.lastCutback }

func (s *Sender) OnPacketSent(now monotime.Time, _ congestion.ByteCount, packet congestion.PacketNumber, bytes congestion.ByteCount, retransmittable bool) {
	s.pacer.sent(now, bytes)
	if retransmittable {
		s.largestSent = max(s.largestSent, packet)
		s.legacy.lastSent = s.largestSent
	}
}

func (s *Sender) MaybeExitSlowStart() {
	if !s.InSlowStart() || s.InRecovery() || s.rtt == nil {
		return
	}
	if s.useHyStart {
		if !s.hyStart.disabled {
			// Only this callback denotes an RTT observation. Do not sample once
			// per OnPacketAcked: one ACK frame often acknowledges many packets.
			s.pendingRTT = s.rtt.LatestRTT()
			s.pendingAckFloor = s.largestAcked
		}
	} else if s.legacy.shouldExit(s.rtt.LatestRTT(), s.rtt.MinRTT(), s.window/s.maxDatagramSize) {
		s.threshold = s.window
	}
}

func (s *Sender) OnPacketAcked(packet congestion.PacketNumber, bytes, inFlight congestion.ByteCount, now monotime.Time) {
	s.largestAcked = max(s.largestAcked, packet)
	if s.InRecovery() || bytes <= 0 {
		return
	}
	if !s.useHyStart && s.InSlowStart() {
		defer s.legacy.onAck(packet)
	}
	if !s.cwndLimited(inFlight) {
		s.cubic.epoch = 0 // Don't accumulate CUBIC growth while application limited.
		return
	}
	maximum := congestion.MaxCongestionWindowPackets * s.maxDatagramSize
	if s.window >= maximum {
		return
	}
	if s.InSlowStart() {
		growth := s.maxDatagramSize // Preserve upstream legacy growth.
		if s.useHyStart {
			growth = s.hyStart.growth(bytes)
		}
		s.window = min(maximum, s.window+growth)
	} else if s.reno {
		s.ackedPackets++
		if s.ackedPackets >= uint64(s.window/s.maxDatagramSize) {
			s.window = min(maximum, s.window+s.maxDatagramSize)
			s.ackedPackets = 0
		}
	} else {
		minRTT := 100 * time.Millisecond
		if s.rtt != nil && s.rtt.MinRTT() > 0 {
			minRTT = s.rtt.MinRTT()
		}
		s.window = min(maximum, s.cubic.afterAck(bytes, s.window, minRTT, now))
	}
}

func (s *Sender) OnCongestionEvent(packet congestion.PacketNumber, _, _ congestion.ByteCount) {
	if packet <= s.lastCutback {
		return // One cutback per recovery window, including ECN events.
	}
	if s.reno {
		s.window = s.window * 7 / 10
	} else {
		s.window = s.cubic.afterLoss(s.window)
	}
	s.window = max(2*s.maxDatagramSize, s.window)
	s.threshold = s.window
	// At installation there can still be packets in flight from the previous
	// controller. Even before our first OnPacketSent, cover the lost / ECN packet.
	s.lastCutback = max(s.largestSent, packet)
	s.ackedPackets = 0
	s.pendingRTT = 0
	s.hyStart.stop() // RFC 9406: only the initial slow start uses HyStart++.
}

func (s *Sender) OnCongestionEventEx(_ congestion.ByteCount, _ monotime.Time, acked []congestion.AckedPacketInfo, _ []congestion.LostPacketInfo) {
	rtt := s.pendingRTT
	s.pendingRTT = 0
	if s.largestAcked <= s.pendingAckFloor {
		// quic-go can issue the RTT hook on a reordered ACK even when it did
		// not update RTTStats. Don't count that stale observation again.
		rtt = 0
	}
	if !s.useHyStart || !s.InSlowStart() || s.InRecovery() || len(acked) == 0 {
		return
	}
	largestInBatch := acked[0].PacketNumber
	for _, packet := range acked[1:] {
		largestInBatch = max(largestInBatch, packet.PacketNumber)
	}
	// Use this batch's packet number, not the historical largest ACK. A late
	// ACK filling an old gap must not complete another (possibly idle) round.
	if s.hyStart.onAckBatch(rtt, largestInBatch, s.largestSent) {
		s.threshold = s.window
	}
}

func (s *Sender) OnRetransmissionTimeout(retransmitted bool) {
	s.lastCutback = -1
	if !retransmitted {
		return
	}
	s.legacy.restart()
	s.hyStart.stop()
	s.pendingRTT = 0
	s.cubic.reset()
	s.ackedPackets = 0
	s.threshold = s.window / 2
	s.window = 2 * s.maxDatagramSize
}

func (s *Sender) SetMaxDatagramSize(size congestion.ByteCount) {
	if size < s.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", s.maxDatagramSize, size))
	}
	if size == s.maxDatagramSize {
		return
	}
	wasMinimum := s.window == 2*s.maxDatagramSize
	s.maxDatagramSize = size
	s.window = max(s.window, 2*size)
	if wasMinimum {
		s.window = 2 * size
	}
	s.cubic.setMaxDatagramSize(size)
	s.pacer.size = size
}

func (s *Sender) cwndLimited(inFlight congestion.ByteCount) bool {
	return inFlight >= s.window || s.window-inFlight <= 3*s.maxDatagramSize ||
		(s.InSlowStart() && inFlight > s.window/2)
}
