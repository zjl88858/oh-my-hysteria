// SPDX-License-Identifier: Apache-2.0 AND MIT-0
// Copyright (c) 2023 The TQUIC Authors.
// Copyright (C) 2023 THL A29 Limited, a Tencent company. All rights reserved.
//
// COPA equations, startup and velocity policy adapted from TQUIC copa.rs at
// d648bbe8cdd34d559cb542f1c83284432de67c0b (Apache-2.0).
// Changed for oh-my-hysteria: Go implementation, rich QUIC events, bounded
// history/arithmetic/velocity, srtt/2 filter, once-per-round loss guard, CE,
// app-limited gating, path lifecycle and diagnostics. Original additions MIT-0.
// See LICENSE-THIRD-PARTY.md and third_party/tquic/LICENSE.

package copa

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const (
	historyCapacity = 131072
	// TQUIC's default, not the paper's 0.5. Express delta as reciprocal
	// packets (25 -> 0.04) to keep the datapath entirely integer-based.
	defaultInverseDelta uint64 = 25
	minRTTWindow               = 10 * time.Second
)

type packet struct {
	bytes uint64
	mtu   bool
}

type senderState struct {
	rtt                               congestion.RTTStatsProvider
	size, cwnd, flight, rate          uint64
	slowStart                         bool
	packets                           map[congestion.PacketNumber]packet
	lastSent, roundEnd, appLimitedEnd congestion.PacketNumber
	round                             uint64
	roundAcked, roundLost             uint64
	// Loss guard uses rational delta = lossScale/25 (capped at 1/2).
	fraction                                                          uint64
	fractionUp                                                        bool
	lossScale                                                         uint64
	lossGuard                                                         bool
	velocity, sameDirection, lastWindow, roundWindow, roundGrowth     uint64
	directionUp, haveDirection                                        bool
	minimum, standing                                                 minFilter
	minRTT, standingRTT, queue                                        time.Duration
	now                                                               monotime.Time
	clockSet                                                          bool
	lastRTTTime                                                       monotime.Time
	hasRTTTime                                                        bool
	pacer                                                             pacer
	ceEnd                                                             congestion.PacketNumber
	acked, lost, unknown, faults, resets, ceCount, upCount, downCount uint64
}

// Snapshot contains no addresses, credentials or payload. Rates are bytes/s.
type Snapshot struct {
	Algorithm                                                             string `json:"algorithm"`
	State                                                                 string `json:"state"`
	Cwnd, InFlight, PacingRate                                            uint64
	MinRTT, StandingRTT, QueueDelay                                       time.Duration
	Delta                                                                 float64
	Velocity, Round, AckedBytes, LostBytes                                uint64
	LossGuard                                                             bool
	UnknownACKs, StateErrors, PathResets, ECNEvents, Increases, Decreases uint64
	History                                                               int
}

type Sender struct {
	mu           sync.Mutex
	debug        bool
	debugStamp   monotime.Time
	debugStarted bool
	debugState   string
	senderState
}

var _ congestion.AdvancedControl = (*Sender)(nil)

func NewSender(size congestion.ByteCount) *Sender {
	s := &Sender{debug: os.Getenv("OH_MY_HYSTERIA_COPA_DEBUG") == "1"}
	s.reset(size, nil)
	return s
}

func (s *Sender) reset(size congestion.ByteCount, rtt congestion.RTTStatsProvider) {
	if size <= 0 {
		size = congestion.InitialPacketSize
	}
	// UDP payloads cannot exceed 65527; guard synthetic invalid callers too.
	size = min(size, 65527)
	s.senderState = senderState{
		rtt: rtt, size: uint64(size), cwnd: 32 * uint64(size), slowStart: true,
		packets: make(map[congestion.PacketNumber]packet), lastSent: -1, roundEnd: -1, appLimitedEnd: -1,
		ceEnd: -1, lossScale: 1, velocity: 1, lastWindow: 32 * uint64(size), roundWindow: 32 * uint64(size),
	}
	s.updateRate()
}

func (s *Sender) floor() uint64   { return 4 * s.size }
func (s *Sender) maximum() uint64 { return uint64(congestion.MaxCongestionWindowPackets) * s.size }
func (s *Sender) srtt() time.Duration {
	if s.rtt != nil && s.rtt.SmoothedRTT() > 0 {
		return s.rtt.SmoothedRTT()
	}
	return 100 * time.Millisecond
}

func (s *Sender) updateRate() {
	rtt := s.standingRTT
	if rtt <= 0 {
		rtt = s.srtt()
	}
	s.rate = max(1, mulDiv(s.cwnd, 2*uint64(time.Second), uint64(max(time.Microsecond, rtt))))
}

func (s *Sender) quantum() uint64 {
	return max(s.size, min(uint64(65536), mulDiv(s.rate, uint64(time.Millisecond), uint64(time.Second))))
}
func (s *Sender) burst() uint64 { return max(2*s.size, s.quantum()) }
func (s *Sender) setClock(now monotime.Time) {
	// Receive timestamps are captured on the socket reader and can precede
	// a send already processed by the connection loop. Never drop ACK/loss
	// accounting merely because callback timestamps interleave.
	if !s.clockSet || now > s.now {
		s.now = now
	}
	s.clockSet = true
}

func (s *Sender) SetRTTStatsProvider(r congestion.RTTStatsProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rtt = r
	s.updateRate()
}

func (s *Sender) GetCongestionWindow() congestion.ByteCount {
	s.mu.Lock()
	defer s.mu.Unlock()
	return congestion.ByteCount(s.cwnd)
}
func (s *Sender) InSlowStart() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.slowStart }
func (*Sender) InRecovery() bool    { return false } // no TCP-style loss recovery window
func (s *Sender) CanSend(flight congestion.ByteCount) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return flight >= 0 && uint64(flight) < s.cwnd
}

func (s *Sender) TimeUntilSend(congestion.ByteCount) monotime.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pacer.deadline(s.size, s.rate)
}

func (s *Sender) HasPacingBudget(now monotime.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pacer.budget(now, s.rate, s.burst()) >= int64(s.size)
}

func (s *Sender) SendQuantum() congestion.ByteCount {
	s.mu.Lock()
	defer s.mu.Unlock()
	return congestion.ByteCount(s.quantum())
}

// Rich notifications own all accounting; legacy callbacks must not double it.
func (*Sender) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
}

func (*Sender) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
}

func (*Sender) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
}
func (*Sender) MaybeExitSlowStart()                                     {}
func (*Sender) OnRetransmissionTimeout(bool)                            {} // QUIC PTO is not TCP RTO.
func (*Sender) OnSpuriousPacket(congestion.PacketNumber, monotime.Time) {} // no window loss cut to undo

func (s *Sender) OnPacketSentContext(e congestion.SentPacketContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setClock(e.Time)
	s.pacer.sent(s.now, uint64(max(0, e.Bytes)), s.rate, s.burst())
	if e.Space != congestion.SpaceApplication {
		return
	}
	s.flight = uint64(max(0, e.ApplicationBytesInFlight))
	if !e.AckEliciting || e.Bytes <= 0 {
		return
	}
	if e.PacketNumber <= s.lastSent || len(s.packets) >= historyCapacity {
		// Fail closed: don't silently evict active history and grow on unknown
		// ACKs. Reset the model, preserving externally visible fault counts.
		s.resetPath(e.Time, congestion.ByteCount(s.size))
		s.faults++
		return
	}
	s.packets[e.PacketNumber] = packet{uint64(e.Bytes), e.MTUProbe}
	s.lastSent = e.PacketNumber
}

func (s *Sender) OnApplicationLimited(now monotime.Time, _ congestion.ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setClock(now)
	s.appLimitedEnd = s.lastSent
	s.velocity, s.sameDirection = 1, 0
	s.haveDirection = false
}

func (s *Sender) OnPacketRemoved(space congestion.PacketSpace, pn congestion.PacketNumber, _ congestion.RemovalReason) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if space == congestion.SpaceApplication {
		delete(s.packets, pn)
	}
}

func (s *Sender) resetPath(now monotime.Time, size congestion.ByteCount) {
	faults, resets, provider := s.faults, s.resets, s.rtt
	s.reset(size, provider)
	s.faults, s.resets = faults, resets
	s.setClock(now)
}

func (s *Sender) OnPathReset(now monotime.Time, size congestion.ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetPath(now, size)
	s.resets++
}

func (s *Sender) SetMaxDatagramSize(size congestion.ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if size <= 0 || uint64(size) < s.size || size > 65527 {
		panic("copa: invalid datagram size")
	}
	initial := s.cwnd == 32*s.size && s.slowStart
	s.size = uint64(size)
	if initial {
		s.cwnd = 32 * s.size
	}
	s.cwnd = min(s.maximum(), max(s.floor(), s.cwnd))
	s.updateRate()
}

func (s *Sender) OnCongestionEventContext(e congestion.CongestionEventContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Space != congestion.SpaceApplication {
		return
	}
	s.setClock(e.Time)
	s.flight = uint64(max(0, e.ApplicationBytesInFlight))
	for _, l := range e.Lost {
		p, ok := s.packets[l.PacketNumber]
		if !ok {
			continue
		}
		delete(s.packets, l.PacketNumber)
		if p.mtu {
			continue
		}
		s.lost = add(s.lost, p.bytes)
		s.roundLost = add(s.roundLost, p.bytes)
	}
	var acked, grow uint64
	mtuACK := false
	largest := congestion.PacketNumber(-1)
	for _, a := range e.Acked {
		p, ok := s.packets[a.PacketNumber]
		if !ok {
			s.unknown++
			continue
		}
		delete(s.packets, a.PacketNumber)
		if p.mtu {
			mtuACK = true
			continue
		}
		acked = add(acked, p.bytes)
		if a.PacketNumber > s.appLimitedEnd {
			grow = add(grow, p.bytes)
		}
		largest = max(largest, a.PacketNumber)
	}
	s.acked = add(s.acked, acked)
	s.roundAcked = add(s.roundAcked, acked)
	newRound := acked > 0 && largest > s.roundEnd
	if newRound {
		s.round++
		total := add(s.roundAcked, s.roundLost)
		s.lossGuard = total > 0 && s.roundLost >= total/10+boolByte(total%10 != 0)
		if s.lossGuard {
			s.lossScale = min(16, 2*s.lossScale)
			s.slowStart = false
		} else {
			s.lossScale = 1
		}
		s.roundAcked, s.roundLost = 0, 0
		s.roundEnd = s.lastSent
		s.roundGrowth = 0
		s.roundWindow = s.cwnd
	}
	// Only the transport's fresh, ACK-delay-adjusted sample may enter the
	// filters. Loss-only/duplicate/PMTU/other-space events cannot fake RTTs.
	window := max(time.Microsecond, min(minRTTWindow, s.srtt()/2))
	if acked > 0 && !mtuACK && e.RTTUpdated && e.RTT > 0 && (!s.hasRTTTime || e.Time >= s.lastRTTTime) {
		s.minimum.add(s.now, e.RTT, minRTTWindow)
		s.standing.add(s.now, e.RTT, window)
		s.lastRTTTime, s.hasRTTTime = e.Time, true
	} else {
		s.minimum.expire(s.now, minRTTWindow)
		s.standing.expire(s.now, window)
	}
	s.minRTT, s.standingRTT = s.minimum.get(), s.standing.get()
	s.queue = max(0, s.standingRTT-s.minRTT)
	ce := e.ECNCongestion && s.lastSent >= 0 && (s.ceEnd < 0 || largest > s.ceEnd)
	if ce {
		s.ceEnd = s.lastSent
		s.ceCount++
		s.slowStart = false
		s.cwnd = max(s.floor(), mulDiv(s.cwnd, 7, 10))
		s.velocity = 1
	}
	if acked > 0 && s.minRTT > 0 && s.standingRTT > 0 {
		// cwnd * dq * delta <= MSS * standing RTT. Avoid three-factor
		// overflow by comparing independently saturated byte rates.
		current := mulDiv(s.cwnd, uint64(time.Second), uint64(s.standingRTT))
		numerator, denominator := s.inverseDelta()
		target := mulDiv(s.size, numerator*uint64(time.Second), uint64(max(time.Microsecond, s.queue))) / denominator
		increase := s.queue == 0 || current <= target
		s.updateVelocity(newRound, increase)
		if !increase {
			s.slowStart = false
		}
		if !ce {
			if increase && grow > 0 {
				if s.slowStart {
					s.changeWindow(grow, true)
				} else {
					s.changeWindow(s.windowStep(grow, true), true)
				}
			} else if !increase {
				s.changeWindow(s.windowStep(acked, false), false)
			}
		}
	}
	s.cwnd = min(s.maximum(), max(s.floor(), s.cwnd))
	s.updateRate()
	s.trace()
}

func (s *Sender) updateVelocity(roundStart, increase bool) {
	if s.slowStart && increase {
		return
	}
	if !s.haveDirection {
		s.directionUp, s.haveDirection = increase, true
		s.lastWindow = s.cwnd
		s.velocity = 1
		s.sameDirection = 0
		return
	}
	if increase != s.directionUp {
		s.velocity, s.sameDirection = 1, 0
		s.directionUp = increase
		s.lastWindow = s.cwnd
		return
	}
	if !roundStart {
		return
	}
	// Compare actual window movement, not just the requested direction.
	if (increase && s.cwnd > s.lastWindow) || (!increase && s.cwnd < s.lastWindow) {
		s.sameDirection = min(64, s.sameDirection+1)
		if s.sameDirection >= 3 {
			s.velocity = min(uint64(1<<20), 2*s.velocity)
		}
	} else {
		s.sameDirection = 0
		s.velocity = 1
	}
	s.lastWindow = s.cwnd
}

func (s *Sender) step(acked uint64) uint64 {
	return s.stepFraction(acked) >> 16
}

func (s *Sender) stepFraction(acked uint64) uint64 {
	// v*ACKed*MSS/(delta*cwnd), computed without wrapping any product.
	// Bound v so the per-round increment cannot exceed one current window.
	numerator, denominator := s.inverseDelta()
	velocity := min(s.velocity, max(1, mulDiv(s.cwnd, denominator, s.size*numerator)))
	return min(s.cwnd<<16, mulDiv(acked, (velocity*s.size*numerator)<<16, s.cwnd*denominator))
}

func (s *Sender) windowStep(acked uint64, up bool) uint64 {
	if up != s.fractionUp {
		s.fraction = 0
		s.fractionUp = up
	}
	fixed := s.stepFraction(acked) + s.fraction
	s.fraction = fixed & 65535
	return fixed >> 16
}

func boolByte(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func (s *Sender) inverseDelta() (uint64, uint64) {
	if s.lossScale >= 13 {
		return 2, 1
	}
	return defaultInverseDelta, s.lossScale
}

func (s *Sender) changeWindow(bytes uint64, increase bool) {
	if increase {
		// Independent hard growth budget, including aggregated ACKs.
		budget := max(s.floor(), s.roundWindow)
		bytes = min(bytes, budget-min(budget, s.roundGrowth))
		s.roundGrowth = add(s.roundGrowth, bytes)
		s.cwnd = add(s.cwnd, bytes)
		if bytes > 0 {
			s.upCount++
		}
	} else {
		s.cwnd -= min(s.cwnd-s.floor(), bytes)
		if bytes > 0 {
			s.downCount++
		}
	}
}

func (s *Sender) snapshot() Snapshot {
	state := "Steady"
	if s.slowStart {
		state = "Startup"
	}
	delta := float64(s.lossScale) / float64(defaultInverseDelta)
	return Snapshot{
		Algorithm: "copa", State: state, Cwnd: s.cwnd, InFlight: s.flight, PacingRate: s.rate,
		MinRTT: s.minRTT, StandingRTT: s.standingRTT, QueueDelay: s.queue, Delta: min(.5, delta), Velocity: s.velocity, Round: s.round,
		AckedBytes: s.acked, LostBytes: s.lost, LossGuard: s.lossGuard, UnknownACKs: s.unknown, StateErrors: s.faults,
		PathResets: s.resets, ECNEvents: s.ceCount, Increases: s.upCount, Decreases: s.downCount, History: len(s.packets),
	}
}
func (s *Sender) Snapshot() Snapshot { s.mu.Lock(); defer s.mu.Unlock(); return s.snapshot() }
func (s *Sender) trace() {
	if !s.debug {
		return
	}
	snap := s.snapshot()
	if s.debugStarted && snap.State == s.debugState && s.now.Sub(s.debugStamp) < time.Second {
		return
	}
	data, err := json.Marshal(snap)
	if err == nil {
		fmt.Fprintf(os.Stderr, "copa snapshot %s\n", data)
	}
	s.debugStarted, s.debugStamp, s.debugState = true, s.now, snap.State
}
