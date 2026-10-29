// SPDX-License-Identifier: BSD-2-Clause AND MIT AND MIT-0
// Copyright (c) 2017 ~ 2035 PPP PRIVATE NETWORK(TM) X
// Copyright (c) 2026 PPP PRIVATE NETWORK™ X
// Adapted KCC/UCP model policy; Go byte-rate math, QUIC pacing bounds and
// ACK aggregation units changed for oh-my-hysteria. See estimator.go notices.

package geodesic

import (
	"time"
)

const (
	startupGain uint64 = 739 // 739/256, not an exact decimal 2.885
	drainGain   uint64 = 88
)

type bandwidthSlot struct {
	round, value uint64
	valid        bool
}

func (s *Sender) maxBandwidth() uint64 {
	var bw uint64
	for _, p := range s.bwSlots {
		if p.valid && s.bwRound-p.round < 10 {
			bw = max(bw, p.value)
		}
	}
	return bw
}

func (s *Sender) bandwidth() uint64 {
	bw := s.maxBandwidth()
	if bw == 0 {
		bw = s.lastBandwidth
	}
	if bw == 0 {
		bw = s.seedRate
	}
	if s.ltUse && s.ltRate > 0 {
		bw = min(bw, s.ltRate)
	}
	return max(1, bw)
}

func (s *Sender) noteBandwidth(rs rateSample) {
	// Control packets are not capacity experiments. In particular, the low
	// traffic in the reverse direction must not age out a bulk data estimate.
	// App-limited samples may raise the estimate, but never age or lower it.
	if !rs.valid || rs.delivered < s.size || (rs.appLimited && rs.rate < max(s.maxBandwidth(), s.lastBandwidth)) {
		if rs.hasData || rs.valid {
			s.rejectedBW++
		}
		return
	}
	if !rs.appLimited && (s.bwRound == 0 || s.bwDeliveryRound != s.round) {
		s.bwRound++
		s.bwDeliveryRound = s.round
	}
	if !rs.appLimited && s.state == probeBW {
		s.roundQualified = true
	}
	s.lastBandwidth = rs.rate
	p := &s.bwSlots[s.bwRound%10]
	if !p.valid || p.round != s.bwRound {
		*p = bandwidthSlot{round: s.bwRound, valid: true}
	}
	p.value = max(p.value, rs.rate)
}

func (s *Sender) modelRTT() time.Duration {
	if s.geo.minimum > 0 {
		return time.Duration(s.geo.minimum) * time.Microsecond
	}
	return s.initialRTT()
}

func (s *Sender) bdp(gain uint64) uint64 {
	w := durationBytes(s.bandwidth(), s.modelRTT())
	return min(s.maximum(), max(s.size, mulDiv(w, gain, 256)))
}

func (s *Sender) tsoSegments() uint64 {
	divisor := uint64(8)
	if s.geo.jitter > 4000 {
		divisor = 32
	}
	minimum := uint64(2)
	if s.rate < 1200000/divisor {
		minimum = 1
	}
	return min(127, max(minimum, (s.rate>>10)/s.size))
}
func (s *Sender) quantum() uint64 { return min(65536, max(s.size, s.tsoSegments()*s.size)) }
func (s *Sender) burst() uint64   { return max(2*s.size, s.quantum()) }
func (s *Sender) inflightTarget(gain uint64) uint64 {
	target := addBounded(s.bdp(gain), 3*s.tsoSegments()*s.size)
	packets := target / s.size
	if target%s.size != 0 {
		packets++
	}
	if packets%2 != 0 {
		packets++
	}
	return min(s.maximum(), max(s.floor(), packets*s.size))
}

func (s *Sender) gains() (uint64, uint64) {
	switch s.state {
	case startup:
		return startupGain, startupGain
	case drain:
		return drainGain, startupGain
	default:
		if s.ltUse {
			return 256, 512
		}
		return [...]uint64{320, 192, 256, 256, 256, 256, 256, 256}[s.phase], 512
	}
}

func (s *Sender) updateControls(acked uint64, appLimited, ce bool) {
	pg, cg := s.gains()
	rate := mulDiv(mulDiv(s.bandwidth(), pg, 256), 99, 100)
	if s.state == startup {
		s.rate = max(s.rate, rate)
	} else {
		s.rate = max(1, rate)
	}
	target := s.inflightTarget(cg)
	if s.fullReached && s.geo.minimum >= 7500 {
		bonus := min(max(s.extra[0], s.extra[1]), durationBytes(s.bandwidth(), 100*time.Millisecond))
		target = addBounded(target, bonus)
	}
	if s.state == probeBW && s.phase == 0 {
		target = addBounded(target, 2*s.size)
	}
	if s.inRecovery {
		// QUIC has no TCP CA-state callback: bound conservation to packets
		// sent before this recovery episode, not the original UCP tautology.
		if acked > 0 {
			s.cwnd = max(s.floor(), min(s.cwnd, addBounded(s.inFlight, acked)))
		}
	} else if acked > 0 {
		if s.fullReached {
			if !appLimited && !ce {
				s.cwnd = addBounded(s.cwnd, acked)
			}
			s.cwnd = min(s.cwnd, target)
		} else if !appLimited && !ce && (s.cwnd < target || s.sampler.totals.delivered < s.initial) {
			s.cwnd = addBounded(s.cwnd, acked)
		}
	}
	s.cwnd = min(s.maximum(), max(s.floor(), s.cwnd))
}

func (s *Sender) advance(rs rateSample, newRound, loss bool) {
	if newRound && rs.valid && !rs.appLimited && rs.delivered >= s.size && !s.fullReached {
		bw := s.maxBandwidth()
		if bw >= mulDiv(s.fullBW, 320, 256) {
			s.fullBW = bw
			s.plateau = 0
		} else {
			s.plateau++
		}
		if s.plateau >= 3 {
			s.fullReached = true
		}
	}
	if s.state == startup && s.fullReached {
		s.state = drain
		s.cycleStamp = s.now
		return
	}
	elapsed, _ := sampleElapsed(s.now, s.cycleStamp)
	rtt := s.modelRTT()
	if s.state == drain {
		if (elapsed > rtt && s.inFlight <= s.inflightTarget(256)) || elapsed > 4*rtt {
			s.state = probeBW
			s.phase = uint8(s.rng.Uint64N(7) + 1)
			s.cycleStamp = s.now
		}
		return
	}
	if s.state != probeBW || s.ltUse || !rs.hasData {
		return
	}
	pg, _ := s.gains()
	next := false
	if pg == 256 {
		next = elapsed > rtt
	} else if pg > 256 {
		next = (elapsed > rtt && (loss || s.inFlight >= s.inflightTarget(pg))) || elapsed > 2*rtt
	} else {
		next = (elapsed > rtt && s.inFlight <= s.inflightTarget(256)) || elapsed > 4*rtt
	}
	if next {
		s.phase = (s.phase + 1) % 8
		s.cycleStamp = s.now
	}
}

func (s *Sender) aggregation(acked uint64, newRound bool) {
	if newRound {
		s.aggRounds++
		if s.aggRounds >= 5 {
			s.aggRounds = 0
			s.aggIndex ^= 1
			s.extra[s.aggIndex] = 0
		}
	}
	if acked == 0 {
		return
	}
	elapsed, _ := sampleElapsed(s.now, s.aggStamp)
	expected := durationBytes(s.bandwidth(), elapsed)
	if !s.aggSet || s.aggAcked <= expected || addBounded(s.aggAcked, acked) > 1<<20 {
		s.aggAcked = 0
		s.aggStamp = s.now
		s.aggSet = true
		expected = 0
	}
	s.aggAcked = addBounded(s.aggAcked, acked)
	extra := min(s.cwnd, s.aggAcked-min(s.aggAcked, expected))
	s.extra[s.aggIndex] = max(s.extra[s.aggIndex], extra)
}

// Two stable high-loss intervals, each 4..16 delivery rounds, are required.
// This is a policer heuristic, not a guarantee that random loss is identified.
func (s *Sender) longTerm(rs rateSample, newRound, loss bool) {
	if s.ltUse {
		if newRound {
			s.ltRounds++
		}
		if s.ltRounds >= 48 {
			s.resetLT()
		}
		return
	}
	if rs.appLimited {
		s.resetLT()
		return
	}
	if s.geo.samples < 5 {
		return
	}
	if !s.ltSampling {
		if loss {
			s.startLT()
		}
		return
	}
	if newRound {
		s.ltRounds++
	}
	if s.ltRounds > 16 {
		s.resetLT()
		return
	}
	if s.ltRounds < 4 || !loss {
		return
	}
	delivered := s.sampler.totals.delivered - s.ltDelivered
	lost := s.sampler.totals.congestionLost - s.ltLost
	elapsed, ok := sampleElapsed(s.now, s.ltStamp)
	if !ok || elapsed < time.Millisecond || delivered == 0 || lost < mulDiv(delivered, 50, 256) {
		return
	}
	rate := bytesPerSecond(delivered, elapsed)
	if s.ltRate > 0 {
		diff := max(rate, s.ltRate) - min(rate, s.ltRate)
		if diff <= s.ltRate/8 || diff <= 500 {
			if s.geo.queue > max(500, s.geo.minimum/4) || uint64(s.initialRTT()/time.Microsecond) > s.geo.minimum+5000 {
				s.resetLT()
				return
			}
			s.ltRate = s.ltRate/2 + rate/2
			s.ltUse = true
			s.ltRounds = 0
			return
		}
	}
	s.ltRate = rate
	s.startLT()
}

func (s *Sender) startLT() {
	s.ltSampling = true
	s.ltRounds = 0
	s.ltStamp = s.now
	s.ltDelivered = s.sampler.totals.delivered
	s.ltLost = s.sampler.totals.congestionLost
}

func (s *Sender) resetLT() {
	s.ltUse, s.ltSampling = false, false
	s.ltRate, s.ltRounds = 0, 0
}
