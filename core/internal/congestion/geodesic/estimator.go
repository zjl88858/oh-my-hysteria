// SPDX-License-Identifier: BSD-2-Clause AND MIT AND MIT-0
// Copyright (c) 2017 ~ 2035 PPP PRIVATE NETWORK(TM) X
// Copyright (c) 2026 PPP PRIVATE NETWORK™ X
//
// G1/G2/G3 policy adapted from liulilittle/kcc c8bead4638c9257c98760c386a0a5cf4fe2e3d20
// (BSD option of Dual BSD/GPL) and liulilittle/ucp 927cb83bb509f293a44bd26be52edd34dae09863
// (MIT). Changed: Go, bounded microsecond arithmetic, explicit completed-round
// inputs and observation-gap reset. Original QUIC adaptation is MIT-0.
// See third_party/geodesic/ and LICENSE-THIRD-PARTY.md.

package geodesic

import "time"

const maxRTTUs = uint64(time.Minute / time.Microsecond)

// All estimator times are microseconds; x retains 10 fractional bits.
// The three labels describe heuristics, not identifiable physical components.
type estimator struct {
	x, minimum, jitter, queue, samples, confidence    uint64
	fast, slow, unlock, fall, srttGuard, srttSuppress uint64
	locked                                            bool
	lastMinRound                                      uint64
	g1, g2, g3, lockReleases                          uint64
}

func rttMicros(rtt time.Duration) uint64 {
	return min(maxRTTUs, max(1, uint64(max(0, rtt)/time.Microsecond)))
}

func (g *estimator) setMinimum(us, round uint64, upward bool) {
	g.minimum = max(1, min(maxRTTUs, us))
	g.lastMinRound = round
	g.fast, g.slow, g.fall, g.srttGuard = 0, 0, 0, 0
	if upward {
		g.srttSuppress = 24
		g.confidence = 1000
		g.g3++
	}
}

// completeRound is called once per ACK-delivery round, even with no new RTT.
// A missing round minimum breaks consecutive evidence, rather than reusing
// the previous sample six times. New path baselines never use x directly.
func (g *estimator) completeRound(round, minimum, srtt uint64) {
	g.completeRoundWithPolicy(round, minimum, srtt, true)
}

// Upward confirmation needs an eligible data round in ProbeBW. Startup queues
// and reverse-direction control traffic do not establish a longer path. A
// downward confirmation remains independent of this additional QUIC gate.
func (g *estimator) completeRoundWithPolicy(round, minimum, srtt uint64, allowUp bool) {
	srtt = min(maxRTTUs, srtt)
	if g.minimum == 0 {
		return
	}
	if minimum == 0 {
		g.fast, g.slow, g.unlock, g.fall, g.srttGuard = 0, 0, 0, 0, 0
		if g.srttSuppress > 0 {
			g.srttSuppress--
		}
		return
	}
	minimum = min(maxRTTUs, minimum)
	if !allowUp {
		g.fast, g.slow, g.unlock = 0, 0, 0
	} else if g.locked {
		if minimum >= 7500 {
			g.unlock = min(7, g.unlock+1)
		} else {
			g.unlock = 0
		}
		g.fast, g.slow = 0, 0
		if g.unlock == 7 {
			g.locked = false
			g.unlock = 0
			g.lockReleases++
			g.setMinimum(minimum, round, true)
		}
	} else {
		if minimum >= 5000 && minimum*10 >= g.minimum*11 {
			g.fast = min(6, g.fast+1)
		} else {
			g.fast = 0
		}
		if minimum >= 7500 && minimum*20 >= g.minimum*21 {
			g.slow = min(7, g.slow+1)
		} else {
			g.slow = 0
		}
		if g.fast >= 6 || g.slow >= 7 {
			g.setMinimum(minimum, round, true)
		}
	}
	// Confirm a >4x decrease in two completed rounds; other material
	// decreases in five. A one-round timestamp outlier cannot cut BDP.
	if minimum*100 < g.minimum*95 {
		g.fall = min(5, g.fall+1)
		need := uint64(5)
		if minimum*4 < g.minimum {
			need = 2
		}
		if g.fall >= need {
			g.setMinimum(minimum, round, false)
		}
	} else {
		g.fall = 0
	}
	if g.srttSuppress > 0 {
		g.srttSuppress--
		g.srttGuard = 0
	} else if srtt > 0 && srtt*10 < g.minimum*9 {
		g.srttGuard = min(5, g.srttGuard+1)
		if g.srttGuard == 5 {
			g.setMinimum(srtt, round, false)
		}
	} else {
		g.srttGuard = 0
	}
}

// observe consumes one fresh transport RTT, never one sample per ACKed packet.
// allowUp grants at most one G2 increment in an ACK-delivery round.
func (g *estimator) observe(us, round uint64, allowUp bool) {
	us = max(1, min(maxRTTUs, us))
	z := us << 10
	if g.samples == 0 {
		g.x = z
		g.minimum = us
		g.confidence = 1000
		g.jitter = max(1, us/4)
		g.samples = 1
		g.lastMinRound = round
		g.locked = us < 5000
		return
	}
	if g.samples == 1 {
		g.x = min(g.x, g.minimum<<10)
	}
	innovation := max(g.x, z) - min(g.x, z)
	if z <= g.x {
		g.x = z
		g.g1++
	} else if allowUp {
		g.x = min(z, g.x+g.x*122/1000)
		g.g2++
	}
	if round-g.lastMinRound >= 128 && g.x <= (g.minimum<<10)*11/10 {
		g.x = max(1024, min(g.x, (g.minimum<<10)*95/100))
		g.lastMinRound = round
	}
	raw := innovation >> 10
	if g.samples == 1 {
		g.jitter = raw
	} else {
		g.jitter = (g.jitter*7 + raw) / 8
	}
	g.jitter = min(g.jitter, max(g.minimum, 500000))
	q := us - min(us, g.minimum)
	if g.samples == 1 {
		g.queue = q
	} else {
		g.queue = (g.queue*7 + q) / 8
	}
	g.samples = min(uint64(1<<32-1), g.samples+1)
	if g.samples >= 5 {
		if (g.x>>10)*20 <= g.minimum*21 && g.fast == 0 && g.slow == 0 {
			if g.confidence > 10 {
				g.confidence -= max(1, (g.confidence-10)/16)
			}
		} else if (g.x>>10)*10 > g.minimum*11 && g.confidence < 1000 {
			g.confidence = min(1000, g.confidence+max(1, (1000-g.confidence)/8))
		}
	}
	// Only modest (<5%) sample-level decreases bypass round confirmation.
	// Unlike UCP's old min(x,minRTT), an unconfirmed x cannot cut the BDP.
	if us <= g.minimum && us*100 >= g.minimum*95 {
		g.setMinimum(us, round, false)
	}
	if us < 5000 && g.minimum <= 5000 {
		g.locked = true
	}
}
