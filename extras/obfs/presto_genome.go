// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"time"
)

// v1's compiler is part of the protocol: changing it requires a new version.
// It defines a distribution, NOT a deterministic packet or nonce sequence.
type prestoMode struct {
	length, jitter, burst, gapUS int
	weights                      [4]int
}

type prestoGenome struct {
	modes                                     [4]prestoMode
	preludeCount, preludeLength, preludeGapUS int
	fragmentChance, fragmentSize              int
}

func prestoDerive(password []byte, label string, size int) ([]byte, error) {
	if len(password) < 32 || len(password) > 1024 {
		return nil, errors.New("presto: password must contain 32..1024 bytes; use a high-entropy random secret")
	}
	return hkdf.Key(sha256.New, password, []byte("oh-my-hysteria/presto/v1"), label, size)
}

func compilePrestoGenome(password []byte, server bool) (prestoGenome, error) {
	direction := "client-to-server"
	if server {
		direction = "server-to-client"
	}
	data, err := prestoDerive(password, "genome/"+direction, 128)
	if err != nil {
		return prestoGenome{}, err
	}
	var g prestoGenome
	for i := range g.modes {
		b := data[i*16 : (i+1)*16]
		m := &g.modes[i]
		m.length = 520 + int(binary.BigEndian.Uint16(b[:2]))%665
		m.jitter = 8 + int(b[2])%33
		m.burst = 4 + int(b[3])%21
		m.gapUS = 100 + int(binary.BigEndian.Uint16(b[4:6]))%2201
		for j := range m.weights {
			m.weights[j] = 1 + int(b[6+j])%32
		}
		m.weights[int(b[10])%4] += 64 + int(b[11])%129
	}
	g.preludeCount = 1 + int(data[64])%3
	g.preludeLength = 80 + int(data[65])%65
	g.preludeGapUS = 100 + int(binary.BigEndian.Uint16(data[66:68]))%1901
	g.fragmentChance = 16 + int(data[68])%209
	g.fragmentSize = 320 + int(binary.BigEndian.Uint16(data[69:71]))%705
	return g, nil
}

type prestoPart struct {
	offset, size, wire int
	mode               int
}

type prestoPlan struct {
	parts [4]prestoPart
	count int
}

type prestoGrammar struct {
	genome             prestoGenome
	random             *rand.Rand
	state, shift, left int
}

func newPrestoGrammar(g prestoGenome, seed [32]byte) prestoGrammar {
	r := rand.New(rand.NewChaCha8(seed))
	return prestoGrammar{genome: g, random: r, state: r.IntN(4), shift: r.IntN(25) - 12}
}

func (s *prestoGrammar) nextMode() int {
	weights := s.genome.modes[s.state].weights
	total := 0
	for _, w := range weights {
		total += w
	}
	n := s.random.IntN(total)
	for i, w := range weights {
		n -= w
		if n < 0 {
			s.state = i
			return i
		}
	}
	panic("presto: unreachable positive-weight sample")
}

func (s *prestoGrammar) plan(size int) prestoPlan {
	var plan prestoPlan
	offset, budget := 0, size/3
	biased := size >= 600 && s.random.IntN(256) < s.genome.fragmentChance
	for offset < size {
		mode := s.nextMode()
		m := s.genome.modes[mode]
		target := max(484, min(prestoWireMax, m.length+s.shift+s.random.IntN(2*m.jitter+1)-m.jitter))
		capacity := target - prestoOverhead
		if biased {
			capacity = min(capacity, s.genome.fragmentSize+s.random.IntN(65)-32)
		}
		// Leave enough space to finish even at the smallest later targets.
		// No input or random choices can make more than four fragments.
		capacity = max(capacity, (size-offset+3-plan.count)/(4-plan.count))
		n := min(size-offset, capacity)
		pad := min(budget, max(0, target-prestoOverhead-n), 512)
		// Do not collapse all small packets onto a fixed padding ratio.
		if pad > 0 {
			pad = pad/2 + s.random.IntN(pad-pad/2+1)
		}
		budget -= pad
		plan.parts[plan.count] = prestoPart{offset: offset, size: n, wire: prestoOverhead + n + pad, mode: mode}
		plan.count++
		offset += n
	}
	return plan
}

func (s *prestoGrammar) prelude(server bool) []int {
	n := s.genome.preludeCount
	if s.random.IntN(4) == 0 {
		n += s.random.IntN(3) - 1
	}
	n = max(1, min(4, n))
	if server {
		n = min(3, n)
	}
	out := make([]int, n)
	for i := range out {
		out[i] = max(64, min(192, s.genome.preludeLength+s.random.IntN(33)-16))
		if server {
			out[i] = max(prestoOverhead, min(160, out[i]))
		}
	}
	return out
}

// A bounded pause AFTER a group, never a queue that builds up while idle.
func (s *prestoGrammar) gap(mode int) time.Duration {
	m := s.genome.modes[mode]
	if s.left <= 0 {
		s.left = max(2, m.burst+s.random.IntN(5)-2)
	}
	s.left--
	if s.left != 0 {
		return 0
	}
	return time.Duration(min(2500, m.gapUS+s.random.IntN(201))) * time.Microsecond
}
