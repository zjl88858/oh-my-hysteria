// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
)

const (
	marinerDomain   = "oh-my-hysteria/mariner/v1"
	marinerWireMax  = 1232
	marinerInnerMax = 1200
)

var (
	errMarinerFrame    = errors.New("mariner: invalid frame")
	errMarinerAuth     = errors.New("mariner: authentication failed")
	errMarinerRelation = errors.New("mariner: invalid relation")
	errMarinerRandom   = errors.New("mariner: bounded random mapping exhausted")
)

func marinerDerive(password []byte, label string) ([]byte, error) {
	if len(password) < 32 || len(password) > 1024 {
		return nil, errors.New("mariner: password must contain 32..1024 raw UTF-8 bytes")
	}
	return hkdf.Key(sha256.New, password, []byte(marinerDomain), label, 32)
}

type marinerStream struct {
	mac          hash.Hash
	prefix       []byte
	counter      uint64
	block        [32]byte
	counterBytes [8]byte
	pos          int
}

func newMarinerStream(key, label []byte) *marinerStream {
	return &marinerStream{mac: hmac.New(sha256.New, key), prefix: append([]byte("compile\x00"), label...), pos: 32}
}

func (s *marinerStream) below(n int) (int, error) {
	if n < 1 || n > 65536 {
		return 0, errMarinerRandom
	}
	limit := (uint64(1) << 32) / uint64(n) * uint64(n)
	for range 128 {
		if s.pos == 32 {
			binary.BigEndian.PutUint64(s.counterBytes[:], s.counter)
			s.counter++
			s.mac.Reset()
			s.mac.Write(s.prefix)
			s.mac.Write(s.counterBytes[:])
			s.mac.Sum(s.block[:0])
			s.pos = 0
		}
		x := uint64(binary.BigEndian.Uint32(s.block[s.pos:]))
		s.pos += 4
		if x < limit {
			return int(x % uint64(n)), nil
		}
	}
	return 0, errMarinerRandom
}

func marinerWeighted(s interface{ below(int) (int, error) }, weights []int) (int, error) {
	total := 0
	for _, w := range weights {
		total += w
	}
	x, err := s.below(total)
	if err != nil {
		return 0, err
	}
	for i, w := range weights {
		x -= w
		if x < 0 {
			return i, nil
		}
	}
	return 0, errMarinerRandom
}

type marinerProfile struct {
	key           [32]byte
	density, pool int
	orders        [3]int
	deltas        [4]int
	tables        [16][256]byte
}

func compileMarinerProfile(password []byte, direction byte) (marinerProfile, error) {
	var p marinerProfile
	if direction > 1 {
		return p, errMarinerFrame
	}
	label := "profile/c2s"
	if direction == 1 {
		label = "profile/s2c"
	}
	key, err := marinerDerive(password, label)
	if err != nil {
		return p, err
	}
	copy(p.key[:], key)
	s := newMarinerStream(key, []byte("profile"))
	x, err := s.below(5)
	if err != nil {
		return p, err
	}
	p.density = 16 + x
	for i := range p.orders {
		x, err = s.below(16)
		if err != nil {
			return p, err
		}
		p.orders[i] = 1 + x
	}
	x, err = s.below(5)
	if err != nil {
		return p, err
	}
	p.pool = []int{16, 32, 64, 128, 0}[x]
	for i := range p.deltas {
		x, err = s.below(16)
		if err != nil {
			return p, err
		}
		p.deltas[i] = 1 + x
	}
	s = newMarinerStream(key, []byte("tables"))
	for i := range p.tables {
		valid := false
		for range 16 {
			for j := range 256 {
				p.tables[i][j] = byte(j)
			}
			for j := 255; j > 0; j-- {
				k, e := s.below(j + 1)
				if e != nil {
					return p, e
				}
				p.tables[i][j], p.tables[i][k] = p.tables[i][k], p.tables[i][j]
			}
			if !marinerAffine(&p.tables[i]) {
				valid = true
				break
			}
		}
		if !valid {
			return p, errors.New("mariner: nonlinear table compilation exhausted")
		}
	}
	return p, nil
}

func marinerAffine(table *[256]byte) bool {
	for x := range 256 {
		y := table[0]
		for bit := range 8 {
			if x&(1<<bit) != 0 {
				y ^= table[1<<bit] ^ table[0]
			}
		}
		if y != table[x] {
			return false
		}
	}
	return true
}
func (p *marinerProfile) capacity() int      { return 64*marinerWireMax/(64+p.density) - 62 }
func (p *marinerProfile) wireBase(n int) int { return ((64+p.density)*n + 63) / 64 }
func (p *marinerProfile) dimensions(l int) (int, int, error) {
	k := 64 * l / (64 + p.density)
	r := l - k
	if l > marinerWireMax || l < p.wireBase(63) || k < 63 || r < 1 || r >= k || k-r < 4 {
		return 0, 0, errMarinerFrame
	}
	return k, r, nil
}

func (p *marinerProfile) bytes() []byte {
	b := []byte{byte(p.density), byte(p.pool)}
	for _, x := range p.orders {
		b = append(b, byte(x))
	}
	for _, x := range p.deltas {
		b = append(b, byte(x))
	}
	for i := range p.tables {
		b = append(b, p.tables[i][:]...)
	}
	return b
}
