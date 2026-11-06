// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/chacha20"
)

const servoDomain = "oh-my-hysteria/servo/v1"

var errServoRandom = errors.New("servo: bounded random mapping exhausted")

func servoDerive(password []byte, info string) ([]byte, error) {
	if len(password) < 32 || len(password) > 1024 {
		return nil, errors.New("servo: password must contain 32..1024 raw UTF-8 bytes; use a high-entropy random secret")
	}
	return hkdf.Key(sha256.New, password, []byte(servoDomain), info, 32)
}

// Versioned pure compiler / shape stream. Never used to allocate nonces.
type servoStream struct{ cipher *chacha20.Cipher }

func newServoStream(key []byte) (*servoStream, error) {
	c, err := chacha20.NewUnauthenticatedCipher(key, make([]byte, chacha20.NonceSize))
	if err != nil {
		return nil, err
	}
	return &servoStream{cipher: c}, nil
}

func (s *servoStream) below(n int) (int, error) {
	if n < 1 || n > 65536 {
		return 0, errServoRandom
	}
	limit := 65536 / n * n
	for range 128 {
		var b [2]byte
		s.cipher.XORKeyStream(b[:], b[:])
		x := int(binary.BigEndian.Uint16(b[:]))
		if x < limit {
			return x % n, nil
		}
	}
	return 0, errServoRandom
}

type servoProfile struct {
	count, jitter int
	wait          time.Duration
	centers       [12]int
	weights       [12]int
}

func compileServoProfile(password []byte, direction byte) (servoProfile, error) {
	var p servoProfile
	if direction > 1 {
		return p, errServoFrame
	}
	label := "profile/c2s"
	if direction == 1 {
		label = "profile/s2c"
	}
	key, err := servoDerive(password, label)
	if err != nil {
		return p, err
	}
	s, err := newServoStream(key)
	if err != nil {
		return p, err
	}
	// Consume every draw in order, including below(1) in runtime sampling.
	count, err := s.below(7)
	if err != nil {
		return p, err
	}
	p.count = 6 + count
	if p.jitter, err = s.below(17); err != nil {
		return servoProfile{}, err
	}
	wait, err := s.below(301)
	if err != nil {
		return servoProfile{}, err
	}
	p.wait = time.Duration(200+wait) * time.Microsecond
	for i := range p.count {
		center, err := s.below(461)
		if err != nil {
			return servoProfile{}, err
		}
		weight, err := s.below(32)
		if err != nil {
			return servoProfile{}, err
		}
		p.centers[i], p.weights[i] = 640+center, 1+weight
	}
	return p, nil
}

func (p servoProfile) bytes() []byte {
	b := make([]byte, 4+4*p.count)
	b[0], b[1] = byte(p.count), byte(p.jitter)
	binary.BigEndian.PutUint16(b[2:4], uint16(p.wait/time.Microsecond))
	for i := range p.count {
		binary.BigEndian.PutUint16(b[4+4*i:6+4*i], uint16(p.centers[i]))
		binary.BigEndian.PutUint16(b[6+4*i:8+4*i], uint16(p.weights[i]))
	}
	return b
}

func (p servoProfile) sample(s *servoStream) (int, error) {
	weight := 0
	for i := range p.count {
		weight += p.weights[i]
	}
	x, err := s.below(weight)
	if err != nil {
		return 0, err
	}
	for i := range p.count {
		x -= p.weights[i]
		if x < 0 {
			jitter, err := s.below(2*p.jitter + 1)
			if err != nil {
				return 0, err
			}
			return max(640, min(1100, p.centers[i]+jitter-p.jitter)), nil
		}
	}
	return 0, errServoRandom
}
