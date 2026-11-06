// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const tasmanDomain = "oh-my-hysteria/tasman/v1"

func tasmanDerive(password []byte, label string) ([]byte, error) {
	if len(password) < 32 || len(password) > 1024 {
		return nil, errors.New("tasman: password must contain 32..1024 raw UTF-8 bytes; use a high-entropy random secret")
	}
	return hkdf.Key(sha256.New, password, []byte(tasmanDomain), label, 32)
}

type tasmanProfile struct {
	narrow, wide            [4]int
	collect, carrier        time.Duration
	repairs, tails, padding int
}

func compileTasmanProfile(password []byte, direction byte) (tasmanProfile, error) {
	var p tasmanProfile
	if direction > 1 {
		return p, errTasmanFrame
	}
	label := "profile/c2s"
	if direction == 1 {
		label = "profile/s2c"
	}
	key, err := tasmanDerive(password, label)
	if err != nil {
		return p, err
	}
	s, err := newServoStream(key) // pure ChaCha20/rejection tool, never a Servo key
	if err != nil {
		return p, err
	}
	draw := func(n, base int) (int, error) { x, e := s.below(n); return base + x, e }
	for i := range 4 {
		if p.narrow[i], err = draw(85, 416); err != nil {
			return tasmanProfile{}, err
		}
		if p.wide[i], err = draw(85, 616); err != nil {
			return tasmanProfile{}, err
		}
	}
	c, err := draw(2001, 2000)
	if err != nil {
		return p, err
	}
	w, err := draw(4001, 2000)
	if err != nil {
		return p, err
	}
	p.collect, p.carrier = time.Duration(c)*time.Microsecond, time.Duration(w)*time.Microsecond
	if p.repairs, err = draw(2, 1); err != nil {
		return p, err
	}
	if p.tails, err = draw(3, 0); err != nil {
		return p, err
	}
	p.padding, err = draw(33, 0)
	return p, err
}

func (p tasmanProfile) bytes() []byte {
	b := make([]byte, 23)
	for i := range 4 {
		binary.BigEndian.PutUint16(b[4*i:], uint16(p.narrow[i]))
		binary.BigEndian.PutUint16(b[4*i+2:], uint16(p.wide[i]))
	}
	binary.BigEndian.PutUint16(b[16:], uint16(p.collect/time.Microsecond))
	binary.BigEndian.PutUint16(b[18:], uint16(p.carrier/time.Microsecond))
	b[20], b[21], b[22] = byte(p.repairs), byte(p.tails), byte(p.padding)
	return b
}

func tasmanWidth(s int) bool { return s >= 416 && s <= 500 || s >= 616 && s <= 700 }
