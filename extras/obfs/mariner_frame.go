// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

type (
	marinerFrame struct {
		session       [16]byte
		counter, born uint64
		message       uint32
		total, offset uint16
		data          []byte
	}
	marinerCipher struct {
		aead      cipher.AEAD
		hp        [32]byte
		direction byte
	}
)

func newMarinerCipher(password []byte, direction byte) (*marinerCipher, error) {
	if direction > 1 {
		return nil, errMarinerFrame
	}
	label := "c2s"
	if direction == 1 {
		label = "s2c"
	}
	key, err := marinerDerive(password, "aead/"+label)
	if err != nil {
		return nil, err
	}
	hp, err := marinerDerive(password, "nonce-mask/"+label)
	if err != nil {
		return nil, err
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	c := &marinerCipher{aead: a, direction: direction}
	copy(c.hp[:], hp)
	return c, nil
}

func marinerContext(label string, dir byte, l int) []byte {
	b := append([]byte(marinerDomain), 0)
	b = append(b, label...)
	return append(b, 0, dir, byte(l>>8), byte(l))
}

func (c *marinerCipher) mask(l int, tag []byte) [24]byte {
	m := hmac.New(sha256.New, c.hp[:])
	m.Write(marinerContext("nonce-mask", c.direction, l))
	m.Write(tag)
	var out [24]byte
	copy(out[:], m.Sum(nil))
	return out
}

func (p *marinerProfile) splitRange(total int) (int, int) {
	return max(1, total-p.capacity(), total/2-32), min(p.capacity(), total-1, total/2+32)
}

func (p *marinerProfile) validateFragment(f *marinerFrame) error {
	n := len(f.data)
	t, o := int(f.total), int(f.offset)
	if f.born == 0 || f.born > math.MaxInt64 || f.message == 0 || t < 1 || t > 1200 || n < 1 || n > p.capacity() || o+n > t {
		return errMarinerFrame
	}
	if t <= p.capacity() {
		if o != 0 || n != t {
			return errMarinerFrame
		}
	} else {
		lo, hi := p.splitRange(t)
		cut := o
		if o == 0 {
			cut = n
		}
		if cut < lo || cut > hi || o > 0 && o+n != t {
			return errMarinerFrame
		}
	}
	return nil
}

func (c *marinerCipher) seal(dst []byte, f *marinerFrame, p *marinerProfile, l int) ([]byte, error) {
	if err := p.validateFragment(f); err != nil {
		return nil, err
	}
	k, _, err := p.dimensions(l)
	if err != nil {
		return nil, err
	}
	n := 62 + len(f.data)
	padding := k - n
	delta := l - p.wireBase(n)
	if padding < 0 || padding > 3 || delta < 0 || delta > 3 || len(dst) < k {
		return nil, errMarinerFrame
	}
	var plain [marinerWireMax]byte
	b := plain[:k-40]
	binary.BigEndian.PutUint64(b, f.born)
	b[8] = 1
	binary.BigEndian.PutUint16(b[10:], uint16(10+len(f.data)))
	binary.BigEndian.PutUint32(b[12:], f.message)
	binary.BigEndian.PutUint16(b[16:], f.total)
	binary.BigEndian.PutUint16(b[18:], f.offset)
	binary.BigEndian.PutUint16(b[20:], uint16(len(f.data)))
	copy(b[22:], f.data)
	var nonce [24]byte
	copy(nonce[:16], f.session[:])
	binary.BigEndian.PutUint64(nonce[16:], f.counter)
	raw := c.aead.Seal(dst[:24], nonce[:], b, marinerContext("frame", c.direction, l))
	mask := c.mask(l, raw[len(raw)-16:])
	for i := range 24 {
		raw[i] = nonce[i] ^ mask[i]
	}
	return raw, nil
}

func decodeMarinerPlain(b []byte, p *marinerProfile, l int) (marinerFrame, error) {
	var f marinerFrame
	k, _, err := p.dimensions(l)
	if err != nil || len(b) != k-40 || len(b) < 23 || b[8] != 1 || b[9] != 0 {
		return f, errMarinerFrame
	}
	used := int(binary.BigEndian.Uint16(b[10:]))
	if used < 11 || 12+used > len(b) {
		return f, errMarinerFrame
	}
	size := int(binary.BigEndian.Uint16(b[20:]))
	if used != 10+size {
		return f, errMarinerFrame
	}
	f.born = binary.BigEndian.Uint64(b)
	f.message = binary.BigEndian.Uint32(b[12:])
	f.total = binary.BigEndian.Uint16(b[16:])
	f.offset = binary.BigEndian.Uint16(b[18:])
	f.data = b[22 : 12+used]
	pad := len(b) - 12 - used
	delta := l - p.wireBase(52+used)
	if pad > 3 || delta < 0 || delta > 3 {
		return marinerFrame{}, errMarinerFrame
	}
	for _, x := range b[12+used:] {
		if x != 0 {
			return marinerFrame{}, errMarinerFrame
		}
	}
	if err = p.validateFragment(&f); err != nil {
		return marinerFrame{}, err
	}
	return f, nil
}

func (c *marinerCipher) open(dst, raw []byte, p *marinerProfile, l int) (marinerFrame, error) {
	var f marinerFrame
	k, _, err := p.dimensions(l)
	if err != nil || len(raw) != k || len(dst) < k-40 {
		return f, errMarinerFrame
	}
	mask := c.mask(l, raw[k-16:])
	var nonce [24]byte
	for i := range 24 {
		nonce[i] = raw[i] ^ mask[i]
	}
	b, err := c.aead.Open(dst[:0], nonce[:], raw[24:], marinerContext("frame", c.direction, l))
	if err != nil {
		return f, errMarinerAuth
	}
	f, err = decodeMarinerPlain(b, p, l)
	if err != nil {
		return f, err
	}
	copy(f.session[:], nonce[:16])
	f.counter = binary.BigEndian.Uint64(nonce[16:])
	return f, nil
}
