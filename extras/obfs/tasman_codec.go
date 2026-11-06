// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	tasmanSource byte = iota
	tasmanRepair
	tasmanCover
	tasmanShort
	tasmanWireMax    = 1232
	tasmanInnerMax   = 1200
	tasmanRecordsMax = 63 // floor((700-2)/11), bounded before state
)

var (
	errTasmanFrame    = errors.New("tasman: invalid authenticated frame")
	errTasmanAuth     = errors.New("tasman: authentication failed")
	errTasmanConflict = errors.New("tasman: conflicting authenticated state")
	errTasmanResource = errors.New("tasman: receive resource limit")
)

type (
	tasmanRecord struct {
		message       uint32
		total, offset uint16
		data          []byte
	}
	tasmanFrame struct {
		session       [16]byte
		counter, born uint64
		kind          byte
		generation    uint32
		index, finalK byte
		width         int
		body, padding []byte
	}
)

type tasmanCipher struct {
	aead      cipher.AEAD
	hp        [32]byte
	direction byte
}

func newTasmanCipher(password []byte, direction byte) (*tasmanCipher, error) {
	if direction > 1 {
		return nil, errTasmanFrame
	}
	suffix := "c2s"
	if direction == 1 {
		suffix = "s2c"
	}
	key, err := tasmanDerive(password, "aead/"+suffix)
	if err != nil {
		return nil, err
	}
	hp, err := tasmanDerive(password, "nonce-mask/"+suffix)
	if err != nil {
		return nil, err
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	c := &tasmanCipher{aead: a, direction: direction}
	copy(c.hp[:], hp)
	return c, nil
}

func tasmanContext(label string, dir byte, w int) []byte {
	b := append([]byte(tasmanDomain), 0)
	b = append(b, label...)
	return append(b, 0, dir, byte(w>>8), byte(w))
}

func (c *tasmanCipher) mask(w int, tag []byte) []byte {
	m := hmac.New(sha256.New, c.hp[:])
	m.Write(tasmanContext("nonce-mask", c.direction, w))
	m.Write(tag)
	return m.Sum(nil)[:24]
}

func parseTasmanRecords(data []byte, out *[tasmanRecordsMax]tasmanRecord) (int, error) {
	n := 0
	for len(data) > 0 {
		if len(data) < 11 || n == len(out) {
			return 0, errTasmanFrame
		}
		r := tasmanRecord{message: binary.BigEndian.Uint32(data), total: binary.BigEndian.Uint16(data[4:]), offset: binary.BigEndian.Uint16(data[6:])}
		l := int(binary.BigEndian.Uint16(data[8:]))
		data = data[10:]
		if r.message == 0 || r.total < 1 || r.total > 1200 || l < 1 || l > len(data) || int(r.offset)+l > int(r.total) {
			return 0, errTasmanFrame
		}
		r.data = data[:l]
		data = data[l:]
		for j := range n {
			q := out[j]
			if q.message == r.message && tasmanRecordsConflict(q, r) {
				return 0, errTasmanFrame
			}
		}
		out[n] = r
		n++
	}
	if n == 0 {
		return 0, errTasmanFrame
	}
	return n, nil
}

func parseTasmanSymbol(body []byte, out *[tasmanRecordsMax]tasmanRecord) (int, error) {
	if !tasmanWidth(len(body)) {
		return 0, errTasmanFrame
	}
	used := int(binary.BigEndian.Uint16(body))
	if used < 11 || used > len(body)-2 {
		return 0, errTasmanFrame
	}
	for _, b := range body[2+used:] {
		if b != 0 {
			return 0, errTasmanFrame
		}
	}
	return parseTasmanRecords(body[2:2+used], out)
}

func validateTasmanFrame(f *tasmanFrame) error {
	if f.born == 0 || f.born > math.MaxInt64 || f.kind > tasmanShort {
		return errTasmanFrame
	}
	overhead := 60
	var records [tasmanRecordsMax]tasmanRecord
	switch f.kind {
	case tasmanShort:
		overhead = 52
		n, err := parseTasmanRecords(f.body, &records)
		if err != nil || n != 1 || records[0].offset != 0 || len(records[0].data) != int(records[0].total) || len(f.padding) != 0 || f.generation != 0 || f.width != 0 || f.index != 0 || f.finalK != 0 {
			return errTasmanFrame
		}
	case tasmanCover:
		if f.generation != 0 || f.width != 0 || f.index != 0 || f.finalK != 0 || len(f.body) != 0 {
			return errTasmanFrame
		}
	case tasmanSource, tasmanRepair:
		if f.generation == 0 || !tasmanWidth(f.width) || len(f.body) != f.width {
			return errTasmanFrame
		}
		if f.kind == tasmanSource {
			if f.index > 7 || f.finalK != 0 {
				return errTasmanFrame
			}
			if _, err := parseTasmanSymbol(f.body, &records); err != nil {
				return err
			}
		} else if f.index < 0x80 || f.index > 0x81 || f.finalK < 2 || f.finalK > 8 {
			return errTasmanFrame
		}
	}
	if overhead+len(f.body)+len(f.padding) > tasmanWireMax {
		return errTasmanFrame
	}
	return nil
}

func encodeTasmanRecord(dst []byte, r tasmanRecord) int {
	binary.BigEndian.PutUint32(dst, r.message)
	binary.BigEndian.PutUint16(dst[4:], r.total)
	binary.BigEndian.PutUint16(dst[6:], r.offset)
	binary.BigEndian.PutUint16(dst[8:], uint16(len(r.data)))
	copy(dst[10:], r.data)
	return 10 + len(r.data)
}

func (c *tasmanCipher) seal(f *tasmanFrame) ([]byte, error) {
	if err := validateTasmanFrame(f); err != nil {
		return nil, err
	}
	h := 20
	if f.kind == tasmanShort {
		h = 12
	}
	p := make([]byte, h+len(f.body)+len(f.padding))
	binary.BigEndian.PutUint64(p, f.born)
	binary.BigEndian.PutUint16(p[8:], uint16(len(f.padding)))
	binary.BigEndian.PutUint16(p[10:], uint16(f.kind))
	if h == 20 {
		binary.BigEndian.PutUint32(p[12:], f.generation)
		p[16], p[17] = f.index, f.finalK
		binary.BigEndian.PutUint16(p[18:], uint16(f.width))
	}
	copy(p[h:], f.body)
	copy(p[h+len(f.body):], f.padding)
	var nonce [24]byte
	copy(nonce[:16], f.session[:])
	binary.BigEndian.PutUint64(nonce[16:], f.counter)
	w := len(p) + 40
	out := make([]byte, 24, w)
	out = c.aead.Seal(out, nonce[:], p, tasmanContext("frame", c.direction, w))
	mask := c.mask(w, out[len(out)-16:])
	for i := range 24 {
		out[i] = nonce[i] ^ mask[i]
	}
	return out, nil
}

func decodeTasmanPlain(p []byte) (tasmanFrame, error) {
	var f tasmanFrame
	if len(p) < 12 || len(p) > 1192 || binary.BigEndian.Uint16(p[10:]) > 3 {
		return f, errTasmanFrame
	}
	f.born = binary.BigEndian.Uint64(p)
	f.kind = p[11]
	pad := int(binary.BigEndian.Uint16(p[8:]))
	h := 20
	if f.kind == tasmanShort {
		h = 12
	}
	if len(p) < h || pad > len(p)-h {
		return f, errTasmanFrame
	}
	if h == 20 {
		f.generation = binary.BigEndian.Uint32(p[12:])
		f.index, f.finalK = p[16], p[17]
		f.width = int(binary.BigEndian.Uint16(p[18:]))
	}
	f.body, f.padding = p[h:len(p)-pad], p[len(p)-pad:]
	if err := validateTasmanFrame(&f); err != nil {
		return tasmanFrame{}, err
	}
	return f, nil
}

func (c *tasmanCipher) open(w []byte, scratch *[tasmanWireMax]byte) (tasmanFrame, error) {
	var f tasmanFrame
	if len(w) < 60 || len(w) > tasmanWireMax {
		return f, errTasmanFrame
	}
	m := c.mask(len(w), w[len(w)-16:])
	var n [24]byte
	for i := range 24 {
		n[i] = w[i] ^ m[i]
	}
	p, err := c.aead.Open(scratch[:0], n[:], w[24:], tasmanContext("frame", c.direction, len(w)))
	if err != nil {
		return f, errTasmanAuth
	}
	f, err = decodeTasmanPlain(p)
	if err != nil {
		return f, err
	}
	copy(f.session[:], n[:16])
	f.counter = binary.BigEndian.Uint64(n[16:])
	return f, nil
}
