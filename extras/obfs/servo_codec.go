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
	servoNonce      = 24
	servoHeader     = 12
	servoDescriptor = 10
	servoOverhead   = 52
	servoInnerMax   = 1200
	servoDataMax    = 1100
	servoRecordsMax = 8
	servoWireMin    = 63
	servoWireMax    = 1232
)

var (
	errServoFrame = errors.New("servo: invalid frame")
	errServoAuth  = errors.New("servo: authentication failed")
)

type servoRecord struct {
	message uint32
	total   uint16
	offset  uint16
	data    []byte
}

// Only bounded stack metadata before authentication; data aliases caller-owned
// plaintext scratch. State must copy retained data before scratch is reused.
type servoFrame struct {
	session [16]byte
	counter uint64
	born    uint64
	count   int
	records [servoRecordsMax]servoRecord
}

type servoCipher struct {
	aead      cipher.AEAD
	hp        [32]byte
	direction byte
}

func newServoCipher(password []byte, direction byte) (*servoCipher, error) {
	if direction > 1 {
		return nil, errServoFrame
	}
	suffix := "c2s"
	if direction == 1 {
		suffix = "s2c"
	}
	key, err := servoDerive(password, "aead/"+suffix)
	if err != nil {
		return nil, err
	}
	hp, err := servoDerive(password, "nonce-mask/"+suffix)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	c := &servoCipher{aead: aead, direction: direction}
	copy(c.hp[:], hp)
	return c, nil
}

func servoContext(label string, direction byte, wire int) []byte {
	b := make([]byte, 0, len(servoDomain)+len(label)+5)
	b = append(b, servoDomain...)
	b = append(b, 0)
	b = append(b, label...)
	b = append(b, 0, direction, byte(wire>>8), byte(wire))
	return b
}

func (c *servoCipher) mask(wire int, tag []byte) []byte {
	m := hmac.New(sha256.New, c.hp[:])
	_, _ = m.Write(servoContext("nonce-mask", c.direction, wire))
	_, _ = m.Write(tag)
	return m.Sum(nil)[:servoNonce]
}

func validateServoRecords(f *servoFrame) (int, error) {
	if f.born == 0 || f.born > math.MaxInt64 || f.count < 1 || f.count > servoRecordsMax {
		return 0, errServoFrame
	}
	data := 0
	for i := range f.count {
		r := &f.records[i]
		if r.message == 0 || r.total < 1 || r.total > servoInnerMax || len(r.data) < 1 || int(r.offset)+len(r.data) > int(r.total) {
			return 0, errServoFrame
		}
		for j := range i {
			if f.records[j].message == r.message {
				return 0, errServoFrame
			}
		}
		data += len(r.data)
		if data > servoDataMax {
			return 0, errServoFrame
		}
	}
	return servoHeader + servoDescriptor*f.count + data, nil
}

func decodeServoPlain(plain []byte) (servoFrame, error) {
	var f servoFrame
	if len(plain) < servoHeader || len(plain) > servoWireMax-servoNonce-chacha20poly1305.Overhead || plain[9] != 0 {
		return f, errServoFrame
	}
	f.born = binary.BigEndian.Uint64(plain[:8])
	f.count = int(plain[8])
	if f.count < 1 || f.count > servoRecordsMax || int(binary.BigEndian.Uint16(plain[10:12])) != len(plain)-servoHeader {
		return servoFrame{}, errServoFrame
	}
	pos := servoHeader
	for i := range f.count {
		if len(plain)-pos < servoDescriptor {
			return servoFrame{}, errServoFrame
		}
		r := &f.records[i]
		r.message = binary.BigEndian.Uint32(plain[pos : pos+4])
		r.total = binary.BigEndian.Uint16(plain[pos+4 : pos+6])
		r.offset = binary.BigEndian.Uint16(plain[pos+6 : pos+8])
		n := int(binary.BigEndian.Uint16(plain[pos+8 : pos+10]))
		pos += servoDescriptor
		if n > len(plain)-pos {
			return servoFrame{}, errServoFrame
		}
		r.data = plain[pos : pos+n]
		pos += n
	}
	if _, err := validateServoRecords(&f); err != nil || pos != len(plain) {
		return servoFrame{}, errServoFrame
	}
	return f, nil
}

// seal never allocates a nonce or counter: the future sender must consume each
// counter once even on failure/cancellation. No payload-dependent retry exists.
func (c *servoCipher) seal(f *servoFrame) ([]byte, error) {
	n, err := validateServoRecords(f)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, n)
	binary.BigEndian.PutUint64(plain[:8], f.born)
	plain[8] = byte(f.count)
	binary.BigEndian.PutUint16(plain[10:12], uint16(n-servoHeader))
	pos := servoHeader
	for i := range f.count {
		r := &f.records[i]
		binary.BigEndian.PutUint32(plain[pos:pos+4], r.message)
		binary.BigEndian.PutUint16(plain[pos+4:pos+6], r.total)
		binary.BigEndian.PutUint16(plain[pos+6:pos+8], r.offset)
		binary.BigEndian.PutUint16(plain[pos+8:pos+10], uint16(len(r.data)))
		pos += servoDescriptor
		pos += copy(plain[pos:], r.data)
	}
	var nonce [servoNonce]byte
	copy(nonce[:16], f.session[:])
	binary.BigEndian.PutUint64(nonce[16:], f.counter)
	wire := n + servoNonce + chacha20poly1305.Overhead
	out := make([]byte, servoNonce, wire)
	out = c.aead.Seal(out, nonce[:], plain, servoContext("frame", c.direction, wire))
	mask := c.mask(wire, out[len(out)-chacha20poly1305.Overhead:])
	for i := range servoNonce {
		out[i] = nonce[i] ^ mask[i]
	}
	return out, nil
}

// open uses caller-owned fixed scratch; unauthenticated size/fields cannot
// allocate receive sessions or buffers proportional to an advertised total.
func (c *servoCipher) open(wire []byte, scratch *[servoWireMax]byte) (servoFrame, error) {
	var f servoFrame
	if len(wire) < servoWireMin || len(wire) > servoWireMax {
		return f, errServoFrame
	}
	mask := c.mask(len(wire), wire[len(wire)-chacha20poly1305.Overhead:])
	var nonce [servoNonce]byte
	for i := range servoNonce {
		nonce[i] = wire[i] ^ mask[i]
	}
	plain, err := c.aead.Open(scratch[:0], nonce[:], wire[servoNonce:], servoContext("frame", c.direction, len(wire)))
	if err != nil {
		return f, errServoAuth
	}
	f, err = decodeServoPlain(plain)
	if err != nil {
		return servoFrame{}, err
	}
	copy(f.session[:], nonce[:16])
	f.counter = binary.BigEndian.Uint64(nonce[16:])
	return f, nil
}
