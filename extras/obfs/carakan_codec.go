// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	carakanNonce        = chacha20poly1305.NonceSizeX
	carakanHeader       = 12
	carakanOverhead     = carakanNonce + carakanHeader + chacha20poly1305.Overhead
	carakanInnerMax     = 1200
	carakanMaxParts     = 32
	carakanMessageLimit = uint64(1) << 59
)

var (
	ErrCarakanPacketSize = errors.New("carakan: inner datagram must contain 1..1200 bytes")
	errCarakanFrame      = errors.New("carakan: invalid authenticated frame")
)

type carakanHeaderFields struct {
	session            [16]byte
	message, born      uint64
	total, width, size uint16
	index, count       uint8
}

func carakanCiphers(password []byte, code int, server bool) (cipher.AEAD, cipher.AEAD, error) {
	makeCipher := func(direction string) (cipher.AEAD, error) {
		key, err := carakanDerive(password, fmt.Sprintf("aead/%s/%d", direction, code), 32)
		if err != nil {
			return nil, err
		}
		return chacha20poly1305.NewX(key)
	}
	c2s, err := makeCipher("client-to-server")
	if err != nil {
		return nil, nil, err
	}
	s2c, err := makeCipher("server-to-client")
	if err != nil {
		return nil, nil, err
	}
	if server {
		return s2c, c2s, nil
	}
	return c2s, s2c, nil
}

func (h carakanHeaderFields) encode(out []byte) {
	binary.BigEndian.PutUint64(out[:8], h.born)
	binary.BigEndian.PutUint16(out[8:10], uint16(h.count-1)<<11|h.total)
	binary.BigEndian.PutUint16(out[10:12], h.width)
}

func (t *carakanTANS) decodeHeader(in, nonce []byte) (carakanHeaderFields, []byte, error) {
	var h carakanHeaderFields
	if len(in) < carakanHeader || len(nonce) != carakanNonce {
		return h, nil, errCarakanFrame
	}
	copy(h.session[:], nonce[:16])
	sequence := binary.BigEndian.Uint64(nonce[16:])
	h.message, h.index = sequence>>5, uint8(sequence&31)
	h.born = binary.BigEndian.Uint64(in[:8])
	packed := binary.BigEndian.Uint16(in[8:10])
	h.total, h.count = packed&2047, uint8(packed>>11)+1
	h.width = binary.BigEndian.Uint16(in[10:12])
	h.size = uint16(len(in) - carakanHeader)
	if !h.valid(t.partMax) {
		return h, nil, errCarakanFrame
	}
	return h, in[carakanHeader:], nil
}

func (h carakanHeaderFields) valid(partMax int) bool {
	k, width, total := int(h.count), int(h.width), int(h.total)
	if h.session == ([16]byte{}) || h.born == 0 || total < 1 || total > carakanInnerMax || k < 1 || k > carakanMaxData || k > total ||
		int(h.index) >= k+carakanRepairCount(k) || width < 1 || width > partMax || width*k < total || width*(k-1) >= total {
		return false
	}
	if k == 1 && width != total {
		return false
	}
	expected := width
	if int(h.index) == k-1 {
		expected = total - (k-1)*width
	}
	return int(h.size) == expected
}

type (
	carakanPart struct{ offset, size int }
	carakanPlan struct {
		parts [carakanMaxParts]carakanPart
		count int
		width int
	}
)

func (t *carakanTANS) plan(size int, r *rand.Rand) carakanPlan {
	p := carakanPlan{count: (size + t.partMax - 1) / t.partMax}
	lo, hi := (size+p.count-1)/p.count, size
	if p.count > 1 {
		hi = min(t.partMax, (size-1)/(p.count-1))
	}
	p.width = lo + r.IntN(hi-lo+1)
	for i := range p.count {
		p.parts[i] = carakanPart{i * p.width, min(p.width, size-i*p.width)}
	}
	return p
}
