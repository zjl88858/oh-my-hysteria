// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math/rand/v2"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	tridentNonce    = chacha20poly1305.NonceSizeX
	tridentHeader   = 44
	tridentOverhead = tridentNonce + tridentHeader + chacha20poly1305.Overhead
	tridentInnerMax = 1200
	tridentWireMax  = 1232
	tridentRawMax   = 600
	tridentPartMax  = tridentRawMax - tridentOverhead
)

var (
	ErrTridentPacketSize = errors.New("trident: inner datagram must contain 1..1200 bytes")
	errTridentProgram    = errors.New("trident: invalid bytecode program")
	errTridentFrame      = errors.New("trident: invalid authenticated frame")
)

type tridentHeaderFields struct {
	session             [16]byte
	message, born       uint64
	total, offset, size uint16
	index, count        uint8
}

func tridentCiphers(password []byte, server bool) (cipher.AEAD, cipher.AEAD, error) {
	makeCipher := func(direction string) (cipher.AEAD, error) {
		key, err := tridentDerive(password, "aead/"+direction, 32)
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

func (h tridentHeaderFields) encode(out []byte) {
	copy(out, h.session[:])
	binary.BigEndian.PutUint64(out[16:24], h.message)
	binary.BigEndian.PutUint64(out[24:32], h.born)
	binary.BigEndian.PutUint16(out[32:34], h.total)
	binary.BigEndian.PutUint16(out[34:36], h.offset)
	binary.BigEndian.PutUint16(out[36:38], h.size)
	out[38], out[39], out[40], out[41], out[42], out[43] = h.index, h.count, 0, 1, 0, 0
}

func decodeTridentHeader(in []byte) (tridentHeaderFields, []byte, error) {
	var h tridentHeaderFields
	if len(in) < tridentHeader || in[40] != 0 || in[41] != 1 || in[42] != 0 || in[43] != 0 {
		return h, nil, errTridentFrame
	}
	copy(h.session[:], in[:16])
	h.message = binary.BigEndian.Uint64(in[16:24])
	h.born = binary.BigEndian.Uint64(in[24:32])
	h.total = binary.BigEndian.Uint16(in[32:34])
	h.offset = binary.BigEndian.Uint16(in[34:36])
	h.size = binary.BigEndian.Uint16(in[36:38])
	h.index, h.count = in[38], in[39]
	if h.session == ([16]byte{}) || h.born == 0 || h.total == 0 || h.total > tridentInnerMax || h.size == 0 || h.size > tridentPartMax || len(in) != tridentHeader+int(h.size) ||
		h.count == 0 || h.count > 4 || h.index >= h.count || int(h.count) > int(h.total) || int(h.offset)+int(h.size) > int(h.total) || int(h.count)*tridentPartMax < int(h.total) ||
		(h.count == 1 && (h.offset != 0 || h.size != h.total)) {
		return h, nil, errTridentFrame
	}
	return h, in[tridentHeader:], nil
}

type (
	tridentPart struct{ offset, size int }
	tridentPlan struct {
		parts [4]tridentPart
		count int
	}
)

func planTrident(size int, r *rand.Rand) tridentPlan {
	p := tridentPlan{count: (size + tridentPartMax - 1) / tridentPartMax}
	if size >= 256 && p.count < 4 && r.IntN(2) == 0 {
		p.count++
	}
	remaining, offset := size, 0
	minimum := min(64, size/p.count)
	for i := range p.count {
		slots := p.count - i
		lo := max(minimum, remaining-(slots-1)*tridentPartMax)
		hi := min(tridentPartMax, remaining-(slots-1)*minimum)
		n := lo + r.IntN(hi-lo+1)
		p.parts[i] = tridentPart{offset, n}
		offset += n
		remaining -= n
	}
	return p
}
