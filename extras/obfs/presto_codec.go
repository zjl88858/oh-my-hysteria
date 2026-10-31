// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	prestoNonce    = chacha20poly1305.NonceSizeX
	prestoHeader   = 44
	prestoOverhead = prestoNonce + prestoHeader + chacha20poly1305.Overhead
	prestoInnerMax = 1200
	prestoWireMax  = 1232
	prestoCover    = 1
)

var (
	ErrPrestoPacketSize = errors.New("presto: inner datagram must contain 1..1200 bytes")
	errPrestoFrame      = errors.New("presto: invalid authenticated frame")
)

type prestoHeaderFields struct {
	session             [16]byte
	message, born       uint64
	total, offset, size uint16
	index, count, kind  uint8
}

func prestoCiphers(password []byte, server bool) (cipher.AEAD, cipher.AEAD, error) {
	makeCipher := func(direction string) (cipher.AEAD, error) {
		key, err := prestoDerive(password, "aead/"+direction, 32)
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

func (h prestoHeaderFields) encode(out []byte) {
	copy(out, h.session[:])
	binary.BigEndian.PutUint64(out[16:24], h.message)
	binary.BigEndian.PutUint64(out[24:32], h.born)
	binary.BigEndian.PutUint16(out[32:34], h.total)
	binary.BigEndian.PutUint16(out[34:36], h.offset)
	binary.BigEndian.PutUint16(out[36:38], h.size)
	out[38], out[39], out[40], out[41], out[42], out[43] = h.index, h.count, h.kind, 1, 0, 0
}

// Only called after authentication. Grammar is send-side policy: receivers
// cannot require Markov synchronization across packet loss and reordering.
func decodePrestoHeader(in []byte) (prestoHeaderFields, []byte, error) {
	var h prestoHeaderFields
	if len(in) < prestoHeader || in[41] != 1 || in[42] != 0 || in[43] != 0 {
		return h, nil, errPrestoFrame
	}
	copy(h.session[:], in[:16])
	h.message = binary.BigEndian.Uint64(in[16:24])
	h.born = binary.BigEndian.Uint64(in[24:32])
	h.total = binary.BigEndian.Uint16(in[32:34])
	h.offset = binary.BigEndian.Uint16(in[34:36])
	h.size = binary.BigEndian.Uint16(in[36:38])
	h.index, h.count, h.kind = in[38], in[39], in[40]
	pad := len(in) - prestoHeader - int(h.size)
	if h.session == ([16]byte{}) || h.born == 0 || h.count == 0 || h.count > 4 || h.index >= h.count || pad < 0 || pad > 512 {
		return h, nil, errPrestoFrame
	}
	if h.kind == prestoCover {
		if h.total != 0 || h.offset != 0 || h.size != 0 || h.index != 0 || h.count != 1 || len(in)+prestoNonce+16 > 160 {
			return h, nil, errPrestoFrame
		}
	} else if h.kind != 0 || h.total == 0 || h.total > prestoInnerMax || h.size == 0 || int(h.offset)+int(h.size) > int(h.total) || int(h.count) > int(h.total) || (h.count == 1 && (h.offset != 0 || h.size != h.total)) {
		return h, nil, errPrestoFrame
	}
	return h, in[prestoHeader : prestoHeader+int(h.size)], nil
}
