// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	blinkNonce    = chacha20poly1305.NonceSizeX
	blinkHeader   = 32
	blinkOverhead = blinkNonce + blinkHeader + chacha20poly1305.Overhead
	// These are UDP payload sizes, not IP MTUs. Never parse a QUIC header.
	blinkInnerMax   = 1200
	blinkWireMax    = 1400
	blinkReceiveMax = 1500
	blinkFragments  = 4
)

var (
	ErrBlinkPacketSize = errors.New("blink: inner datagram must contain 1..1200 bytes")
	errBlinkFrame      = errors.New("blink: invalid authenticated frame")
)

type blinkHeaderFields struct {
	session      [16]byte
	message      uint64
	total, size  uint16
	index, count uint8
}

func blinkCiphers(password []byte, server bool) (cipher.AEAD, cipher.AEAD, error) {
	if len(password) < 16 || len(password) > 1024 {
		return nil, nil, errors.New("blink: password must contain 16..1024 bytes; use a random secret")
	}
	makeCipher := func(direction string) (cipher.AEAD, error) {
		key, err := hkdf.Key(sha256.New, password, []byte("oh-my-hysteria/blink/v1"), direction, 32)
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

func (h blinkHeaderFields) encode(out []byte) {
	copy(out, h.session[:])
	binary.BigEndian.PutUint64(out[16:24], h.message)
	binary.BigEndian.PutUint16(out[24:26], h.total)
	binary.BigEndian.PutUint16(out[26:28], h.size)
	out[28], out[29], out[30], out[31] = h.index, h.count, 1, 0
}

// Called only after AEAD verification. Exact equal-sized ranges (except the
// final range) forbid overlaps, gaps, inconsistent lengths and sparse offsets.
func decodeBlinkHeader(in []byte) (blinkHeaderFields, []byte, error) {
	var h blinkHeaderFields
	if len(in) < blinkHeader || in[30] != 1 || in[31] != 0 {
		return h, nil, errBlinkFrame
	}
	copy(h.session[:], in[:16])
	h.message = binary.BigEndian.Uint64(in[16:24])
	h.total = binary.BigEndian.Uint16(in[24:26])
	h.size = binary.BigEndian.Uint16(in[26:28])
	h.index, h.count = in[28], in[29]
	if h.session == ([16]byte{}) || h.total == 0 || h.total > blinkInnerMax || h.count == 0 || h.count > blinkFragments || h.index >= h.count || int(h.count) > int(h.total) {
		return h, nil, errBlinkFrame
	}
	span := (int(h.total) + int(h.count) - 1) / int(h.count)
	if (int(h.count)-1)*span >= int(h.total) {
		return h, nil, errBlinkFrame
	}
	start := int(h.index) * span
	expected := min(span, int(h.total)-start)
	if expected <= 0 || int(h.size) != expected || len(in) < blinkHeader+expected || len(in)-blinkHeader-expected > 128 {
		return h, nil, errBlinkFrame
	}
	return h, in[blinkHeader : blinkHeader+expected], nil
}
