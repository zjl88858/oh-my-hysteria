// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"time"
)

const (
	nfProbe byte = iota + 1
	nfOffer
	nfData
	nfCover
	netfrontHeader   = 1 + 16 + 8 + 16 + 2
	netfrontOverhead = prestoNonce + netfrontHeader + 16
)

type netfrontFrame struct {
	kind    byte
	session [16]byte // primary client sending session, in both directions
	seq     uint64   // probe number, then the lease it established
	token   [16]byte
	body    []byte // a complete sealed Presto frame, only for nfData
}

type netfrontAction struct {
	lane, wire int
	addr       netip.AddrPort
	deadline   time.Time // latest useful send time for a queued path offer
	frame      netfrontFrame
}

func (a netfrontAction) seal(buf []byte, aead cipher.AEAD, lanes int) []byte {
	buf = buf[:a.wire]
	rand.Read(buf)
	b := buf[prestoNonce : len(buf)-aead.Overhead()]
	b[0] = a.frame.kind
	copy(b[1:17], a.frame.session[:])
	binary.BigEndian.PutUint64(b[17:25], a.frame.seq)
	copy(b[25:41], a.frame.token[:])
	binary.BigEndian.PutUint16(b[41:43], uint16(len(a.frame.body)))
	copy(b[43:], a.frame.body)
	return aead.Seal(buf[:prestoNonce], buf[:prestoNonce], b, []byte{byte(lanes), byte(a.lane)})
}

func openNetfront(packet []byte, aead cipher.AEAD, lanes, lane int) (f netfrontFrame, ok bool) {
	if len(packet) < netfrontOverhead || len(packet) > netfrontMaxSide {
		return f, false
	}
	b, err := aead.Open(packet[prestoNonce:prestoNonce], packet[:prestoNonce], packet[prestoNonce:], []byte{byte(lanes), byte(lane)})
	if err != nil {
		return f, false
	}
	f.kind = b[0]
	copy(f.session[:], b[1:17])
	f.seq = binary.BigEndian.Uint64(b[17:25])
	copy(f.token[:], b[25:41])
	n := int(binary.BigEndian.Uint16(b[41:43]))
	if n > len(b)-netfrontHeader || f.session == ([16]byte{}) || f.seq == 0 {
		return f, false
	}
	f.body = b[netfrontHeader : netfrontHeader+n]
	switch f.kind {
	case nfProbe:
		ok = n == 0 && f.token == ([16]byte{})
	case nfOffer, nfCover:
		ok = n == 0 && f.token != ([16]byte{})
	case nfData:
		ok = n >= prestoOverhead && f.token != ([16]byte{})
	}
	return f, ok
}
