// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	netfrontDomain   = "oh-my-hysteria/netfront/v1"
	netfrontMaxLanes = 3
	netfrontMaxSide  = 384
	netfrontLease    = 20 * time.Second
)

// NetFrontOptions lists server-side port numbers in lane order, on both peers.
type NetFrontOptions struct {
	Password   []byte
	ExtraPorts []int
}

func (o NetFrontOptions) Validate(primary int) error {
	if len(o.Password) < 32 || len(o.Password) > 1024 {
		return errors.New("netfront: password must contain 32..1024 bytes")
	}
	if primary < 1 || primary > 65535 {
		return errors.New("netfront: a fixed primary UDP port is required")
	}
	if len(o.ExtraPorts) < 2 || len(o.ExtraPorts) > netfrontMaxLanes {
		return errors.New("netfront: extraPorts must list two or three UDP ports")
	}
	for i, port := range o.ExtraPorts {
		if port < 1 || port > 65535 || port == primary {
			return fmt.Errorf("netfront: invalid extraPorts entry %d (must be 1..65535 and distinct from the primary port)", port)
		}
		for _, other := range o.ExtraPorts[:i] {
			if port == other {
				return fmt.Errorf("netfront: duplicate port %d in extraPorts", port)
			}
		}
	}
	return nil
}

type netfrontLaneShape struct {
	length, spread        int // total UDP payload, including the authenticated envelope
	burst, gapMS, quietMS int
}

type netfrontProfile struct {
	prestoKey []byte
	tx, rx    cipher.AEAD
	lanes     []netfrontLaneShape
	seed      [2]uint64
}

func (v prestoVariant) compileNetfront(o NetFrontOptions, server bool) (p netfrontProfile, err error) {
	derive := func(label string, n int) ([]byte, error) {
		return hkdf.Key(sha256.New, o.Password, []byte(netfrontDomain), label, n)
	}
	if p.prestoKey, err = derive("presto-root", 32); err != nil {
		return p, err
	}
	sideKey := func(dir string) (cipher.AEAD, error) {
		k, e := derive(v.authLabel("side/"+dir), 32)
		if e != nil {
			return nil, e
		}
		return chacha20poly1305.NewX(k)
	}
	out, in := "client-to-server", "server-to-client"
	if server {
		out, in = in, out
	}
	if p.tx, err = sideKey(out); err != nil {
		return p, err
	}
	if p.rx, err = sideKey(in); err != nil {
		return p, err
	}
	b, err := derive("shape/"+out, 40)
	if err != nil {
		return p, err
	}
	p.seed = [2]uint64{binary.BigEndian.Uint64(b), binary.BigEndian.Uint64(b[8:])}
	// Role permutation is shared; sizes and timing within a role are directional.
	order, err := derive("roles", 2)
	if err != nil {
		return p, err
	}
	shapes := []netfrontLaneShape{
		{260 + int(b[16])%95, 16 + int(b[17])%14, 2 + int(b[18])%5, 12 + int(b[19])%16, 95 + int(b[20])*2},  // voice-like talk spurts
		{120 + int(b[21])%80, 8 + int(b[22])%16, 1, 0, 550 + int(b[23])*6},                                  // heartbeat-like isolated events
		{190 + int(b[24])%72, 10 + int(b[25])%20, 1 + int(b[26])%3, 35 + int(b[27])%55, 190 + int(b[28])*3}, // chat-like short groups
	}
	p.lanes = shapes[:len(o.ExtraPorts)]
	for i := len(p.lanes) - 1; i > 0; i-- {
		j := int(order[i-1]) % (i + 1)
		p.lanes[i], p.lanes[j] = p.lanes[j], p.lanes[i]
	}
	return p, nil
}

type netfrontLane struct {
	remote              netip.AddrPort // physical source, never the address handed up to QUIC
	seq                 uint64
	token               [16]byte
	verified            bool
	until, probeAt, due time.Time
	left                int
	prior               netfrontPriorLease
}

// Receive only. A renewal can overtake data already in flight in either
// direction. Never use this slot to send, prove a new path or extend a lease.
type netfrontPriorLease struct {
	seq   uint64
	token [16]byte
	until time.Time
}

func (l *netfrontLane) retire(remote netip.AddrPort, now time.Time) {
	if remote != l.remote {
		l.prior = netfrontPriorLease{}
	} else if l.verified {
		until := now.Add(2 * time.Second)
		if l.until.Before(until) {
			until = l.until
		}
		l.prior = netfrontPriorLease{l.seq, l.token, until}
	}
}

// All fields live with the primary client sending session / server receiving
// peer and are protected by prestoPacketConn.mu. There is no second peer map.
type netfrontSession struct {
	id, txID               [16]byte
	rng                    *rand.Rand
	lanes                  [netfrontMaxLanes]netfrontLane
	mainPackets, mainBytes int
}

func (p *netfrontProfile) newSession(id [16]byte) *netfrontSession {
	// The ID is independently random for each Presto sender. PCG is used
	// exclusively for traffic shape, never for the challenge or an AEAD nonce.
	return &netfrontSession{id: id, rng: rand.New(rand.NewPCG(
		p.seed[0]^binary.BigEndian.Uint64(id[:8]), p.seed[1]^binary.BigEndian.Uint64(id[8:])))}
}

func (s *netfrontSession) credit(n int) {
	s.mainPackets = min(8, s.mainPackets+1)
	s.mainBytes = min(8*netfrontMaxSide, s.mainBytes+n)
}

func (s *netfrontSession) schedule(l *netfrontLane, spec netfrontLaneShape, now time.Time) {
	if l.left == 0 {
		l.left = 1 + s.rng.IntN(spec.burst)
	}
	l.left--
	gap := spec.gapMS
	if l.left == 0 {
		gap = spec.quietMS
	}
	l.due = now.Add(time.Duration(gap/2+s.rng.IntN(gap+1)) * time.Millisecond)
}

// At most one action per foreground write. Packet and byte credits are hard
// ceilings, not target shares. Missed time slots never accumulate while idle.
func (s *netfrontSession) choose(p *netfrontProfile, dests []netip.AddrPort, size int, now time.Time) (a netfrontAction) {
	if s.mainPackets < 4 {
		return a
	}
	start := s.rng.IntN(len(p.lanes))
	for i := range p.lanes {
		idx := (i + start) % len(p.lanes)
		l, spec := &s.lanes[idx], p.lanes[idx]
		probe := len(dests) != 0 && !now.Before(l.probeAt)
		if !probe && (!l.verified || !now.Before(l.until) || now.Before(l.due)) {
			continue
		}
		length := spec.length + s.rng.IntN(2*spec.spread+1) - spec.spread
		if probe {
			length = 92 + s.rng.IntN(49)
		}
		if s.mainBytes < 8*length {
			continue
		}
		s.mainBytes -= 8 * length
		s.mainPackets -= 4
		a = netfrontAction{lane: idx + 1, wire: length, addr: l.remote, frame: netfrontFrame{session: s.id, seq: l.seq, token: l.token}}
		if probe {
			l.retire(dests[idx], now)
			l.seq++ // session rotates at 10 minutes; even a failed probe consumes a number
			l.verified, l.token = false, [16]byte{}
			l.remote = dests[idx]
			l.probeAt = now.Add(time.Duration(1200+s.rng.IntN(1601)) * time.Millisecond)
			l.until = l.probeAt // do not accept late offers indefinitely
			a.addr, a.frame.kind, a.frame.seq, a.frame.token = l.remote, nfProbe, l.seq, l.token
		} else {
			s.schedule(l, spec, now)
			a.frame.kind = nfCover
			if size >= prestoOverhead && size+netfrontOverhead <= length {
				a.frame.kind = nfData
			}
		}
		return a
	}
	return a
}
