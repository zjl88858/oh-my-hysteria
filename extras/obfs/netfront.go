// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"net"
	"net/netip"
	"time"
)

type NetFrontLaneStats struct {
	SentPackets, SentBytes, Data, Cover, Probes, Offers, WriteErrors uint64
	ReceivedData, VerifiedPaths                                      uint64
}

type NetFrontStats struct {
	// Index 0 is the primary UDP socket; 1..3 follow extraPorts.
	Lanes                           [1 + netfrontMaxLanes]NetFrontLaneStats
	AuthDrops, PathDrops, RateDrops uint64
}

type netfrontWire struct {
	*netfrontSockets
	presto   *prestoPacketConn
	profile  netfrontProfile
	primary  netip.AddrPort      // client only
	dests    []netip.AddrPort    // nil on server
	offers   chan netfrontAction // bounded; a blocked side write must not stall QUIC reads
	fromSide bool                // serialized by presto.readMu
	stats    NetFrontStats       // guarded by presto.mu
	verify   blinkBucket
	shards   [64]blinkBucket // read side serialized by Presto, independent of the main verification budget
}

type netfrontConn struct {
	net.PacketConn
	wire *netfrontWire
}

// WrapPacketConnNetFront takes ownership of the sockets only on success.
// serverAddr is the fixed remote primary on a client, nil on a server.
// sides contain distinct, unconnected UDP sockets in ExtraPorts order.
func WrapPacketConnNetFront(main net.PacketConn, sides []net.PacketConn, serverAddr *net.UDPAddr, opts NetFrontOptions) (net.PacketConn, error) {
	return prestoStandard.wrapNetFront(main, sides, serverAddr, opts)
}

// WrapPacketConnNetFrontLite uses a Lite primary and separately authenticated
// NetFrontLite side lanes. Socket ownership and extra-port order match NetFront.
func WrapPacketConnNetFrontLite(main net.PacketConn, sides []net.PacketConn, serverAddr *net.UDPAddr, opts NetFrontOptions) (net.PacketConn, error) {
	return prestoLite.wrapNetFront(main, sides, serverAddr, opts)
}

func (v prestoVariant) wrapNetFront(main net.PacketConn, sides []net.PacketConn, serverAddr *net.UDPAddr, opts NetFrontOptions) (net.PacketConn, error) {
	if main == nil {
		return nil, errors.New("netfront: missing primary socket")
	}
	local, ok := main.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return nil, errors.New("netfront: expected a UDP listener")
	}
	primaryPort := local.Port
	var remote netip.AddrPort
	if serverAddr != nil {
		remote, _, ok = blinkAddress(serverAddr)
		if !ok {
			return nil, errors.New("netfront: expected a concrete server UDP address")
		}
		primaryPort = int(remote.Port())
	}
	if err := opts.Validate(primaryPort); err != nil {
		return nil, err
	}
	if len(sides) != len(opts.ExtraPorts) {
		return nil, errors.New("netfront: need one socket per extra port")
	}
	conns := append([]net.PacketConn{main}, sides...)
	seen := map[netip.AddrPort]bool{local.AddrPort(): true}
	for i, c := range sides {
		if c == nil {
			return nil, errors.New("netfront: missing side socket")
		}
		a, ok := c.LocalAddr().(*net.UDPAddr)
		if !ok || a == nil || seen[a.AddrPort()] ||
			(serverAddr == nil && (a.Port != opts.ExtraPorts[i] || !a.IP.Equal(local.IP) || a.Zone != local.Zone)) {
			return nil, fmt.Errorf("netfront: invalid socket for extra port %d", opts.ExtraPorts[i])
		}
		seen[a.AddrPort()] = true
	}
	profile, err := v.compileNetfront(opts, serverAddr == nil)
	if err != nil {
		return nil, err
	}
	w := &netfrontWire{netfrontSockets: newNetfrontSockets(conns), primary: remote, profile: profile}
	if remote.IsValid() {
		for _, port := range opts.ExtraPorts {
			w.dests = append(w.dests, netip.AddrPortFrom(remote.Addr(), uint16(port)))
		}
	}
	w.presto, err = v.newPrestoConn(w, PrestoOptions{Password: profile.prestoKey, Server: serverAddr == nil})
	if err != nil {
		return nil, err
	}
	w.profile.prestoKey = nil
	w.presto.acceptSource = w.acceptSource
	if serverAddr == nil {
		w.offers = make(chan netfrontAction, 16)
		w.wg.Add(1)
		go w.replyLoop()
	}
	for lane := range conns {
		w.wg.Add(1)
		go w.pump(lane)
	}
	return &netfrontConn{PacketConn: w.presto, wire: w}, nil
}

func (*netfrontConn) QUICPacketSizeLimit() int { return prestoInnerMax }

// QUIC's large buffers are useful on the bulk socket. Side sockets carry at
// most 384-byte packets and retain the OS defaults. Do not expose OOB/GSO.
func (c *netfrontConn) SetReadBuffer(n int) error {
	if sock, ok := c.wire.conns[0].(interface{ SetReadBuffer(int) error }); ok {
		return sock.SetReadBuffer(n)
	}
	return errors.ErrUnsupported
}

func (c *netfrontConn) SetWriteBuffer(n int) error {
	if sock, ok := c.wire.conns[0].(interface{ SetWriteBuffer(int) error }); ok {
		return sock.SetWriteBuffer(n)
	}
	return errors.ErrUnsupported
}

func (w *netfrontWire) replyLoop() {
	defer w.wg.Done()
	for {
		select {
		case <-w.done:
			return
		case a := <-w.offers:
			if time.Now().Before(a.deadline) {
				_ = w.sendSide(a)
			}
		}
	}
}

func (w *netfrontWire) acceptSource(ap netip.AddrPort, h prestoHeaderFields) bool {
	if !w.fromSide {
		return true
	}
	p := w.presto.routes[ap]
	return p != nil && p.session == h.session && p.born == h.born && time.Since(p.used) < prestoSessionTTL
}

func (c *netfrontConn) NetFrontStats() NetFrontStats {
	c.wire.presto.mu.Lock()
	defer c.wire.presto.mu.Unlock()
	return c.wire.stats
}

func (c *netfrontConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.wire.primary.IsValid() {
		if ap, _, ok := blinkAddress(addr); !ok || ap != c.wire.primary {
			return 0, errors.New("netfront: writes must target the configured primary endpoint")
		}
	}
	return c.PacketConn.WriteTo(b, addr)
}

// session is called with presto.mu held. Only the primary receive path can
// admit a new peer. Old client sessions at the same endpoint lose all rights
// to issue probes and send side data as soon as the primary route changes.
func (w *netfrontWire) session(ap netip.AddrPort, now time.Time) *netfrontSession {
	c := w.presto
	if c.closed {
		return nil
	}
	var id [16]byte
	var slot **netfrontSession
	if c.opts.Server {
		p := c.routes[ap]
		if p == nil || now.Sub(p.used) >= prestoSessionTTL {
			return nil
		}
		id, slot = p.session, &p.netfront
	} else {
		s := c.senders[ap]
		if s == nil || c.routes[ap] == nil {
			return nil
		}
		id, slot = s.session, &s.netfront
	}
	if *slot == nil {
		*slot = w.profile.newSession(id)
	}
	return *slot
}

func (w *netfrontWire) sendSide(a netfrontAction) error {
	var buf [netfrontMaxSide]byte
	b := a.seal(buf[:], w.profile.tx, len(w.profile.lanes))
	n, err := w.writeSide(a.lane, b, net.UDPAddrFromAddrPort(a.addr))
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	w.presto.mu.Lock()
	defer w.presto.mu.Unlock()
	stats := &w.stats.Lanes[a.lane]
	if err != nil {
		stats.WriteErrors++
		return err
	}
	stats.SentPackets++
	stats.SentBytes += uint64(n)
	switch a.frame.kind {
	case nfData:
		stats.Data++
	case nfCover:
		stats.Cover++
	case nfProbe:
		stats.Probes++
	case nfOffer:
		stats.Offers++
	}
	return nil
}

// Receives already sealed Presto frames. A small frame can be carried once on
// a verified lane. If only large frames are available a budgeted side pulse
// follows a successful main write. Neither case waits for a reply.
func (w *netfrontWire) WriteTo(b []byte, addr net.Addr) (int, error) {
	ap, _, ok := blinkAddress(addr)
	if !ok {
		return 0, errors.New("netfront: expected UDP destination")
	}
	now := time.Now()
	w.presto.mu.Lock()
	s := w.session(ap, now)
	var a netfrontAction
	if s != nil {
		// A rotated server sender must introduce itself on the primary first.
		if tx := w.presto.senders[ap]; tx != nil && s.txID != tx.session {
			s.txID, s.mainPackets, s.mainBytes = tx.session, 0, 0
		}
		a = s.choose(&w.profile, w.dests, len(b), now)
	}
	w.presto.mu.Unlock()
	if a.frame.kind == nfData {
		a.frame.body = b
		if err := w.sendSide(a); err == nil {
			return len(b), nil
		}
		// Same authenticated inner message ID: even an ambiguous short write
		// followed by a main-path retry cannot deliver the datagram twice.
	}
	n, err := w.conns[0].WriteTo(b, addr)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	w.presto.mu.Lock()
	if err == nil {
		w.stats.Lanes[0].SentPackets++
		w.stats.Lanes[0].SentBytes += uint64(n)
		if s != nil {
			s.credit(n)
		}
	} else {
		w.stats.Lanes[0].WriteErrors++
	}
	w.presto.mu.Unlock()
	if err == nil && (a.frame.kind == nfCover || a.frame.kind == nfProbe) {
		_ = w.sendSide(a)
	}
	return n, err
}

// acceptSide is called after AEAD/length checks, with presto.mu held. A
// fresh challenge is tied to one (client session, lane, observed address,
// sequence, expiry). Nothing received here extends its lifetime.
func (w *netfrontWire) acceptSide(f netfrontFrame, physical netip.AddrPort, lane, size int, now time.Time) (netip.AddrPort, netfrontAction, bool) {
	var reply netfrontAction
	main := w.primary
	if !main.IsValid() {
		p := w.presto.peers[f.session]
		if p == nil || p.addr.Addr() != physical.Addr() || w.presto.routes[p.addr] != p {
			return netip.AddrPort{}, reply, false
		}
		main = p.addr
	}
	s := w.session(main, now)
	if s == nil || f.session != s.id {
		return netip.AddrPort{}, reply, false
	}
	l := &s.lanes[lane-1]
	switch f.kind {
	case nfProbe:
		if w.primary.IsValid() || f.seq <= l.seq || now.Before(l.probeAt) {
			break
		}
		l.retire(physical, now)
		l.seq, l.remote, l.verified = f.seq, physical, false
		l.until, l.probeAt = now.Add(netfrontLease), now.Add(time.Second)
		rand.Read(l.token[:])
		reply = netfrontAction{lane: lane, wire: size, addr: physical, deadline: now.Add(time.Second), frame: netfrontFrame{kind: nfOffer, session: s.id, seq: l.seq, token: l.token}}
		return netip.AddrPort{}, reply, true
	case nfOffer:
		if !w.primary.IsValid() || l.verified || l.seq != f.seq || l.remote != physical || !now.Before(l.until) {
			break
		}
		l.token, l.verified = f.token, true
		// Renew before the server's lease expires; don't rely on delivery of
		// any one confirmation. Every client data/cover can prove receipt.
		l.probeAt = now.Add(time.Duration(9+s.rng.IntN(5)) * time.Second)
		l.until = now.Add(netfrontLease - 3*time.Second)
		w.stats.Lanes[lane].VerifiedPaths++
		return netip.AddrPort{}, reply, true
	case nfData, nfCover:
		if l.remote != physical {
			break
		}
		current := l.seq == f.seq && l.token == f.token && now.Before(l.until)
		if !current && (l.prior.seq != f.seq || l.prior.token != f.token || !now.Before(l.prior.until)) {
			break
		}
		if current && !l.verified {
			if w.primary.IsValid() {
				break
			}
			l.verified = true
			w.stats.Lanes[lane].VerifiedPaths++
		}
		if f.kind == nfData {
			w.stats.Lanes[lane].ReceivedData++
			return main, reply, true
		}
		return netip.AddrPort{}, reply, true // cover is consumed, never handed up or answered
	}
	return netip.AddrPort{}, reply, false
}

func (w *netfrontWire) readSide(p *netfrontPacket, out []byte) (int, net.Addr) {
	ap, prefix, ok := blinkAddress(p.addr)
	if !ok || (w.primary.IsValid() && ap != w.dests[p.lane-1]) {
		return 0, nil
	}
	now := time.Now()
	shard := maphash.Comparable(w.presto.hashSeed, prefix) % uint64(len(w.shards))
	if !w.verify.allow(now, 8192, 1024) || !w.shards[shard].allow(now, 2048, 256) {
		w.presto.mu.Lock()
		w.stats.RateDrops++
		w.presto.mu.Unlock()
		return 0, nil
	}
	f, ok := openNetfront(p.buf[:p.n], w.profile.rx, len(w.profile.lanes), p.lane)
	w.presto.mu.Lock()
	if !ok {
		w.stats.AuthDrops++
		w.presto.mu.Unlock()
		return 0, nil
	}
	main, reply, accepted := w.acceptSide(f, ap, p.lane, p.n, now)
	if !accepted {
		w.stats.PathDrops++
	}
	w.presto.mu.Unlock()
	if reply.wire != 0 {
		select {
		case w.offers <- reply:
		default: // best effort; a client with continuing traffic can retry
		}
	}
	if main.IsValid() {
		return copy(out, f.body), net.UDPAddrFromAddrPort(main)
	}
	return 0, nil
}

func (w *netfrontWire) ReadFrom(out []byte) (int, net.Addr, error) {
	for {
		p, err := w.next()
		if err != nil {
			return 0, nil, err
		}
		var n int
		var addr net.Addr
		w.fromSide = p.lane != 0
		if p.lane == 0 {
			n, addr = copy(out, p.buf[:p.n]), p.addr
		} else {
			n, addr = w.readSide(p, out)
		}
		w.pool.Put(p)
		if addr != nil {
			return n, addr, nil
		}
	}
}
