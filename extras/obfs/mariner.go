// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/rand"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type (
	MarinerOptions struct {
		Password []byte
		Server   bool
	}
	MarinerStats struct {
		InnerAcceptedBytes, InnerDatagrams, InnerSentBytes, OuterSentBytes, OuterPackets                          uint64
		FragmentedMessages, RelationBytes, PaddingBytes, WriteErrors, PartialOuterBytes                           uint64
		GraphHits, GraphMisses, GraphPromotions, CompileDrops, RelationDrops                                      uint64
		QUICSendSamples, QUICDelayNanos, QUICDelayMaxNanos, QUICMetricSamples, QUICPacketsLostMax, QUICProbeCalls uint64
		QUICLatestRTT, QUICPTO                                                                                    time.Duration
		Senders, Sessions, Assemblies, ReassemblyBytes, GraphEntries, GraphBytes                                  int
		Receive                                                                                                   MarinerReceiveStats
	}
)

type (
	marinerSender struct {
		session, route                [16]byte
		born, nextPacket, nextMessage uint64
		created, used                 time.Time
		shape                         *servoStream
	}
	marinerPacketConn struct {
		inner               net.PacketConn
		server              bool
		tx                  *marinerCipher
		profile             marinerProfile
		rx                  *marinerReceiver
		txCache             marinerGraphCache
		mu, readMu, writeMu sync.Mutex
		senders             map[netip.AddrPort]*marinerSender
		routes              map[netip.AddrPort][16]byte
		remote              netip.AddrPort
		closed              bool
		once                sync.Once
		closeErr            error
		random              io.Reader
		stats               MarinerStats
		readBuf             [marinerWireMax + 1]byte
		rawBuf, writeBuf    [marinerWireMax]byte
	}
)

func WrapPacketConnMariner(conn net.PacketConn, opts MarinerOptions) (net.PacketConn, error) {
	if conn == nil {
		return nil, errors.New("mariner: nil packet connection")
	}
	dir := byte(0)
	if opts.Server {
		dir = 1
	}
	p, err := compileMarinerProfile(opts.Password, dir)
	if err != nil {
		return nil, err
	}
	tx, err := newMarinerCipher(opts.Password, dir)
	if err != nil {
		return nil, err
	}
	rx, err := newMarinerReceiver(opts.Password, 1-dir)
	if err != nil {
		return nil, err
	}
	c := &marinerPacketConn{inner: conn, server: opts.Server, tx: tx, profile: p, rx: rx, txCache: newMarinerGraphCache(), senders: make(map[netip.AddrPort]*marinerSender), routes: make(map[netip.AddrPort][16]byte), random: rand.Reader}
	rx.state.onComplete = func(p *servoPeer) {
		if _, exists := c.routes[p.addr]; !exists && len(c.routes) >= servoMaxSessions {
			for addr, session := range c.routes {
				peer := c.rx.state.peers[session]
				if peer == nil || !peer.routeReady || time.Since(peer.used) >= servoSessionTTL {
					delete(c.routes, addr)
				}
			}
		}
		if _, exists := c.routes[p.addr]; exists || len(c.routes) < servoMaxSessions {
			c.routes[p.addr] = p.session
		}
	}
	if udp, ok := conn.(udpLikePacketConn); ok {
		return &marinerPacketConnUDP{marinerPacketConn: c, udp: udp}, nil
	}
	return c, nil
}
func (*marinerPacketConn) QUICPacketSizeLimit() int { return 1200 }
func (c *marinerPacketConn) MarinerStats() MarinerStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Senders = len(c.senders)
	s.Sessions = len(c.rx.state.peers)
	s.Assemblies = c.rx.state.assemblyOrder.Len()
	s.ReassemblyBytes = c.rx.state.assemblyBytes
	s.Receive = c.rx.state.stats
	s.GraphEntries = c.txCache.order.Len() + c.rx.cache.order.Len()
	s.GraphBytes = s.GraphEntries * int(unsafe.Sizeof(marinerGraph{}))
	s.GraphHits = c.txCache.hits + c.rx.cache.hits
	s.GraphMisses = c.txCache.misses + c.rx.cache.misses
	s.GraphPromotions = c.txCache.promotions + c.rx.cache.promotions
	s.CompileDrops = c.rx.compileDrops
	s.RelationDrops = c.rx.relationDrops
	return s
}

func (c *marinerPacketConn) sender(addr netip.AddrPort, now time.Time) (*marinerSender, error) {
	if c.closed {
		return nil, net.ErrClosed
	}
	if !c.server {
		if c.remote.IsValid() && c.remote != addr {
			return nil, errors.New("mariner: port hopping / rebinding is unsupported")
		}
	} else {
		peer := c.rx.state.peers[c.routes[addr]]
		if peer == nil || !peer.routeReady || peer.addr != addr || now.Sub(peer.used) >= servoSessionTTL {
			return nil, errors.New("mariner: no completed authenticated route")
		}
	}
	// Bounded by the fixed sender cap; no per-message goroutines or timers.
	for ap, s := range c.senders {
		if now.Sub(s.used) >= time.Minute {
			delete(c.senders, ap)
		}
	}
	s := c.senders[addr]
	if s == nil || now.Sub(s.created) >= 10*time.Minute || s.nextMessage > math.MaxUint32 || s.nextPacket > math.MaxUint64-2 || c.server && s.route != c.routes[addr] {
		if s == nil && len(c.senders) >= servoMaxSessions {
			return nil, errServoResource
		}
		s = &marinerSender{born: uint64(now.Unix()), created: now, used: now, nextMessage: 1, route: c.routes[addr]}
		var seed [32]byte
		if _, err := io.ReadFull(c.random, s.session[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(c.random, seed[:]); err != nil {
			return nil, err
		}
		stream, err := newServoStream(seed[:])
		if err != nil {
			return nil, err
		}
		s.shape = stream
		c.senders[addr] = s
	}
	s.used = now
	if !c.server {
		c.remote = addr
	}
	return s, nil
}

func (c *marinerPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.WriteToWithQUICSendTime(p, addr, time.Time{})
}

func (c *marinerPacketConn) WriteToWithQUICSendTime(p []byte, addr net.Addr, sent time.Time) (int, error) {
	if len(p) < 1 || len(p) > 1200 {
		return 0, errors.New("mariner: datagram must contain 1..1200 bytes")
	}
	ap, _, ok := blinkAddress(addr)
	if !ok {
		return 0, errors.New("mariner: concrete UDP endpoint required")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	s, err := c.sender(ap, time.Now())
	if err != nil {
		c.mu.Unlock()
		return 0, err
	}
	var sizes, lengths [2]int
	count := 1
	sizes[0] = len(p)
	if len(p) > c.profile.capacity() {
		lo, hi := c.profile.splitRange(len(p))
		x, e := s.shape.below(hi - lo + 1)
		if e != nil {
			c.mu.Unlock()
			return 0, e
		}
		sizes[0], sizes[1] = lo+x, len(p)-lo-x
		count = 2
	}
	for i := range count {
		base := c.profile.wireBase(62 + sizes[i])
		delta, e := marinerWeighted(s.shape, c.profile.deltas[:min(3, 1232-base)+1])
		if e != nil {
			c.mu.Unlock()
			return 0, e
		}
		lengths[i] = base + delta
	}
	id := uint32(s.nextMessage)
	s.nextMessage++
	firstCounter := s.nextPacket
	s.nextPacket += uint64(count)
	c.stats.InnerAcceptedBytes += uint64(len(p))
	c.stats.InnerDatagrams++
	if count == 2 {
		c.stats.FragmentedMessages++
	}
	c.mu.Unlock()
	offset := 0
	for i := range count {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		g := c.txCache.find(lengths[i])
		if g == nil {
			g = &c.txCache.scratch
			err = c.profile.graph(lengths[i], g)
			if err == nil {
				c.txCache.promote(g)
			}
		}
		c.mu.Unlock()
		if err != nil {
			return 0, err
		}
		f := marinerFrame{session: s.session, counter: firstCounter + uint64(i), born: s.born, message: id, total: uint16(len(p)), offset: uint16(offset), data: p[offset : offset+sizes[i]]}
		raw, e := c.tx.seal(c.rawBuf[:], &f, &c.profile, lengths[i])
		if e != nil {
			return 0, e
		}
		wire, e := c.profile.encode(c.writeBuf[:], raw, g)
		if e != nil {
			return 0, e
		}
		n, e := c.inner.WriteTo(wire, net.UDPAddrFromAddrPort(ap))
		actual := max(0, min(n, len(wire)))
		if e == nil && n != len(wire) {
			e = io.ErrShortWrite
		}
		c.mu.Lock()
		c.stats.OuterSentBytes += uint64(actual)
		if e == nil {
			c.stats.OuterPackets++
			c.stats.RelationBytes += uint64(g.r)
			c.stats.PaddingBytes += uint64(g.k - 62 - sizes[i])
		} else {
			c.stats.WriteErrors++
			c.stats.PartialOuterBytes += uint64(actual)
		}
		c.mu.Unlock()
		if e != nil {
			return 0, e
		}
		offset += sizes[i]
	}
	c.mu.Lock()
	c.stats.InnerSentBytes += uint64(len(p))
	if !sent.IsZero() {
		delay := uint64(max(0, time.Since(sent)))
		c.stats.QUICSendSamples++
		c.stats.QUICDelayNanos += delay
		c.stats.QUICDelayMaxNanos = max(c.stats.QUICDelayMaxNanos, delay)
	}
	c.mu.Unlock()
	return len(p), nil
}

func (c *marinerPacketConn) QUICTransportMetrics(_ net.Addr, rtt, pto time.Duration, lost uint64, probe bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.QUICMetricSamples++
	c.stats.QUICLatestRTT, c.stats.QUICPTO = rtt, pto
	c.stats.QUICPacketsLostMax = max(c.stats.QUICPacketsLostMax, lost)
	if probe {
		c.stats.QUICProbeCalls++
	}
}

func (c *marinerPacketConn) ReadFrom(out []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		if c.rx.state.queue.Len() > 0 {
			n, ap, err := c.rx.state.pop(out)
			c.mu.Unlock()
			return n, net.UDPAddrFromAddrPort(ap), err
		}
		c.mu.Unlock()
		n, addr, err := c.inner.ReadFrom(c.readBuf[:])
		if err != nil {
			if errors.Is(err, syscall.EMSGSIZE) {
				continue
			}
			return 0, addr, err
		}
		ap, _, ok := blinkAddress(addr)
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		if ok && n >= 0 && n <= marinerWireMax && (c.server || ap == c.remote) {
			_ = c.rx.receive(c.readBuf[:n], ap, time.Now())
		} else {
			c.rx.state.stats.MalformedDrops++
		}
		c.mu.Unlock()
	}
}

func (c *marinerPacketConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.closeErr = c.inner.Close()
		c.readMu.Lock()
		defer c.readMu.Unlock()
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		c.mu.Lock()
		defer c.mu.Unlock()
		clear(c.senders)
		clear(c.routes)
		stats := c.rx.state.stats
		c.rx.state = newFramedReceiveState()
		c.rx.state.stats = stats
		for _, cache := range []*marinerGraphCache{&c.rx.cache, &c.txCache} {
			clear(cache.entries)
			cache.order.Init()
		}
	})
	return c.closeErr
}
func (c *marinerPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *marinerPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *marinerPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
func (c *marinerPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }

type marinerPacketConnUDP struct {
	*marinerPacketConn
	udp udpLikePacketConn
}

func (c *marinerPacketConnUDP) SyscallConn() (syscall.RawConn, error) { return c.udp.SyscallConn() }
func (c *marinerPacketConnUDP) SetReadBuffer(n int) error             { return c.udp.SetReadBuffer(n) }
func (c *marinerPacketConnUDP) SetWriteBuffer(n int) error            { return c.udp.SetWriteBuffer(n) }
