// SPDX-License-Identifier: MIT-0

package obfs

import (
	"container/list"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"hash/maphash"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
)

// Password is the sole morphology setting. Server selects the local role,
// not a different genome. The compiler and safety limits are versioned.
type PrestoOptions struct {
	Password []byte
	Server   bool
}

type PrestoStats struct {
	SentPackets, SentWireBytes, SentInnerBytes, PaddingBytes                                            uint64
	PreludePackets, PreludeBytes, FragmentedMessages, BurstPauses                                       uint64
	ReceivedPackets, ReceivedWireBytes, DeliveredBytes, ReceivedCoverPackets                            uint64
	AuthDrops, RateDrops, MalformedDrops, ReplayDrops, ResourceDrops, FreshnessDrops, ExpiredAssemblies uint64
	Reassembled, EvictedAssemblies                                                                      uint64
	Sessions, Assemblies, ReassemblyBytes                                                               int
}

type prestoSender struct {
	session       [16]byte
	next, born    uint64
	created, used time.Time
	due           time.Time
	grammar       prestoGrammar
	preludeDone   bool
}

type prestoPacketConn struct {
	inner                       net.PacketConn
	opts                        PrestoOptions
	genome                      prestoGenome
	tx, rx                      cipher.AEAD
	readMu, writeMu, mu         sync.Mutex
	readBuf, plainBuf, writeBuf []byte
	closed                      bool
	closeOnce                   sync.Once
	closeErr                    error
	writeDeadline               time.Time
	wake                        chan struct{}
	remote                      netip.AddrPort
	peers                       map[[16]byte]*prestoPeer
	sources                     map[netip.Prefix]int
	routes                      map[netip.AddrPort]*prestoPeer
	senders                     map[netip.AddrPort]*prestoSender
	peerOrder, assemblyOrder    *list.List
	assemblies                  map[prestoAssemblyKey]*prestoAssembly
	assemblyBytes               int
	verify, admit               blinkBucket
	verifyShards                [256]blinkBucket
	hashSeed                    maphash.Seed
	stats                       PrestoStats
}

func WrapPacketConnPresto(conn net.PacketConn, opts PrestoOptions) (net.PacketConn, error) {
	if conn == nil {
		return nil, errors.New("presto: nil packet connection")
	}
	genome, err := compilePrestoGenome(opts.Password, opts.Server)
	if err != nil {
		return nil, err
	}
	tx, rx, err := prestoCiphers(opts.Password, opts.Server)
	if err != nil {
		return nil, err
	}
	opts.Password = nil
	c := &prestoPacketConn{
		inner: conn, opts: opts, genome: genome, tx: tx, rx: rx, wake: make(chan struct{}),
		readBuf: make([]byte, prestoWireMax+1), plainBuf: make([]byte, 0, prestoWireMax), writeBuf: make([]byte, prestoWireMax),
		peers: make(map[[16]byte]*prestoPeer), sources: make(map[netip.Prefix]int), routes: make(map[netip.AddrPort]*prestoPeer), senders: make(map[netip.AddrPort]*prestoSender),
		peerOrder: list.New(), assemblyOrder: list.New(), assemblies: make(map[prestoAssemblyKey]*prestoAssembly), hashSeed: maphash.MakeSeed(),
	}
	if udp, ok := conn.(udpLikePacketConn); ok {
		return &prestoPacketConnUDP{prestoPacketConn: c, udp: udp}, nil
	}
	return c, nil
}

func (*prestoPacketConn) QUICPacketSizeLimit() int { return prestoInnerMax }

func (c *prestoPacketConn) PrestoStats() PrestoStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Sessions, s.Assemblies, s.ReassemblyBytes = len(c.peers), len(c.assemblies), c.assemblyBytes
	return s
}

func (c *prestoPacketConn) ReadFrom(out []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		n, addr, err := c.inner.ReadFrom(c.readBuf)
		if err != nil {
			if errors.Is(err, syscall.EMSGSIZE) {
				c.mu.Lock()
				c.stats.MalformedDrops++
				c.mu.Unlock()
				continue
			}
			return 0, addr, err
		}
		ap, source, ok := blinkAddress(addr)
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, addr, net.ErrClosed
		}
		c.stats.ReceivedPackets++
		c.stats.ReceivedWireBytes += uint64(max(0, n))
		if !ok || n < prestoOverhead || n > prestoWireMax || (!c.opts.Server && ap != c.remote) {
			c.stats.MalformedDrops++
			c.mu.Unlock()
			continue
		}
		if !c.verifyBudget(source, time.Now()) {
			c.stats.RateDrops++
			c.mu.Unlock()
			continue
		}
		c.mu.Unlock()
		plain, err := c.rx.Open(c.plainBuf[:0], c.readBuf[:prestoNonce], c.readBuf[prestoNonce:n], nil)
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, addr, net.ErrClosed
		}
		if err != nil {
			c.stats.AuthDrops++
			c.mu.Unlock()
			continue
		}
		h, payload, err := decodePrestoHeader(plain)
		if err != nil {
			c.stats.MalformedDrops++
			c.mu.Unlock()
			continue
		}
		data, ready := c.accept(ap, source, h, payload, time.Now())
		if !ready {
			c.mu.Unlock()
			continue
		}
		if len(out) < len(data) {
			c.mu.Unlock()
			return 0, addr, io.ErrShortBuffer
		}
		n = copy(out, data)
		c.stats.DeliveredBytes += uint64(n)
		c.mu.Unlock()
		return n, addr, nil
	}
}

// Called with writeMu held. Map lifetime is protected separately from the
// send-only grammar; receiver maintenance never mutates a sender in use.
func (c *prestoPacketConn) sender(ap netip.AddrPort, now time.Time) (*prestoSender, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if !c.opts.Server {
		if c.remote.IsValid() && c.remote != ap {
			return nil, errors.New("presto: client socket is bound to one UDP endpoint; port hopping is not supported")
		}
		c.remote = ap
	} else if c.routes[ap] == nil {
		return nil, errors.New("presto: no authenticated receive route")
	}
	s := c.senders[ap]
	if s == nil || now.Sub(s.used) >= time.Minute || now.Sub(s.created) >= 10*time.Minute {
		if s == nil && len(c.senders) >= prestoMaxSessions {
			return nil, errors.New("presto: sender capacity exhausted")
		}
		var seed [32]byte
		s = &prestoSender{created: now, used: now, born: uint64(now.Unix())}
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, err
		}
		if _, err := rand.Read(s.session[:]); err != nil {
			return nil, err
		}
		if s.session == ([16]byte{}) {
			return nil, errors.New("presto: invalid random session")
		}
		s.grammar = newPrestoGrammar(c.genome, seed)
		c.senders[ap] = s
	}
	s.used = now
	return s, nil
}

func (c *prestoPacketConn) waitUntil(due time.Time) error {
	for {
		c.mu.Lock()
		closed, deadline, wake := c.closed, c.writeDeadline, c.wake
		c.mu.Unlock()
		if closed {
			return net.ErrClosed
		}
		now := time.Now()
		if !deadline.IsZero() && !now.Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		if !now.Before(due) {
			return nil
		}
		end := due
		if !deadline.IsZero() && deadline.Before(end) {
			end = deadline
		}
		timer := time.NewTimer(end.Sub(now))
		select {
		case <-timer.C:
		case <-wake:
		}
		timer.Stop()
	}
}

func (c *prestoPacketConn) writeWire(packet []byte, addr net.Addr, prelude bool) error {
	n, err := c.inner.WriteTo(packet, addr)
	c.mu.Lock()
	c.stats.SentPackets++
	c.stats.SentWireBytes += uint64(max(0, min(n, len(packet))))
	if prelude {
		c.stats.PreludePackets++
		c.stats.PreludeBytes += uint64(max(0, min(n, len(packet))))
	}
	c.mu.Unlock()
	if err == nil && n != len(packet) {
		return io.ErrShortWrite
	}
	return err
}

func (c *prestoPacketConn) seal(h prestoHeaderFields, payload []byte, wire int) ([]byte, error) {
	buf := c.writeBuf[:wire]
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	h.encode(buf[prestoNonce:])
	copy(buf[prestoNonce+prestoHeader:], payload)
	return c.tx.Seal(buf[:prestoNonce], buf[:prestoNonce], buf[prestoNonce:wire-16], nil), nil
}

func (c *prestoPacketConn) WriteTo(in []byte, addr net.Addr) (int, error) {
	if len(in) < 1 || len(in) > prestoInnerMax {
		return 0, ErrPrestoPacketSize
	}
	ap, _, ok := blinkAddress(addr)
	if !ok {
		return 0, errors.New("presto: a concrete UDP address is required")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	s, err := c.sender(ap, time.Now())
	if err != nil {
		return 0, err
	}
	if s.next > math.MaxUint64-5 {
		return 0, errors.New("presto: message counter exhausted; reopen the socket")
	}
	if !s.preludeDone {
		s.preludeDone = true // Including failed attempts: retries cannot multiply it.
		for _, size := range s.grammar.prelude(c.opts.Server) {
			if err := c.waitUntil(s.due); err != nil {
				return 0, err
			}
			var wire []byte
			if c.opts.Server {
				h := prestoHeaderFields{session: s.session, born: s.born, message: s.next, count: 1, kind: prestoCover}
				s.next++
				wire, err = c.seal(h, nil, size)
			} else {
				wire = c.writeBuf[:size]
				_, err = rand.Read(wire)
			}
			if err != nil {
				return 0, err
			}
			if err := c.writeWire(wire, addr, true); err != nil {
				return 0, err
			}
			s.due = time.Now().Add(time.Duration(s.grammar.genome.preludeGapUS+s.grammar.random.IntN(201)) * time.Microsecond)
		}
	}
	id := s.next
	s.next++ // Even a partially transmitted message never reuses its ID.
	plan := s.grammar.plan(len(in))
	padding := 0
	for i := range plan.count {
		part := plan.parts[i]
		if err := c.waitUntil(s.due); err != nil {
			return 0, err
		}
		h := prestoHeaderFields{session: s.session, message: id, born: s.born, total: uint16(len(in)), offset: uint16(part.offset), size: uint16(part.size), index: uint8(i), count: uint8(plan.count)}
		wire, err := c.seal(h, in[part.offset:part.offset+part.size], part.wire)
		if err != nil {
			return 0, err
		}
		if err := c.writeWire(wire, addr, false); err != nil {
			return 0, err
		}
		padding += part.wire - prestoOverhead - part.size
		gap := s.grammar.gap(part.mode)
		s.due = time.Now().Add(gap)
		if gap > 0 {
			c.mu.Lock()
			c.stats.BurstPauses++
			c.mu.Unlock()
		}
	}
	c.mu.Lock()
	c.stats.SentInnerBytes += uint64(len(in))
	c.stats.PaddingBytes += uint64(padding)
	if plan.count > 1 {
		c.stats.FragmentedMessages++
	}
	c.mu.Unlock()
	return len(in), nil
}

func (c *prestoPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		close(c.wake)
		c.mu.Unlock()
		c.closeErr = c.inner.Close()
		c.mu.Lock()
		clear(c.peers)
		clear(c.sources)
		clear(c.routes)
		clear(c.senders)
		clear(c.assemblies)
		c.peerOrder.Init()
		c.assemblyOrder.Init()
		c.assemblyBytes = 0
		c.mu.Unlock()
	})
	return c.closeErr
}

func (c *prestoPacketConn) LocalAddr() net.Addr               { return c.inner.LocalAddr() }
func (c *prestoPacketConn) SetReadDeadline(t time.Time) error { return c.inner.SetReadDeadline(t) }
func (c *prestoPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if err := c.inner.SetWriteDeadline(t); err != nil {
		return err
	}
	c.writeDeadline = t
	close(c.wake)
	c.wake = make(chan struct{})
	return nil
}

func (c *prestoPacketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// Expose socket controls but never ReadMsgUDP / WriteMsgUDP / GSO bypasses.
type prestoPacketConnUDP struct {
	*prestoPacketConn
	udp udpLikePacketConn
}

func (c *prestoPacketConnUDP) SyscallConn() (syscall.RawConn, error) { return c.udp.SyscallConn() }
func (c *prestoPacketConnUDP) SetReadBuffer(n int) error             { return c.udp.SetReadBuffer(n) }
func (c *prestoPacketConnUDP) SetWriteBuffer(n int) error            { return c.udp.SetWriteBuffer(n) }

var _ net.PacketConn = (*prestoPacketConn)(nil)
