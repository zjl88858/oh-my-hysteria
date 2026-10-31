// SPDX-License-Identifier: MIT-0

package obfs

import (
	"container/list"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash/maphash"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

type CarakanOptions struct {
	Password []byte
	// Nil selects 4.00 bits/byte. Explicit zero is invalid.
	TargetEntropy *float64
	Server        bool
}

type CarakanStats struct {
	SentPackets, SentWireBytes, SentInnerBytes, FragmentedMessages                                      uint64
	ShapingBytes                                                                                        int64
	ReceivedPackets, ReceivedWireBytes, DeliveredBytes                                                  uint64
	AuthDrops, RateDrops, MalformedDrops, ReplayDrops, ResourceDrops, FreshnessDrops, ExpiredAssemblies uint64
	Reassembled, EvictedAssemblies                                                                      uint64
	SentRepairPackets, SentRepairBytes, ReceivedRepairPackets, RedundantRepairPackets                   uint64
	FECRecoveredMessages, FECRecoveredShards, FECRecoveryFailures                                       uint64
	Sessions, Assemblies, ReassemblyBytes                                                               int
	TargetEntropy, SpectrumEntropy                                                                      float64
	MaxFragmentPayload                                                                                  int
	FrameOverhead                                                                                       int
	WireVersion                                                                                         int
	// Frequencies sum to 16384. They are public traffic-shape metadata, not keys.
	Spectrum [256]uint16
}

type carakanSender struct {
	session       [16]byte
	next, born    uint64
	created, used time.Time
	random        *mathrand.Rand
}

type carakanPacketConn struct {
	inner                                           net.PacketConn
	server                                          bool
	table                                           *carakanTANS
	tx, rx                                          cipher.AEAD
	readMu, writeMu, mu                             sync.Mutex
	readBuf, decodeBuf, plainBuf, writeBuf, sealBuf []byte
	closed                                          bool
	closeOnce                                       sync.Once
	closeErr                                        error
	remote                                          netip.AddrPort
	peers                                           map[[16]byte]*carakanPeer
	sources                                         map[netip.Prefix]int
	routes                                          map[netip.AddrPort]*carakanPeer
	senders                                         map[netip.AddrPort]*carakanSender
	peerOrder, assemblyOrder                        *list.List
	assemblies                                      map[carakanAssemblyKey]*carakanAssembly
	assemblyBytes                                   int
	verify, admit                                   blinkBucket
	verifyShards                                    [256]blinkBucket
	hashSeed                                        maphash.Seed
	stats                                           CarakanStats
	repairBuf                                       [carakanMaxRepair][carakanRawMax]byte
}

// WrapPacketConnCarakan applies authenticated target-spectrum homophonic
// shaping using a reversed tANS coder. This is NOT encryption or compression.
func WrapPacketConnCarakan(conn net.PacketConn, opts CarakanOptions) (net.PacketConn, error) {
	if conn == nil {
		return nil, errors.New("carakan: nil packet connection")
	}
	t, err := compileCarakanTANS(opts.Password, opts.TargetEntropy)
	if err != nil {
		return nil, err
	}
	tx, rx, err := carakanCiphers(opts.Password, t.code, opts.Server)
	if err != nil {
		return nil, err
	}
	c := &carakanPacketConn{
		inner: conn, server: opts.Server, table: t, tx: tx, rx: rx,
		readBuf: make([]byte, carakanWireMax+1), decodeBuf: make([]byte, carakanRawMax+2), plainBuf: make([]byte, 0, carakanRawMax),
		writeBuf: make([]byte, carakanWireMax), sealBuf: make([]byte, carakanRawMax),
		peers: make(map[[16]byte]*carakanPeer), sources: make(map[netip.Prefix]int), routes: make(map[netip.AddrPort]*carakanPeer), senders: make(map[netip.AddrPort]*carakanSender),
		peerOrder: list.New(), assemblyOrder: list.New(), assemblies: make(map[carakanAssemblyKey]*carakanAssembly), hashSeed: maphash.MakeSeed(),
	}
	if udp, ok := conn.(udpLikePacketConn); ok {
		return &carakanPacketConnUDP{carakanPacketConn: c, udp: udp}, nil
	}
	return c, nil
}

func (*carakanPacketConn) QUICPacketSizeLimit() int { return carakanInnerMax }

func (c *carakanPacketConn) CarakanStats() CarakanStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Sessions, s.Assemblies, s.ReassemblyBytes = len(c.peers), len(c.assemblies), c.assemblyBytes
	s.TargetEntropy, s.SpectrumEntropy, s.MaxFragmentPayload = c.table.target, c.table.entropy, c.table.partMax
	s.Spectrum = c.table.freq
	s.FrameOverhead = carakanOverhead
	s.WireVersion = 3
	return s
}

func (c *carakanPacketConn) ReadFrom(out []byte) (int, net.Addr, error) {
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
		if !ok || n < 1 || n > carakanWireMax || (!c.server && ap != c.remote) {
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
		raw, err := c.table.unpack(c.decodeBuf, c.readBuf[:n])
		var plain []byte
		malformed := err != nil
		if err == nil {
			var aad [2]byte
			binary.BigEndian.PutUint16(aad[:], uint16(len(raw)))
			plain, err = c.rx.Open(c.plainBuf[:0], raw[:carakanNonce], raw[carakanNonce:], aad[:])
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, addr, net.ErrClosed
		}
		if err != nil {
			if malformed {
				c.stats.MalformedDrops++
			} else {
				c.stats.AuthDrops++
			}
			c.mu.Unlock()
			continue
		}
		h, payload, err := c.table.decodeHeader(plain, raw[:carakanNonce])
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

// Called under writeMu; only map membership is shared with receive cleanup.
func (c *carakanPacketConn) sender(ap netip.AddrPort, now time.Time) (*carakanSender, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if !c.server {
		if c.remote.IsValid() && c.remote != ap {
			return nil, errors.New("carakan: client socket is bound to one UDP endpoint; port hopping is not supported")
		}
		c.remote = ap
	} else if c.routes[ap] == nil {
		return nil, errors.New("carakan: no authenticated receive route")
	}
	s := c.senders[ap]
	if s == nil || now.Sub(s.used) >= time.Minute || now.Sub(s.created) >= 10*time.Minute {
		if s == nil && len(c.senders) >= carakanMaxSessions {
			return nil, errors.New("carakan: sender capacity exhausted")
		}
		var seed [32]byte
		s = &carakanSender{created: now, used: now, born: uint64(now.Unix())}
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, err
		}
		if _, err := rand.Read(s.session[:]); err != nil {
			return nil, err
		}
		if s.session == ([16]byte{}) {
			return nil, errors.New("carakan: invalid random session")
		}
		s.random = mathrand.New(mathrand.NewChaCha8(seed))
		c.senders[ap] = s
	}
	s.used = now
	return s, nil
}

func (c *carakanPacketConn) seal(h carakanHeaderFields, payload []byte) ([]byte, error) {
	length := carakanOverhead + len(payload)
	if length > c.table.rawMax || h.message >= carakanMessageLimit || h.index >= carakanMaxParts || h.count < 1 || h.count > carakanMaxParts || h.total > 2047 || int(h.size) != len(payload) {
		return nil, errCarakanFrame
	}
	buf := c.sealBuf[:length]
	// A random 128-bit session prefix and injective 59+5-bit counter encoding
	// retain the full XChaCha nonce size without duplicating these header fields.
	copy(buf[:16], h.session[:])
	binary.BigEndian.PutUint64(buf[16:24], h.message<<5|uint64(h.index))
	h.encode(buf[carakanNonce:])
	copy(buf[carakanNonce+carakanHeader:], payload)
	var aad [2]byte
	binary.BigEndian.PutUint16(aad[:], uint16(length))
	raw := c.tx.Seal(buf[:carakanNonce], buf[:carakanNonce], buf[carakanNonce:length-16], aad[:])
	return c.table.pack(c.writeBuf, raw)
}

func (c *carakanPacketConn) WriteTo(in []byte, addr net.Addr) (int, error) {
	if len(in) < 1 || len(in) > carakanInnerMax {
		return 0, ErrCarakanPacketSize
	}
	ap, _, ok := blinkAddress(addr)
	if !ok {
		return 0, errors.New("carakan: a concrete UDP address is required")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	s, err := c.sender(ap, time.Now())
	if err != nil {
		return 0, err
	}
	if s.next >= carakanMessageLimit {
		return 0, errors.New("carakan: message counter exhausted; reopen the socket")
	}
	id := s.next
	s.next++ // Consume even on partial sends, deadlines or errors.
	plan := c.table.plan(len(in), s.random)
	repairs := carakanRepairCount(plan.count)
	for row := range repairs {
		carakanRepair(c.repairBuf[row][:], in, plan.width, plan.count, row)
	}
	for i := range plan.count + repairs {
		var payload []byte
		if i < plan.count {
			part := plan.parts[i]
			payload = in[part.offset : part.offset+part.size]
		} else {
			payload = c.repairBuf[i-plan.count][:plan.width]
		}
		h := carakanHeaderFields{session: s.session, message: id, born: s.born, total: uint16(len(in)), width: uint16(plan.width), size: uint16(len(payload)), index: uint8(i), count: uint8(plan.count)}
		packet, err := c.seal(h, payload)
		if err != nil {
			return 0, err
		}
		n, err := c.inner.WriteTo(packet, addr)
		c.mu.Lock()
		c.stats.SentPackets++
		c.stats.SentWireBytes += uint64(max(0, min(n, len(packet))))
		if err == nil && n == len(packet) {
			c.stats.ShapingBytes += int64(len(packet) - carakanOverhead - len(payload))
			if i >= plan.count {
				c.stats.SentRepairPackets++
				c.stats.SentRepairBytes += uint64(len(payload))
			}
		}
		c.mu.Unlock()
		if err == nil && n != len(packet) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return 0, err
		}
	}
	c.mu.Lock()
	c.stats.SentInnerBytes += uint64(len(in))
	if plan.count > 1 {
		c.stats.FragmentedMessages++
	}
	c.mu.Unlock()
	return len(in), nil
}

func (c *carakanPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
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

func (c *carakanPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *carakanPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *carakanPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
func (c *carakanPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }

// Deliberately do not expose ReadMsgUDP/WriteMsgUDP: no GSO/batch bypass.
type carakanPacketConnUDP struct {
	*carakanPacketConn
	udp udpLikePacketConn
}

func (c *carakanPacketConnUDP) SyscallConn() (syscall.RawConn, error) { return c.udp.SyscallConn() }
func (c *carakanPacketConnUDP) SetReadBuffer(n int) error             { return c.udp.SetReadBuffer(n) }
func (c *carakanPacketConnUDP) SetWriteBuffer(n int) error            { return c.udp.SetWriteBuffer(n) }

var _ net.PacketConn = (*carakanPacketConn)(nil)
