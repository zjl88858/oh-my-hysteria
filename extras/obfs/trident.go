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
	"math"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// Password alone compiles the dialect; Server only selects AEAD directions.
type TridentOptions struct {
	Password []byte
	Server   bool
}

type TridentStats struct {
	SentPackets, SentWireBytes, SentInnerBytes, PackingBytes, FragmentedMessages                        uint64
	ReceivedPackets, ReceivedWireBytes, DeliveredBytes                                                  uint64
	AuthDrops, RateDrops, MalformedDrops, ReplayDrops, ResourceDrops, FreshnessDrops, ExpiredAssemblies uint64
	Reassembled, EvictedAssemblies                                                                      uint64
	Sessions, Assemblies, ReassemblyBytes                                                               int
}

type tridentSender struct {
	session       [16]byte
	next, born    uint64
	created, used time.Time
	random        *mathrand.Rand
}

type tridentPacketConn struct {
	inner                        net.PacketConn
	opts                         TridentOptions
	isa                          tridentISA
	tx, rx                       cipher.AEAD
	readMu, writeMu, mu          sync.Mutex
	readBuf, decodeBuf, plainBuf []byte
	writeBuf, sealBuf            []byte
	closed                       bool
	closeOnce                    sync.Once
	closeErr                     error
	remote                       netip.AddrPort
	peers                        map[[16]byte]*tridentPeer
	sources                      map[netip.Prefix]int
	routes                       map[netip.AddrPort]*tridentPeer
	senders                      map[netip.AddrPort]*tridentSender
	peerOrder, assemblyOrder     *list.List
	assemblies                   map[tridentAssemblyKey]*tridentAssembly
	assemblyBytes                int
	verify, admit                blinkBucket
	verifyShards                 [256]blinkBucket
	hashSeed                     maphash.Seed
	stats                        TridentStats
}

// WrapPacketConnTrident carries authenticated fragments as inert bytecode.
// The decoder never executes programs. It does not impersonate a real VM.
func WrapPacketConnTrident(conn net.PacketConn, opts TridentOptions) (net.PacketConn, error) {
	if conn == nil {
		return nil, errors.New("trident: nil packet connection")
	}
	isa, err := compileTridentISA(opts.Password)
	if err != nil {
		return nil, err
	}
	tx, rx, err := tridentCiphers(opts.Password, opts.Server)
	if err != nil {
		return nil, err
	}
	opts.Password = nil
	c := &tridentPacketConn{
		inner: conn, opts: opts, isa: isa, tx: tx, rx: rx,
		readBuf: make([]byte, tridentWireMax+1), decodeBuf: make([]byte, tridentRawMax+12), plainBuf: make([]byte, 0, tridentRawMax),
		writeBuf: make([]byte, tridentWireMax), sealBuf: make([]byte, tridentRawMax),
		peers: make(map[[16]byte]*tridentPeer), sources: make(map[netip.Prefix]int), routes: make(map[netip.AddrPort]*tridentPeer), senders: make(map[netip.AddrPort]*tridentSender),
		peerOrder: list.New(), assemblyOrder: list.New(), assemblies: make(map[tridentAssemblyKey]*tridentAssembly), hashSeed: maphash.MakeSeed(),
	}
	if udp, ok := conn.(udpLikePacketConn); ok {
		return &tridentPacketConnUDP{tridentPacketConn: c, udp: udp}, nil
	}
	return c, nil
}

func (*tridentPacketConn) QUICPacketSizeLimit() int { return tridentInnerMax }

func (c *tridentPacketConn) TridentStats() TridentStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Sessions, s.Assemblies, s.ReassemblyBytes = len(c.peers), len(c.assemblies), c.assemblyBytes
	return s
}

func (c *tridentPacketConn) ReadFrom(out []byte) (int, net.Addr, error) {
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
		if !ok || n < 1 || n > tridentWireMax || (!c.opts.Server && ap != c.remote) {
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
		raw, err := c.isa.unpack(c.decodeBuf, c.readBuf[:n])
		var plain []byte
		malformed := err != nil
		if err == nil {
			var aad [2]byte
			binary.BigEndian.PutUint16(aad[:], uint16(len(raw)))
			plain, err = c.rx.Open(c.plainBuf[:0], raw[:tridentNonce], raw[tridentNonce:], aad[:])
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
		h, payload, err := decodeTridentHeader(plain)
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

// Called under writeMu. Only map membership is shared with receiver cleanup;
// the session ID/counter and fragment sampler belong exclusively to the writer.
func (c *tridentPacketConn) sender(ap netip.AddrPort, now time.Time) (*tridentSender, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if !c.opts.Server {
		if c.remote.IsValid() && c.remote != ap {
			return nil, errors.New("trident: client socket is bound to one UDP endpoint; port hopping is not supported")
		}
		c.remote = ap
	} else if c.routes[ap] == nil {
		return nil, errors.New("trident: no authenticated receive route")
	}
	s := c.senders[ap]
	if s == nil || now.Sub(s.used) >= time.Minute || now.Sub(s.created) >= 10*time.Minute {
		if s == nil && len(c.senders) >= tridentMaxSessions {
			return nil, errors.New("trident: sender capacity exhausted")
		}
		var seed [32]byte
		s = &tridentSender{created: now, used: now, born: uint64(now.Unix())}
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, err
		}
		if _, err := rand.Read(s.session[:]); err != nil {
			return nil, err
		}
		if s.session == ([16]byte{}) {
			return nil, errors.New("trident: invalid random session")
		}
		s.random = mathrand.New(mathrand.NewChaCha8(seed))
		c.senders[ap] = s
	}
	s.used = now
	return s, nil
}

func (c *tridentPacketConn) seal(h tridentHeaderFields, payload []byte) ([]byte, error) {
	length := tridentOverhead + len(payload)
	buf := c.sealBuf[:length]
	if _, err := rand.Read(buf[:tridentNonce]); err != nil {
		return nil, err
	}
	h.encode(buf[tridentNonce:])
	copy(buf[tridentNonce+tridentHeader:], payload)
	var aad [2]byte
	binary.BigEndian.PutUint16(aad[:], uint16(length))
	raw := c.tx.Seal(buf[:tridentNonce], buf[:tridentNonce], buf[tridentNonce:length-16], aad[:])
	return c.isa.pack(c.writeBuf, raw)
}

func (c *tridentPacketConn) WriteTo(in []byte, addr net.Addr) (int, error) {
	if len(in) < 1 || len(in) > tridentInnerMax {
		return 0, ErrTridentPacketSize
	}
	ap, _, ok := blinkAddress(addr)
	if !ok {
		return 0, errors.New("trident: a concrete UDP address is required")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	s, err := c.sender(ap, time.Now())
	if err != nil {
		return 0, err
	}
	if s.next == math.MaxUint64 {
		return 0, errors.New("trident: message counter exhausted; reopen the socket")
	}
	id := s.next
	s.next++ // Consume even on deadline, seal failure or partially sent datagrams.
	plan := planTrident(len(in), s.random)
	for i := range plan.count {
		part := plan.parts[i]
		h := tridentHeaderFields{session: s.session, message: id, born: s.born, total: uint16(len(in)), offset: uint16(part.offset), size: uint16(part.size), index: uint8(i), count: uint8(plan.count)}
		packet, err := c.seal(h, in[part.offset:part.offset+part.size])
		if err != nil {
			return 0, err
		}
		n, err := c.inner.WriteTo(packet, addr)
		c.mu.Lock()
		c.stats.SentPackets++
		c.stats.SentWireBytes += uint64(max(0, min(n, len(packet))))
		if err == nil && n == len(packet) {
			// Includes length prefix, instruction/alignment and canonical tail.
			c.stats.PackingBytes += uint64(len(packet) - tridentOverhead - part.size)
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

func (c *tridentPacketConn) Close() error {
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

func (c *tridentPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *tridentPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *tridentPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
func (c *tridentPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }

// Never expose ReadMsgUDP/WriteMsgUDP: batching and GSO may not bypass bytecode.
type tridentPacketConnUDP struct {
	*tridentPacketConn
	udp udpLikePacketConn
}

func (c *tridentPacketConnUDP) SyscallConn() (syscall.RawConn, error) { return c.udp.SyscallConn() }
func (c *tridentPacketConnUDP) SetReadBuffer(n int) error             { return c.udp.SetReadBuffer(n) }
func (c *tridentPacketConnUDP) SetWriteBuffer(n int) error            { return c.udp.SetWriteBuffer(n) }

var _ net.PacketConn = (*tridentPacketConn)(nil)
