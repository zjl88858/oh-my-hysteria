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
	"sync"
	"syscall"
	"time"
)

// BlinkOptions describe local sending policy and local receive resource limits.
// Password and Fragmentation must be compatible on both ends. Other limits
// need not match. A nil padding/junk setting selects the bounded default;
// an explicit zero disables that optional traffic.
type BlinkOptions struct {
	Password               []byte
	Server                 bool
	MaxPacketSize          int
	PaddingMax             *int
	JunkPackets            *int
	Fragmentation          bool
	MaxSessions            int
	MaxReassemblyBytes     int
	VerifyPacketsPerSecond int
}

type BlinkStats struct {
	EvictedAssemblies                                                                   uint64
	Reassembled                                                                         uint64
	SentPackets, SentWireBytes, SentInnerBytes, PaddingBytes                            uint64
	JunkPackets, JunkBytes, FragmentedMessages                                          uint64
	ReceivedPackets, ReceivedWireBytes, DeliveredBytes                                  uint64
	AuthDrops, RateDrops, MalformedDrops, ReplayDrops, ResourceDrops, ExpiredAssemblies uint64
	Sessions, Assemblies, ReassemblyBytes                                               int
}

type blinkSender struct {
	session               [16]byte
	next                  uint64
	paddingLimit, credits int
}

type blinkPacketConn struct {
	inner                       net.PacketConn
	opts                        BlinkOptions
	tx, rx                      cipher.AEAD
	readMu, writeMu, mu         sync.Mutex
	readBuf, plainBuf, writeBuf []byte
	closed                      bool
	closeOnce                   sync.Once
	closeErr                    error
	junkDone                    bool
	remote                      netip.AddrPort
	peers                       map[blinkPeerKey]*blinkPeer
	sources                     map[netip.Prefix]int
	routes                      map[netip.AddrPort]*blinkPeer
	senders                     map[netip.AddrPort]*blinkSender
	peerOrder, assemblyOrder    *list.List
	assemblies                  map[blinkAssemblyKey]*blinkAssembly
	assemblyBytes               int
	verify, admit               blinkBucket
	verifyShards                [256]blinkBucket
	hashSeed                    maphash.Seed
	stats                       BlinkStats
}

func normalizeBlink(o BlinkOptions) (BlinkOptions, error) {
	if o.MaxPacketSize == 0 {
		o.MaxPacketSize = 1400
	}
	if o.MaxSessions == 0 {
		o.MaxSessions = 1024
	}
	if o.MaxReassemblyBytes == 0 {
		o.MaxReassemblyBytes = 1024 * 1024
	}
	if o.VerifyPacketsPerSecond == 0 {
		o.VerifyPacketsPerSecond = 32768
	}
	pad, junk := 32, 2
	if o.PaddingMax != nil {
		pad = *o.PaddingMax
	}
	if o.JunkPackets != nil {
		junk = *o.JunkPackets
	}
	if o.MaxPacketSize < 512 || o.MaxPacketSize > blinkWireMax || (!o.Fragmentation && o.MaxPacketSize < blinkInnerMax+blinkOverhead) {
		return o, errors.New("blink: maxPacketSize must be 512..1400 and at least 1272 without fragmentation")
	}
	if pad < 0 || pad > 128 || junk < 0 || junk > 4 || (o.Server && o.JunkPackets != nil && junk != 0) {
		return o, errors.New("blink: paddingMax must be 0..128; junkPackets 0..4 on clients, 0 on servers")
	}
	if o.Server {
		junk = 0
	}
	if o.MaxSessions < 1 || o.MaxSessions > 4096 || o.MaxReassemblyBytes < blinkInnerMax || o.MaxReassemblyBytes > 8*1024*1024 || o.VerifyPacketsPerSecond < 64 || o.VerifyPacketsPerSecond > 262144 {
		return o, errors.New("blink: resource limits outside safe bounds")
	}
	o.PaddingMax = &pad
	o.JunkPackets = &junk
	return o, nil
}

// WrapPacketConnBlink implements an independent, authenticated L4 envelope.
// It does not implement WireGuard/AWG messages, reliability, retransmission,
// TLS impersonation, traffic secrecy without QUIC, or a DPI-resistance proof.
func WrapPacketConnBlink(conn net.PacketConn, opts BlinkOptions) (net.PacketConn, error) {
	if conn == nil {
		return nil, errors.New("blink: nil packet connection")
	}
	opts, err := normalizeBlink(opts)
	if err != nil {
		return nil, err
	}
	tx, rx, err := blinkCiphers(opts.Password, opts.Server)
	if err != nil {
		return nil, err
	}
	opts.Password = nil
	c := &blinkPacketConn{
		inner: conn, opts: opts, tx: tx, rx: rx,
		readBuf: make([]byte, blinkReceiveMax+1), plainBuf: make([]byte, 0, blinkReceiveMax), writeBuf: make([]byte, blinkReceiveMax),
		peers: make(map[blinkPeerKey]*blinkPeer), sources: make(map[netip.Prefix]int), routes: make(map[netip.AddrPort]*blinkPeer), senders: make(map[netip.AddrPort]*blinkSender),
		peerOrder: list.New(), assemblyOrder: list.New(), assemblies: make(map[blinkAssemblyKey]*blinkAssembly), hashSeed: maphash.MakeSeed(),
	}
	if udp, ok := conn.(udpLikePacketConn); ok {
		return &blinkPacketConnUDP{blinkPacketConn: c, udp: udp}, nil
	}
	return c, nil
}

// The core recognizes this opt-in contract. A framed path is NOT a raw UDP
// path: QUIC PMTU probes cannot be used to increase the inner datagram size.
func (*blinkPacketConn) QUICPacketSizeLimit() int { return blinkInnerMax }

func (c *blinkPacketConn) BlinkStats() BlinkStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Sessions = len(c.peers)
	s.Assemblies = len(c.assemblies)
	s.ReassemblyBytes = c.assemblyBytes
	return s
}

func (c *blinkPacketConn) ReadFrom(out []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		n, addr, err := c.inner.ReadFrom(c.readBuf)
		if err != nil {
			// Windows UDP reports WSAEMSGSIZE for an oversized datagram.
			// It is unauthenticated input, not a reason to kill the listener.
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
		if !ok || n < blinkOverhead+1 || n > blinkReceiveMax || (!c.opts.Server && ap != c.remote) {
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
		plain, err := c.rx.Open(c.plainBuf[:0], c.readBuf[:blinkNonce], c.readBuf[blinkNonce:n], nil)
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
		h, payload, err := decodeBlinkHeader(plain)
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

func (c *blinkPacketConn) sender(ap netip.AddrPort, entropy []byte) (*blinkSender, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if !c.opts.Server {
		if c.remote.IsValid() && c.remote != ap {
			return nil, errors.New("blink: client socket is bound to one UDP endpoint; port hopping is not supported")
		}
		c.remote = ap
	} else if c.routes[ap] == nil {
		return nil, errors.New("blink: no authenticated receive route")
	}
	s := c.senders[ap]
	if s == nil {
		s = &blinkSender{}
		copy(s.session[:], entropy[:16])
		if s.session == ([16]byte{}) {
			return nil, errors.New("blink: invalid random session")
		}
		limit := *c.opts.PaddingMax
		s.paddingLimit = limit/2 + int(entropy[16])%(limit-limit/2+1)
		c.senders[ap] = s
	}
	return s, nil
}

func (c *blinkPacketConn) writeWire(packet []byte, addr net.Addr, junk bool) error {
	n, err := c.inner.WriteTo(packet, addr)
	c.mu.Lock()
	c.stats.SentPackets++
	c.stats.SentWireBytes += uint64(max(0, min(n, len(packet))))
	if junk {
		c.stats.JunkPackets++
		c.stats.JunkBytes += uint64(max(0, min(n, len(packet))))
	}
	c.mu.Unlock()
	if err == nil && n != len(packet) {
		return io.ErrShortWrite
	}
	return err
}

func (c *blinkPacketConn) WriteTo(in []byte, addr net.Addr) (int, error) {
	if len(in) < 1 || len(in) > blinkInnerMax {
		return 0, ErrBlinkPacketSize
	}
	ap, _, ok := blinkAddress(addr)
	if !ok {
		return 0, errors.New("blink: a concrete UDP address is required")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return 0, err
	}
	s, err := c.sender(ap, entropy[:])
	if err != nil {
		return 0, err
	}
	if s.next == math.MaxUint64 {
		return 0, errors.New("blink: message counter exhausted; reopen the socket")
	}
	id := s.next
	s.next++ // Consume even on partial writes; never reuse an ID.
	if !c.junkDone {
		c.junkDone = true // Includes failed attempts: QUIC retries cannot multiply it.
		for i := 0; i < *c.opts.JunkPackets; i++ {
			size := 64 + int(entropy[17+i])%129 // 64..192, <=768 bytes / client socket.
			if _, err := rand.Read(c.writeBuf[:size]); err != nil {
				return 0, err
			}
			if err := c.writeWire(c.writeBuf[:size], addr, true); err != nil {
				return 0, err
			}
		}
	}
	capacity := c.opts.MaxPacketSize - blinkOverhead
	count := (len(in) + capacity - 1) / capacity
	if c.opts.Fragmentation && len(in) >= 512 {
		s.credits = min(8, s.credits+1)
		if count == 1 && s.credits >= 4 && entropy[21]%4 == 0 {
			count = 2
			s.credits -= 4
		}
	}
	if count > blinkFragments || (count > 1 && !c.opts.Fragmentation) {
		return 0, ErrBlinkPacketSize
	}
	span := (len(in) + count - 1) / count
	// Optional padding <=10% of this original datagram, <=configured cap,
	// and <=available outer MTU space. Fixed framing is counted separately.
	padBudget := min(len(in)/10, s.paddingLimit)
	padding := 0
	for i := 0; i < count; i++ {
		start, end := i*span, min(len(in), (i+1)*span)
		size := end - start
		maxPad := min(padBudget, c.opts.MaxPacketSize-blinkOverhead-size)
		pad := 0
		if maxPad > 0 {
			pad = int(entropy[22+i]) % (maxPad + 1)
		}
		padBudget -= pad
		padding += pad
		buf := c.writeBuf
		if _, err := rand.Read(buf[:blinkNonce]); err != nil {
			return 0, err
		}
		h := blinkHeaderFields{session: s.session, message: id, total: uint16(len(in)), size: uint16(size), index: uint8(i), count: uint8(count)}
		h.encode(buf[blinkNonce : blinkNonce+blinkHeader])
		copy(buf[blinkNonce+blinkHeader:], in[start:end])
		plainLen := blinkHeader + size + pad
		if _, err := rand.Read(buf[blinkNonce+blinkHeader+size : blinkNonce+plainLen]); err != nil {
			return 0, err
		}
		packet := c.tx.Seal(buf[:blinkNonce], buf[:blinkNonce], buf[blinkNonce:blinkNonce+plainLen], nil)
		if err := c.writeWire(packet, addr, false); err != nil {
			return 0, err
		}
	}
	c.mu.Lock()
	c.stats.SentInnerBytes += uint64(len(in))
	c.stats.PaddingBytes += uint64(padding)
	if count > 1 {
		c.stats.FragmentedMessages++
	}
	c.mu.Unlock()
	return len(in), nil
}

func (c *blinkPacketConn) Close() error {
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
func (c *blinkPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *blinkPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *blinkPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *blinkPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// Deliberately no ReadMsgUDP/WriteMsgUDP: GSO/batch I/O must not bypass framing.
type blinkPacketConnUDP struct {
	*blinkPacketConn
	udp udpLikePacketConn
}

func (c *blinkPacketConnUDP) SyscallConn() (syscall.RawConn, error) { return c.udp.SyscallConn() }
func (c *blinkPacketConnUDP) SetReadBuffer(n int) error             { return c.udp.SetReadBuffer(n) }
func (c *blinkPacketConnUDP) SetWriteBuffer(n int) error            { return c.udp.SetWriteBuffer(n) }

var _ net.PacketConn = (*blinkPacketConn)(nil)
