// SPDX-License-Identifier: MIT-0

package obfs

import (
	"container/list"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
)

var (
	ErrTasmanPermit   = errors.New("tasman: an explicit QUIC wire reservation is required")
	ErrTasmanOverflow = errors.New("tasman: asynchronous error notification overflow")
	ErrTasmanExpired  = errors.New("tasman: accepted message exceeded 100ms queue age")
)

type (
	TasmanOptions struct {
		Password      []byte
		Server, Trace bool
	}
	TasmanError struct {
		Remote    netip.AddrPort
		MessageID uint32
		Operation string
		Err       error
	}
)

func (e TasmanError) Error() string {
	return fmt.Sprintf("tasman %s to %s message %d: %v", e.Operation, e.Remote, e.MessageID, e.Err)
}
func (e TasmanError) Unwrap() error { return e.Err }

type TasmanTraceEvent struct {
	Remote                         netip.AddrPort
	Session                        [16]byte
	Counter                        uint64
	Generation                     uint32
	Kind                           byte
	WireBytes                      int
	Accepted, QUICSent, Start, End time.Time
	Error                          string
}
type TasmanStats struct {
	InnerAcceptedBytes, InnerDatagrams, InnerSentBytes, CompletedSends, OuterSentBytes, OuterPackets                                                uint64
	SourcePackets, RepairPackets, CoverPackets, ShortPackets, PaddingBytes, ZeroTailBytes                                                           uint64
	TinyOverheadException, TinyExceptionBytes, AsyncErrors, AsyncErrorsLost, FailedMessages, FailedInnerBytes                                       uint64
	PartialOuterBytes, PermitBytes, SpentPermitBytes, TraceDrops, SessionRotations                                                                  uint64
	ReportedRecoveredSources                                                                                                                        uint64
	QueueWaitNanos, QueueWaitMaxNanos, QUICDelayNanos, QUICDelayMaxNanos, QUICSendSamples                                                           uint64
	QUICMetricSamples, QUICProbeCalls, QUICPacketsLostMax                                                                                           uint64
	QUICLatestRTT, QUICPTO                                                                                                                          time.Duration
	ReservedData, ReservedRepair, ReservedTiny, Credit                                                                                              int64
	PendingBytes, PendingDatagrams, QueuePeakBytes, QueuePeakItems, Senders, ReceiveSessions, Generations, SymbolBytes, Assemblies, ReassemblyBytes int
	Receive                                                                                                                                         TasmanReceiveStats
}
type tasmanMessage struct {
	id                        uint32
	data                      []byte
	accepted, sent, notBefore time.Time
	reserve                   int64
	tinyHold                  int64
	offset, completed         int
	elem                      *list.Element
}
type tasmanSender struct {
	addr                                       netip.AddrPort
	session, route                             [16]byte
	born, counter, nextMessage, nextGeneration uint64
	created, used                              time.Time
	stream                                     *servoStream
	queue                                      *list.List
	bytes                                      int
	elem                                       *list.Element
	inflight, reset                            bool
	d, w, reserved, repairReserved, exceptions int64
	tinyHeld                                   int64
	permit, spent                              int64
	feedback                                   uint64
	plan                                       *tasmanPlan
	tailUntil, nextTail                        time.Time
	tails                                      int
}
type tasmanPacketConn struct {
	inner                       net.PacketConn
	server                      bool
	profile                     tasmanProfile
	tx                          *tasmanCipher
	rx                          *tasmanReceiver
	mu                          sync.Mutex
	wake, done                  chan struct{}
	closed                      bool
	sticky                      error
	readDeadline, writeDeadline time.Time
	senders                     map[netip.AddrPort]*tasmanSender
	routes                      map[netip.AddrPort][16]byte
	order                       *list.List
	remote                      netip.AddrPort
	items, bytes                int
	errors                      chan TasmanError
	trace                       chan TasmanTraceEvent
	wg                          sync.WaitGroup
	once                        sync.Once
	closeErr                    error
	random                      io.Reader
	stats                       TasmanStats
}

func WrapPacketConnTasman(conn net.PacketConn, opts TasmanOptions) (net.PacketConn, error) {
	if conn == nil {
		return nil, errors.New("tasman: nil connection")
	}
	dir := byte(0)
	if opts.Server {
		dir = 1
	}
	p, err := compileTasmanProfile(opts.Password, dir)
	if err != nil {
		return nil, err
	}
	tx, err := newTasmanCipher(opts.Password, dir)
	if err != nil {
		return nil, err
	}
	rx, err := newTasmanReceiver(opts.Password, 1-dir)
	if err != nil {
		return nil, err
	}
	c := &tasmanPacketConn{inner: conn, server: opts.Server, profile: p, tx: tx, rx: rx, wake: make(chan struct{}), done: make(chan struct{}), senders: make(map[netip.AddrPort]*tasmanSender), routes: make(map[netip.AddrPort][16]byte), order: list.New(), errors: make(chan TasmanError, 256), random: rand.Reader}
	if opts.Trace {
		c.trace = make(chan TasmanTraceEvent, 1024)
	}
	rx.onComplete = func(p *tasmanPeer) {
		{
			if old, ok := c.routes[p.addr]; !ok || old != p.session {
				if s := c.senders[p.addr]; c.server && ok && s != nil {
					s.reset = true
				}
				c.routes[p.addr] = p.session
				c.signal()
			}
		}
	}
	rx.onPadding = func(addr netip.AddrPort, padding []byte) { c.acceptFeedback(net.UDPAddrFromAddrPort(addr), padding) }
	c.wg.Add(2)
	go c.readLoop()
	go c.sendLoop()
	go func() {
		c.wg.Wait()
		c.mu.Lock()
		for _, s := range c.senders {
			c.cancel(s, net.ErrClosed, "close")
		}
		clear(c.senders)
		clear(c.routes)
		c.order.Init()
		c.rx.peers = make(map[[16]byte]*tasmanPeer)
		clear(c.rx.sources)
		clear(c.rx.endpoints)
		clear(c.rx.tombs)
		clear(c.rx.queued)
		c.rx.peerOrder.Init()
		c.rx.genOrder.Init()
		c.rx.assemblyOrder.Init()
		c.rx.queue.Init()
		c.rx.symbolBytes, c.rx.assemblyBytes, c.rx.queueBytes = 0, 0, 0
		close(c.errors)
		if c.trace != nil {
			close(c.trace)
		}
		c.mu.Unlock()
		close(c.done)
	}()
	if udp, ok := conn.(udpLikePacketConn); ok {
		return &tasmanPacketConnUDP{tasmanPacketConn: c, udp: udp}, nil
	}
	return c, nil
}
func (*tasmanPacketConn) QUICPacketSizeLimit() int               { return 1200 }
func (*tasmanPacketConn) QUICWireReservation() bool              { return true }
func (c *tasmanPacketConn) TasmanErrors() <-chan TasmanError     { return c.errors }
func (c *tasmanPacketConn) TasmanTrace() <-chan TasmanTraceEvent { return c.trace }
func (c *tasmanPacketConn) signal()                              { close(c.wake); c.wake = make(chan struct{}) }
func (c *tasmanPacketConn) terminal() error {
	if c.closed {
		return net.ErrClosed
	}
	return c.sticky
}

func (c *tasmanPacketConn) fail(err error) {
	if c.sticky == nil {
		c.sticky = err
	}
	c.signal()
}
func (c *tasmanPacketConn) closeSocket() { c.once.Do(func() { c.closeErr = c.inner.Close() }) }
func (c *tasmanPacketConn) release(s *tasmanSender, m *tasmanMessage, err error, op string) {
	if m.elem == nil {
		return
	}
	s.queue.Remove(m.elem)
	m.elem = nil
	s.bytes -= len(m.data)
	c.items--
	c.bytes -= len(m.data)
	s.reserved -= m.reserve
	s.tinyHeld -= m.tinyHold
	m.tinyHold = 0
	m.reserve = 0
	if err != nil {
		c.stats.FailedMessages++
		c.stats.FailedInnerBytes += uint64(len(m.data))
		c.stats.AsyncErrors++
		select {
		case c.errors <- TasmanError{Remote: s.addr, MessageID: m.id, Operation: op, Err: err}:
		default:
			c.stats.AsyncErrorsLost++
			c.fail(ErrTasmanOverflow)
		}
	} else {
		c.stats.CompletedSends++
		c.stats.InnerSentBytes += uint64(len(m.data))
		if !m.sent.IsZero() {
			d := uint64(max(0, time.Since(m.sent)))
			c.stats.QUICSendSamples++
			c.stats.QUICDelayNanos += d
			c.stats.QUICDelayMaxNanos = max(c.stats.QUICDelayMaxNanos, d)
		}
	}
	c.signal()
}

func (c *tasmanPacketConn) cancel(s *tasmanSender, err error, op string) {
	for s.queue.Len() > 0 {
		c.release(s, s.queue.Front().Value.(*tasmanMessage), err, op)
	}
	if s.plan != nil {
		s.reserved -= s.plan.dataReserve
		s.tinyHeld -= s.plan.tinyHold
	}
	s.plan = nil
	s.repairReserved = 0
	s.tails = 0
}

func (c *tasmanPacketConn) newSender(addr netip.AddrPort, now time.Time) (*tasmanSender, error) {
	s := &tasmanSender{addr: addr, route: c.routes[addr], born: uint64(now.Unix()), nextMessage: 1, nextGeneration: 1, created: now, used: now, queue: list.New()}
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
	s.stream = stream
	s.elem = c.order.PushBack(s)
	c.senders[addr] = s
	c.stats.SessionRotations++
	return s, nil
}
func (c *tasmanPacketConn) WriteTo([]byte, net.Addr) (int, error) { return 0, ErrTasmanPermit }

// Each permit was already charged to the selected QUIC congestion controller.
// It cannot be created by the shaping deadline, tiny exception or cover timer.
func (c *tasmanPacketConn) WriteToWithQUICBudget(p []byte, addr net.Addr, sent, notBefore time.Time, allowance int) (int, error) {
	if len(p) < 1 || len(p) > 1200 {
		return 0, errors.New("tasman: datagram must contain 1..1200 bytes")
	}
	if allowance < 2*len(p) || allowance > 2*len(p)+62 {
		return 0, ErrTasmanPermit
	}
	ap, _, ok := blinkAddress(addr)
	if !ok {
		return 0, errors.New("tasman: concrete UDP endpoint required")
	}
	for {
		c.mu.Lock()
		if err := c.terminal(); err != nil {
			c.mu.Unlock()
			return 0, err
		}
		now := time.Now()
		if !c.writeDeadline.IsZero() && !now.Before(c.writeDeadline) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if !c.server && c.remote.IsValid() && c.remote != ap {
			c.mu.Unlock()
			return 0, errors.New("tasman: port hopping / rebinding is unsupported")
		}
		if c.server {
			route, exists := c.routes[ap]
			peer := c.rx.peers[route]
			if !exists || peer == nil || !peer.ready || now.Sub(peer.used) >= 2*time.Minute {
				c.mu.Unlock()
				return 0, errors.New("tasman: no completed authenticated route")
			}
		}
		s := c.senders[ap]
		rotate := s != nil && (s.reset || now.Sub(s.used) >= time.Minute || now.Sub(s.created) >= 10*time.Minute || s.nextMessage > math.MaxUint32 || s.nextGeneration > math.MaxUint32 || s.counter > math.MaxUint64-256)
		if rotate && s.queue.Len() == 0 && !s.inflight && s.plan == nil {
			delete(c.senders, ap)
			c.order.Remove(s.elem)
			s = nil
			rotate = false
		}
		if !rotate && c.items < 1024 && c.bytes+len(p) <= 2<<20 && (s == nil || s.queue.Len() < 64 && s.bytes+len(p) <= 64<<10) {
			if s == nil {
				if len(c.senders) >= 1024 {
					c.mu.Unlock()
					return 0, errTasmanResource
				}
				var err error
				s, err = c.newSender(ap, now)
				if err != nil {
					c.mu.Unlock()
					return 0, err
				}
			}
			cost := int64(len(p) + 62)
			if len(p) > 1170 {
				cost = int64(((len(p) + c.profile.wide[0] - 13) / (c.profile.wide[0] - 12)) * (c.profile.wide[0] + 60))
			}
			m := &tasmanMessage{id: uint32(s.nextMessage), data: append([]byte(nil), p...), accepted: now, sent: sent, notBefore: notBefore, reserve: cost}
			m.tinyHold = max(0, cost-2*int64(len(p)))
			m.elem = s.queue.PushBack(m)
			s.nextMessage++
			s.d += int64(len(p))
			s.reserved += cost
			s.tinyHeld += m.tinyHold
			s.permit += int64(allowance)
			s.used = now
			s.bytes += len(p)
			s.tails = 0
			c.items++
			c.bytes += len(p)
			c.stats.InnerAcceptedBytes += uint64(len(p))
			c.stats.InnerDatagrams++
			c.stats.PermitBytes += uint64(allowance)
			c.stats.QueuePeakItems = max(c.stats.QueuePeakItems, c.items)
			c.stats.QueuePeakBytes = max(c.stats.QueuePeakBytes, c.bytes)
			if !c.server {
				c.remote = ap
			}
			c.signal()
			c.mu.Unlock()
			return len(p), nil
		}
		c.signal()
		wake, deadline := c.wake, c.writeDeadline
		c.mu.Unlock()
		waitServo(wake, deadline)
	}
}

func (c *tasmanPacketConn) QUICTransportMetrics(_ net.Addr, rtt, pto time.Duration, lost uint64, probe bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.QUICMetricSamples++
	c.stats.QUICLatestRTT, c.stats.QUICPTO = rtt, pto
	c.stats.QUICPacketsLostMax = max(c.stats.QUICPacketsLostMax, lost)
	if probe {
		c.stats.QUICProbeCalls++
	}
}

func (c *tasmanPacketConn) readLoop() {
	defer c.wg.Done()
	var buf [1233]byte
	for {
		n, addr, err := c.inner.ReadFrom(buf[:])
		if err != nil {
			if errors.Is(err, syscall.EMSGSIZE) {
				continue
			}
			c.mu.Lock()
			if !c.closed {
				c.fail(err)
			}
			c.mu.Unlock()
			c.closeSocket()
			return
		}
		ap, _, ok := blinkAddress(addr)
		c.mu.Lock()
		if c.terminal() != nil {
			c.mu.Unlock()
			return
		}
		if ok && n >= 0 && n <= len(buf) && (c.server || c.remote == ap) {
			_ = c.rx.receive(buf[:n], ap, time.Now())
			if c.rx.queue.Len() > 0 {
				c.signal()
			}
		}
		c.mu.Unlock()
	}
}

func (c *tasmanPacketConn) ReadFrom(out []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		if err := c.terminal(); err != nil {
			c.mu.Unlock()
			return 0, nil, err
		}
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			c.mu.Unlock()
			return 0, nil, os.ErrDeadlineExceeded
		}
		if c.rx.queue.Len() > 0 {
			n, ap, err := c.rx.pop(out)
			c.mu.Unlock()
			return n, net.UDPAddrFromAddrPort(ap), err
		}
		wake, d := c.wake, c.readDeadline
		c.mu.Unlock()
		waitServo(wake, d)
	}
}
func (c *tasmanPacketConn) LocalAddr() net.Addr { return c.inner.LocalAddr() }
func (c *tasmanPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.terminal(); err != nil {
		return err
	}
	c.readDeadline = t
	c.signal()
	return nil
}

func (c *tasmanPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.terminal(); err != nil {
		return err
	}
	if err := c.inner.SetWriteDeadline(t); err != nil {
		return err
	}
	c.writeDeadline = t
	c.signal()
	return nil
}

func (c *tasmanPacketConn) SetDeadline(t time.Time) error {
	if err := c.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.SetReadDeadline(t)
}

func (c *tasmanPacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.signal()
	c.mu.Unlock()
	c.closeSocket()
	<-c.done
	return c.closeErr
}

type tasmanPacketConnUDP struct {
	*tasmanPacketConn
	udp udpLikePacketConn
}

func (c *tasmanPacketConnUDP) SyscallConn() (syscall.RawConn, error) { return c.udp.SyscallConn() }
func (c *tasmanPacketConnUDP) SetReadBuffer(n int) error             { return c.udp.SetReadBuffer(n) }
func (c *tasmanPacketConnUDP) SetWriteBuffer(n int) error            { return c.udp.SetWriteBuffer(n) }
