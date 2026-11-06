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

const (
	servoSendItems     = 1024
	servoSendBytes     = 2 << 20
	servoPeerSendItems = 64
	servoPeerSendBytes = 64 << 10
	servoErrorItems    = 256
	servoQueueTTL      = 100 * time.Millisecond
)

var (
	ErrServoPacketSize    = errors.New("servo: inner datagram must contain 1..1200 bytes")
	ErrServoErrorOverflow = errors.New("servo: asynchronous error notification overflow")
	ErrServoSessionReset  = errors.New("servo: authenticated remote session changed")
	ErrServoQueueExpired  = errors.New("servo: accepted datagram exceeded bounded queue age")
)

// Password is the only morphology setting. Trace is an instrumentation API,
// never a wire/config/profile parameter. Consumers must drain ServoErrors.
type ServoOptions struct {
	Password []byte
	Server   bool
	Trace    bool
}

type ServoError struct {
	Remote    netip.AddrPort
	Session   [16]byte
	MessageID uint32
	Operation string
	Err       error
}

func (e ServoError) Error() string {
	return fmt.Sprintf("servo %s to %s message %d: %v", e.Operation, e.Remote, e.MessageID, e.Err)
}

func (e ServoError) Unwrap() error { return e.Err }

type ServoTraceEvent struct {
	Remote                         netip.AddrPort
	Session                        [16]byte
	MessageID                      uint32
	Counter                        uint64
	Offset, Length, WireBytes      int
	Accepted, QUICSent, Start, End time.Time
	Error                          string
}

type ServoStats struct {
	InnerAcceptedBytes, InnerDatagrams, InnerSentBytes, CompletedSends   uint64
	OuterSentBytes, OuterPackets, Records, FragmentedMessages            uint64
	AsyncErrors, AsyncErrorsLost, CancelledMessages, FailedMessages      uint64
	FailedInnerBytes, PartialOuterBytes, TraceDrops, SessionRotations    uint64
	QueuePeakBytes, QueuePeakItems                                       int
	QueueWaitNanos, QueueWaitMaxNanos, QUICDelayNanos, QUICDelayMaxNanos uint64
	QUICSendSamples                                                      uint64
	QUICMetricSamples, QUICProbeCalls, QUICPacketsLostMax                uint64
	QUICLatestRTT, QUICPTO                                               time.Duration
	PendingBytes, PendingDatagrams, Senders, ReceiveSessions             int
	Assemblies, ReassemblyBytes, ReceiveQueueBytes, ReceiveQueueItems    int
	ReceivedPackets, ReceivedWireBytes, AuthDrops, MalformedDrops        uint64
	RateDrops, ReplayDrops, ResourceDrops, ExpiredAssemblies             uint64
	ReceiveQueueDrops, DeliveredBytes                                    uint64
}

type servoSender struct {
	addr          netip.AddrPort
	session       [16]byte
	route         [16]byte
	born          uint64
	nextMessage   uint64
	nextPacket    uint64
	created, used time.Time
	queue         *list.List
	bytes         int
	packer        servoPacker
	elem          *list.Element
	inflight      bool
	reset         bool
}

// No embedded UDPConn and no ReadMsgUDP/WriteMsgUDP: quic-go's OOB/GSO/ECN
// paths cannot bypass the envelope. Mutexes are never held during socket I/O
// or aggregation sleeps. There is one fair scheduler, not one goroutine/peer.
type servoPacketConn struct {
	inner                       net.PacketConn
	server                      bool
	profile                     servoProfile
	tx                          *servoCipher
	rx                          *servoReceiver
	mu                          sync.Mutex
	writeDeadline, readDeadline time.Time
	wake                        chan struct{}
	closed                      bool
	sticky                      error
	remote                      netip.AddrPort
	senders                     map[netip.AddrPort]*servoSender
	routes                      map[netip.AddrPort][16]byte
	order                       *list.List
	pendingItems, pendingBytes  int
	errors                      chan ServoError
	trace                       chan ServoTraceEvent
	done                        chan struct{}
	wg                          sync.WaitGroup
	socketOnce                  sync.Once
	closeErr                    error
	stats                       ServoStats
	random                      io.Reader // fixed crypto/rand.Reader; injectable only in package tests
}

func WrapPacketConnServo(conn net.PacketConn, opts ServoOptions) (net.PacketConn, error) {
	if conn == nil {
		return nil, errors.New("servo: nil packet connection")
	}
	direction := byte(0)
	if opts.Server {
		direction = 1
	}
	p, err := compileServoProfile(opts.Password, direction)
	if err != nil {
		return nil, err
	}
	tx, err := newServoCipher(opts.Password, direction)
	if err != nil {
		return nil, err
	}
	rx, err := newServoReceiver(opts.Password, 1-direction)
	if err != nil {
		return nil, err
	}
	c := &servoPacketConn{
		inner: conn, server: opts.Server, profile: p, tx: tx, rx: rx,
		wake: make(chan struct{}), senders: make(map[netip.AddrPort]*servoSender),
		routes: make(map[netip.AddrPort][16]byte), order: list.New(), random: rand.Reader,
		errors: make(chan ServoError, servoErrorItems), done: make(chan struct{}),
	}
	if opts.Trace {
		c.trace = make(chan ServoTraceEvent, 1024)
	}
	rx.onComplete = c.completedRoute
	c.wg.Add(2)
	go c.readLoop()
	go c.sendLoop()
	go func() {
		c.wg.Wait()
		c.mu.Lock()
		c.cancelAllLocked(net.ErrClosed, "close")
		clear(c.senders)
		clear(c.routes)
		c.order.Init()
		// Release all retained receive buffers, maps and bit windows.
		c.rx.peers = make(map[[16]byte]*servoPeer)
		clear(c.rx.sources)
		clear(c.rx.endpoints)
		clear(c.rx.tombstones)
		clear(c.rx.queued)
		c.rx.peerOrder.Init()
		c.rx.tombOrder.Init()
		c.rx.assemblyOrder.Init()
		c.rx.queue.Init()
		c.rx.assemblyBytes, c.rx.queueBytes = 0, 0
		close(c.errors)
		if c.trace != nil {
			close(c.trace)
		}
		c.mu.Unlock()
		close(c.done)
	}()
	if udp, ok := conn.(udpLikePacketConn); ok {
		return &servoPacketConnUDP{servoPacketConn: c, udp: udp}, nil
	}
	return c, nil
}

func (*servoPacketConn) QUICPacketSizeLimit() int             { return servoInnerMax }
func (c *servoPacketConn) ServoErrors() <-chan ServoError     { return c.errors }
func (c *servoPacketConn) ServoTrace() <-chan ServoTraceEvent { return c.trace }

func (c *servoPacketConn) signalLocked() {
	close(c.wake)
	c.wake = make(chan struct{})
}

func (c *servoPacketConn) terminalLocked() error {
	if c.closed {
		return net.ErrClosed
	}
	return c.sticky
}

func (c *servoPacketConn) closeSocket() { c.socketOnce.Do(func() { c.closeErr = c.inner.Close() }) }

func (c *servoPacketConn) failLocked(err error) {
	if c.sticky == nil {
		c.sticky = err
	}
	c.signalLocked()
}

func (c *servoPacketConn) reportLocked(s *servoSender, m *servoMessage, op string, err error) {
	c.stats.AsyncErrors++
	e := ServoError{Remote: s.addr, Session: s.session, MessageID: m.id, Operation: op, Err: err}
	select {
	case c.errors <- e:
	default:
		c.stats.AsyncErrorsLost++
		c.failLocked(ErrServoErrorOverflow)
	}
}

func (c *servoPacketConn) releaseLocked(s *servoSender, m *servoMessage, err error, op string) {
	if m.elem == nil {
		return
	}
	s.queue.Remove(m.elem)
	m.elem = nil
	s.bytes -= len(m.data)
	c.pendingItems--
	c.pendingBytes -= len(m.data)
	if err != nil {
		c.stats.FailedMessages++
		c.stats.FailedInnerBytes += uint64(len(m.data))
		if op == "close" || op == "session-reset" {
			c.stats.CancelledMessages++
		}
		c.reportLocked(s, m, op, err)
	} else {
		c.stats.CompletedSends++
		c.stats.InnerSentBytes += uint64(len(m.data))
		if m.parts == 2 {
			c.stats.FragmentedMessages++
		}
	}
	c.signalLocked()
}

func (c *servoPacketConn) cancelSenderLocked(s *servoSender, err error, op string) {
	for s.queue.Len() > 0 {
		c.releaseLocked(s, s.queue.Front().Value.(*servoMessage), err, op)
	}
	s.packer.current = nil
	// A failed reserved container is consumed, not re-drawn to get a nicer shape.
	s.packer.next = 0
}

func (c *servoPacketConn) cancelAllLocked(err error, op string) {
	for _, s := range c.senders {
		if !s.inflight {
			c.cancelSenderLocked(s, err, op)
		}
	}
}

func (c *servoPacketConn) completedRoute(p *servoPeer) {
	if !c.server {
		return
	}
	old, exists := c.routes[p.addr]
	if !exists || old != p.session {
		if s := c.senders[p.addr]; s != nil {
			s.reset = true
		}
		c.routes[p.addr] = p.session
		c.signalLocked()
	}
}

func (c *servoPacketConn) newSenderLocked(addr netip.AddrPort, now time.Time) (*servoSender, error) {
	var session [16]byte
	var seed [32]byte
	if _, err := io.ReadFull(c.random, session[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c.random, seed[:]); err != nil {
		return nil, err
	}
	stream, err := newServoStream(seed[:])
	if err != nil {
		return nil, err
	}
	s := &servoSender{
		addr: addr, session: session, route: c.routes[addr], born: uint64(now.Unix()),
		nextMessage: 1, created: now, used: now, queue: list.New(),
	}
	s.packer.wait = c.profile.wait
	s.packer.sample = func() (int, error) { return c.profile.sample(stream) }
	s.elem = c.order.PushBack(s)
	c.senders[addr] = s
	c.stats.SessionRotations++
	return s, nil
}

func waitServo(wake <-chan struct{}, until time.Time) {
	if until.IsZero() {
		<-wake
		return
	}
	t := time.NewTimer(max(0, time.Until(until)))
	select {
	case <-wake:
	case <-t.C:
	}
	t.Stop()
}

func (c *servoPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.writeTo(p, addr, time.Time{})
}

// Optional vendored quic-go timing hook. It OBSERVES the original send time;
// it doesn't rewrite QUIC RTT/loss accounting or pretend outer bytes are inner.
func (c *servoPacketConn) WriteToWithQUICSendTime(p []byte, addr net.Addr, sent time.Time) (int, error) {
	return c.writeTo(p, addr, sent)
}

func (c *servoPacketConn) QUICTransportMetrics(_ net.Addr, rtt, pto time.Duration, lost uint64, probe bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.QUICMetricSamples++
	c.stats.QUICLatestRTT, c.stats.QUICPTO = rtt, pto
	c.stats.QUICPacketsLostMax = max(c.stats.QUICPacketsLostMax, lost)
	if probe {
		c.stats.QUICProbeCalls++
	}
}

func (c *servoPacketConn) writeTo(p []byte, addr net.Addr, quicSent time.Time) (int, error) {
	if len(p) < 1 || len(p) > servoInnerMax {
		return 0, ErrServoPacketSize
	}
	ap, _, ok := blinkAddress(addr)
	if !ok {
		return 0, errors.New("servo: a concrete UDP endpoint is required")
	}
	for {
		c.mu.Lock()
		if err := c.terminalLocked(); err != nil {
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
			return 0, errors.New("servo: client socket is bound to one endpoint; port hopping is not supported")
		}
		if c.server {
			route, exists := c.routes[ap]
			peer := c.rx.peers[route]
			if !exists || peer == nil || !peer.routeReady || now.Sub(peer.used) >= servoSessionTTL {
				delete(c.routes, ap)
				c.mu.Unlock()
				return 0, errors.New("servo: no completed authenticated receive route")
			}
		}
		s := c.senders[ap]
		rotate := s != nil && (s.reset || now.Sub(s.used) >= time.Minute || now.Sub(s.created) >= 10*time.Minute || s.nextMessage > math.MaxUint32 || s.nextPacket >= math.MaxUint64-128)
		if rotate && s.queue.Len() == 0 && !s.inflight {
			delete(c.senders, ap)
			c.order.Remove(s.elem)
			s = nil
			rotate = false
		}
		if !rotate && c.pendingItems < servoSendItems && c.pendingBytes+len(p) <= servoSendBytes && (s == nil || (s.queue.Len() < servoPeerSendItems && s.bytes+len(p) <= servoPeerSendBytes)) {
			if s == nil {
				if len(c.senders) >= servoMaxSessions {
					c.mu.Unlock()
					return 0, errors.New("servo: sender capacity exhausted")
				}
				var err error
				s, err = c.newSenderLocked(ap, now)
				if err != nil {
					c.mu.Unlock()
					return 0, err
				}
			}
			// Quota is reserved under the lock BEFORE copying. No pre-copied
			// buffers can pile up in goroutines waiting for admission.
			m := &servoMessage{id: uint32(s.nextMessage), data: append([]byte(nil), p...), accepted: now, quicSent: quicSent}
			s.nextMessage++
			s.used = now
			m.elem = s.queue.PushBack(m)
			s.bytes += len(p)
			c.pendingItems++
			c.pendingBytes += len(p)
			c.stats.InnerAcceptedBytes += uint64(len(p))
			c.stats.InnerDatagrams++
			c.stats.QueuePeakBytes = max(c.stats.QueuePeakBytes, c.pendingBytes)
			c.stats.QueuePeakItems = max(c.stats.QueuePeakItems, c.pendingItems)
			if !c.server {
				c.remote = ap
			}
			c.signalLocked()
			c.mu.Unlock()
			return len(p), nil
		}
		wake, deadline := c.wake, c.writeDeadline
		c.signalLocked() // wake send owner for session rotation/cancellation
		wake = c.wake
		c.mu.Unlock()
		waitServo(wake, deadline)
	}
}

func (c *servoPacketConn) readLoop() {
	defer c.wg.Done()
	var wire [servoWireMax + 1]byte
	for {
		n, addr, err := c.inner.ReadFrom(wire[:])
		if err != nil {
			if errors.Is(err, syscall.EMSGSIZE) {
				c.mu.Lock()
				c.rx.stats.MalformedDrops++
				c.mu.Unlock()
				continue
			}
			c.mu.Lock()
			if !c.closed {
				c.failLocked(err)
			}
			c.mu.Unlock()
			c.closeSocket()
			return
		}
		ap, _, ok := blinkAddress(addr)
		c.mu.Lock()
		if c.terminalLocked() != nil {
			c.mu.Unlock()
			return
		}
		if ok && n >= 0 && n <= len(wire) && (c.server || ap == c.remote) {
			_ = c.rx.receive(wire[:n], ap, time.Now())
			if c.rx.queue.Len() > 0 {
				c.signalLocked()
			}
		} else {
			c.rx.stats.MalformedDrops++
		}
		c.mu.Unlock()
	}
}

func (c *servoPacketConn) ReadFrom(out []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		if err := c.terminalLocked(); err != nil {
			c.mu.Unlock()
			return 0, nil, err
		}
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			c.mu.Unlock()
			return 0, nil, os.ErrDeadlineExceeded
		}
		if c.rx.queue.Len() > 0 {
			n, addr, err := c.rx.pop(out)
			c.mu.Unlock()
			return n, net.UDPAddrFromAddrPort(addr), err
		}
		wake, deadline := c.wake, c.readDeadline
		c.mu.Unlock()
		waitServo(wake, deadline)
	}
}

func (c *servoPacketConn) LocalAddr() net.Addr { return c.inner.LocalAddr() }

func (c *servoPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.terminalLocked(); err != nil {
		return err
	}
	c.readDeadline = t
	c.signalLocked()
	return nil
}

func (c *servoPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.terminalLocked(); err != nil {
		return err
	}
	if err := c.inner.SetWriteDeadline(t); err != nil {
		return err
	}
	c.writeDeadline = t
	c.signalLocked()
	return nil
}

func (c *servoPacketConn) SetDeadline(t time.Time) error {
	if err := c.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.SetReadDeadline(t)
}

func (c *servoPacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.signalLocked()
	c.mu.Unlock()
	c.closeSocket()
	<-c.done
	return c.closeErr
}

type servoPacketConnUDP struct {
	*servoPacketConn
	udp udpLikePacketConn
}

func (c *servoPacketConnUDP) SyscallConn() (syscall.RawConn, error) { return c.udp.SyscallConn() }
func (c *servoPacketConnUDP) SetReadBuffer(n int) error             { return c.udp.SetReadBuffer(n) }
func (c *servoPacketConnUDP) SetWriteBuffer(n int) error            { return c.udp.SetWriteBuffer(n) }

var _ net.PacketConn = (*servoPacketConn)(nil)
