// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type servoSocketWrite struct {
	data []byte
	addr net.Addr
}

type servoTestSocket struct {
	mu        sync.Mutex
	in        chan blinkTestPacket
	closed    chan struct{}
	wake      chan struct{}
	once      sync.Once
	gate      chan struct{}
	started   chan struct{}
	deadline  time.Time
	writes    []servoSocketWrite
	nextError error
	errorAt   int
	attempts  int
	short     bool
}

func newServoSocket() *servoTestSocket {
	return &servoTestSocket{in: make(chan blinkTestPacket, 64), closed: make(chan struct{}), wake: make(chan struct{}), started: make(chan struct{}, 64)}
}

func (s *servoTestSocket) ReadFrom(out []byte) (int, net.Addr, error) {
	select {
	case p := <-s.in:
		return copy(out, p.data), p.addr, nil
	case <-s.closed:
		return 0, nil, net.ErrClosed
	}
}

func (s *servoTestSocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case s.started <- struct{}{}:
	default:
	}
	for {
		s.mu.Lock()
		deadline, wake, gate := s.deadline, s.wake, s.gate
		s.mu.Unlock()
		select {
		case <-s.closed:
			return 0, net.ErrClosed
		default:
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if gate == nil {
			break
		}
		t := time.NewTimer(time.Hour)
		if !deadline.IsZero() {
			t.Reset(max(0, time.Until(deadline)))
		}
		select {
		case <-gate:
			t.Stop()
			goto ready
		case <-s.closed:
			t.Stop()
			return 0, net.ErrClosed
		case <-wake:
			t.Stop()
		case <-t.C:
			return 0, os.ErrDeadlineExceeded
		}
	}
ready:
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.nextError != nil && (s.errorAt == 0 || s.errorAt == s.attempts) {
		err := s.nextError
		s.nextError = nil
		return 0, err
	}
	if s.short {
		return len(p) - 1, nil
	}
	s.writes = append(s.writes, servoSocketWrite{data: bytes.Clone(p), addr: addr})
	return len(p), nil
}

func (s *servoTestSocket) Close() error                    { s.once.Do(func() { close(s.closed) }); return nil }
func (s *servoTestSocket) LocalAddr() net.Addr             { return blinkClientAddr }
func (s *servoTestSocket) SetReadDeadline(time.Time) error { return nil }
func (s *servoTestSocket) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadline = t
	close(s.wake)
	s.wake = make(chan struct{})
	return nil
}
func (s *servoTestSocket) SetDeadline(t time.Time) error { return s.SetWriteDeadline(t) }

func newServoConnTest(t testing.TB, server bool) (*servoPacketConn, *servoTestSocket) {
	t.Helper()
	s := newServoSocket()
	w, err := WrapPacketConnServo(s, ServoOptions{Password: servoTestPassword, Server: server, Trace: true})
	require.NoError(t, err)
	c := w.(*servoPacketConn)
	t.Cleanup(func() { c.Close() })
	return c, s
}

func waitServoDrained(t *testing.T, c *servoPacketConn) {
	t.Helper()
	require.Eventually(t, func() bool { return c.ServoStats().PendingDatagrams == 0 }, 3*time.Second, time.Millisecond)
}

func TestServoAsyncCopyCountersAndAggregation(t *testing.T) {
	c, raw := newServoConnTest(t, false)
	data := bytes.Repeat([]byte{7}, 1200)
	for range 20 {
		n, err := c.WriteToWithQUICSendTime(data, blinkServerAddr, time.Now().Add(-time.Millisecond))
		require.NoError(t, err)
		require.Equal(t, len(data), n)
	}
	clear(data)
	waitServoDrained(t, c)
	stats := c.ServoStats()
	require.Equal(t, uint64(20*1200), stats.InnerAcceptedBytes)
	require.Equal(t, stats.InnerAcceptedBytes, stats.InnerSentBytes)
	require.Equal(t, uint64(20), stats.QUICSendSamples)
	require.Positive(t, stats.QUICDelayNanos)
	require.Zero(t, stats.AsyncErrors)
	require.Less(t, stats.OuterPackets, uint64(40), "tail/head must really share containers")
	r := servoTestReceiver(t)
	raw.mu.Lock()
	writes := append([]servoSocketWrite(nil), raw.writes...)
	raw.mu.Unlock()
	var prev uint64
	for i, p := range writes {
		var scratch [servoWireMax]byte
		f, err := r.cipher.open(p.data, &scratch)
		require.NoError(t, err)
		if i > 0 {
			require.Greater(t, f.counter, prev)
		}
		prev = f.counter
		require.NoError(t, r.receive(p.data, servoTestAddr, time.Now()))
	}
	var out [1200]byte
	for range 20 {
		n, _, err := r.pop(out[:])
		require.NoError(t, err)
		require.Equal(t, bytes.Repeat([]byte{7}, 1200), out[:n])
	}
}

func TestServoConcurrentAdmissionAndSessionRotation(t *testing.T) {
	c, _ := newServoConnTest(t, false)
	var wg sync.WaitGroup
	errors := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			for range 4 {
				_, err := c.WriteTo(make([]byte, 64), blinkServerAddr)
				if err != nil {
					errors <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	waitServoDrained(t, c)
	require.Equal(t, uint64(64), c.ServoStats().CompletedSends)
	c.mu.Lock()
	ap, _, _ := blinkAddress(blinkServerAddr)
	s := c.senders[ap]
	old := s.session
	s.nextMessage = math.MaxUint32 + 1
	c.mu.Unlock()
	_, err := c.WriteTo([]byte{1}, blinkServerAddr)
	require.NoError(t, err)
	waitServoDrained(t, c)
	c.mu.Lock()
	s = c.senders[ap]
	require.NotEqual(t, old, s.session)
	old = s.session
	s.nextPacket = math.MaxUint64
	c.mu.Unlock()
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.NoError(t, err)
	waitServoDrained(t, c)
	c.mu.Lock()
	require.NotEqual(t, old, c.senders[ap].session)
	c.mu.Unlock()
}

func TestServoQueueBackpressureDeadlineAndClose(t *testing.T) {
	c, raw := newServoConnTest(t, false)
	raw.mu.Lock()
	raw.gate = make(chan struct{})
	raw.mu.Unlock()
	for range servoPeerSendItems {
		_, err := c.WriteTo(make([]byte, 64), blinkServerAddr)
		require.NoError(t, err)
	}
	require.Equal(t, servoPeerSendItems, c.ServoStats().PendingDatagrams)
	result := make(chan error, 1)
	go func() { _, err := c.WriteTo([]byte{1}, blinkServerAddr); result <- err }()
	require.NoError(t, c.SetWriteDeadline(time.Now().Add(20*time.Millisecond)))
	select {
	case err := <-result:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("admission deadline blocked")
	}
	waitServoDrained(t, c)
	require.Equal(t, uint64(servoPeerSendItems), c.ServoStats().FailedMessages)
	require.NoError(t, c.SetWriteDeadline(time.Time{}))
	_, err := c.WriteTo([]byte{1}, blinkServerAddr)
	require.NoError(t, err)
	readDone := make(chan error, 1)
	go func() { _, _, err := c.ReadFrom(make([]byte, 1200)); readDone <- err }()
	require.NoError(t, c.Close())
	select {
	case err := <-readDone:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("read not released")
	}
	require.Zero(t, c.ServoStats().PendingDatagrams)
	require.NoError(t, c.Close())
}

func TestServoAsyncPacketAndTerminalErrors(t *testing.T) {
	for _, kind := range []string{"packet", "fatal", "short"} {
		t.Run(kind, func(t *testing.T) {
			c, raw := newServoConnTest(t, false)
			raw.mu.Lock()
			if kind == "packet" {
				raw.nextError = syscall.EMSGSIZE
			} else if kind == "fatal" {
				raw.nextError = io.ErrClosedPipe
			} else {
				raw.short = true
			}
			raw.mu.Unlock()
			_, err := c.WriteTo(make([]byte, 1200), blinkServerAddr)
			require.NoError(t, err)
			select {
			case e := <-c.ServoErrors():
				require.Equal(t, uint32(1), e.MessageID)
				require.Equal(t, "write", e.Operation)
				require.Error(t, e.Err)
			case <-time.After(time.Second):
				t.Fatal("missing async error")
			}
			waitServoDrained(t, c)
			if kind == "packet" {
				_, err = c.WriteTo([]byte{1}, blinkServerAddr)
				require.NoError(t, err)
				waitServoDrained(t, c)
				require.Equal(t, uint64(1), c.ServoStats().CompletedSends)
			} else {
				require.Eventually(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.sticky != nil }, time.Second, time.Millisecond)
				_, err = c.WriteTo([]byte{1}, blinkServerAddr)
				require.Error(t, err)
			}
		})
	}
}

func TestServoErrorOverflowIsStickyAndRandomFailureIsNotAccepted(t *testing.T) {
	c, _ := newServoConnTest(t, false)
	c.mu.Lock()
	c.random = bytes.NewReader(nil)
	c.mu.Unlock()
	n, err := c.WriteTo([]byte{1}, blinkServerAddr)
	require.Error(t, err)
	require.Zero(t, n)
	require.Zero(t, c.ServoStats().InnerDatagrams)
	c.mu.Lock()
	s := &servoSender{addr: netip.MustParseAddrPort("192.0.2.1:1234")}
	for i := 0; i <= servoErrorItems; i++ {
		c.reportLocked(s, &servoMessage{id: uint32(i)}, "test", io.EOF)
	}
	require.ErrorIs(t, c.sticky, ErrServoErrorOverflow)
	c.mu.Unlock()
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, ErrServoErrorOverflow)
}

func TestServoServerRouteAndReceiveDeadline(t *testing.T) {
	c, raw := newServoConnTest(t, true)
	_, err := c.WriteTo([]byte{1}, blinkClientAddr)
	require.ErrorContains(t, err, "route")
	tx := servoTestCipher(t, 0)
	f := servoStateFrame(1, 0, servoRecord{message: 1, total: 1200, data: make([]byte, 700)})
	f.born = uint64(time.Now().Unix())
	wire, err := tx.seal(&f)
	require.NoError(t, err)
	raw.in <- blinkTestPacket{data: wire, addr: blinkClientAddr}
	require.Eventually(t, func() bool { return c.ServoStats().Assemblies == 1 }, time.Second, time.Millisecond)
	_, err = c.WriteTo([]byte{1}, blinkClientAddr)
	require.ErrorContains(t, err, "route")
	f.counter++
	f.records[0] = servoRecord{message: 1, total: 1200, offset: 700, data: make([]byte, 500)}
	wire, err = tx.seal(&f)
	require.NoError(t, err)
	raw.in <- blinkTestPacket{data: wire, addr: blinkClientAddr}
	require.NoError(t, c.SetReadDeadline(time.Now().Add(time.Second)))
	_, _, err = c.ReadFrom(make([]byte, 1))
	require.ErrorIs(t, err, io.ErrShortBuffer)
	_, err = c.WriteTo([]byte{1}, blinkClientAddr)
	require.NoError(t, err)
	waitServoDrained(t, c)
	require.NoError(t, c.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
	_, _, err = c.ReadFrom(make([]byte, 1200))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestServoRejectsInvalidAndDifferentRemote(t *testing.T) {
	_, err := WrapPacketConnServo(nil, ServoOptions{})
	require.Error(t, err)
	_, err = WrapPacketConnServo(newServoSocket(), ServoOptions{})
	require.Error(t, err)
	c, _ := newServoConnTest(t, false)
	for _, data := range [][]byte{nil, make([]byte, 1201)} {
		n, err := c.WriteTo(data, blinkServerAddr)
		require.ErrorIs(t, err, ErrServoPacketSize)
		require.Zero(t, n)
	}
	_, err = c.WriteTo([]byte{1}, &net.TCPAddr{})
	require.Error(t, err)
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.NoError(t, err)
	_, err = c.WriteTo([]byte{1}, blinkClientAddr)
	require.ErrorContains(t, err, "one endpoint")
	require.False(t, errors.Is(err, net.ErrClosed))
}

func servoTestRoute(t *testing.T, c *servoPacketConn, id uint64, addr *net.UDPAddr) {
	t.Helper()
	f := servoStateFrame(id, 0, servoFullRecord(1, 1))
	f.born = uint64(time.Now().Unix())
	wire, err := c.rx.cipher.seal(&f)
	require.NoError(t, err)
	ap, _, _ := blinkAddress(addr)
	c.mu.Lock()
	err = c.rx.receive(wire, ap, time.Now())
	c.mu.Unlock()
	require.NoError(t, err)
}

func TestServoMultiRemoteFairnessAndGlobalAdmissionBound(t *testing.T) {
	c, raw := newServoConnTest(t, true)
	raw.mu.Lock()
	raw.gate = make(chan struct{})
	gate := raw.gate
	raw.mu.Unlock()
	a := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	b := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 1234}
	servoTestRoute(t, c, 1, a)
	servoTestRoute(t, c, 2, b)
	for range 32 {
		_, err := c.WriteTo(make([]byte, 64), a)
		require.NoError(t, err)
	}
	select {
	case <-raw.started:
	case <-time.After(time.Second):
		t.Fatal("send not started")
	}
	for range 8 {
		_, err := c.WriteTo(make([]byte, 64), b)
		require.NoError(t, err)
	}
	close(gate)
	waitServoDrained(t, c)
	raw.mu.Lock()
	writes := append([]servoSocketWrite(nil), raw.writes...)
	raw.mu.Unlock()
	index := -1
	for i, w := range writes {
		if w.addr.String() == b.String() {
			index = i
			break
		}
	}
	require.GreaterOrEqual(t, index, 0)
	require.LessOrEqual(t, index, 2, "a busy peer must not drain before a ready peer")

	c2, raw2 := newServoConnTest(t, true)
	raw2.mu.Lock()
	raw2.gate = make(chan struct{})
	raw2.mu.Unlock()
	for peer := 1; peer <= 16; peer++ {
		addr := &net.UDPAddr{IP: net.IPv4(198, 18, 0, byte(peer)), Port: 1234}
		servoTestRoute(t, c2, uint64(peer), addr)
		for range servoPeerSendItems {
			_, err := c2.WriteTo([]byte{1}, addr)
			require.NoError(t, err)
		}
	}
	require.Equal(t, servoSendItems, c2.ServoStats().PendingDatagrams)
	third := &net.UDPAddr{IP: net.IPv4(198, 18, 0, 17), Port: 1234}
	servoTestRoute(t, c2, 17, third)
	waiting := make(chan error, 1)
	go func() { _, err := c2.WriteTo([]byte{1}, third); waiting <- err }()
	require.NoError(t, c2.Close())
	select {
	case err := <-waiting:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("global quota waiter leaked")
	}
	require.Zero(t, c2.ServoStats().PendingBytes)
	require.Equal(t, uint64(servoSendItems), c2.ServoStats().FailedMessages)
}

func TestServoPartialFailureDoesNotRetryOrReuseCounter(t *testing.T) {
	c, raw := newServoConnTest(t, false)
	raw.mu.Lock()
	raw.nextError = syscall.EMSGSIZE
	raw.errorAt = 2
	raw.mu.Unlock()
	_, err := c.WriteTo(make([]byte, 1200), blinkServerAddr)
	require.NoError(t, err)
	waitServoDrained(t, c)
	require.Equal(t, uint64(1), c.ServoStats().OuterPackets)
	require.Zero(t, c.ServoStats().InnerSentBytes)
	_, err = c.WriteTo([]byte{3}, blinkServerAddr)
	require.NoError(t, err)
	waitServoDrained(t, c)
	raw.mu.Lock()
	writes := append([]servoSocketWrite(nil), raw.writes...)
	raw.mu.Unlock()
	require.Len(t, writes, 2)
	cipher := servoTestCipher(t, 0)
	var scratch [servoWireMax]byte
	f, err := cipher.open(writes[0].data, &scratch)
	require.NoError(t, err)
	require.Zero(t, f.counter)
	f, err = cipher.open(writes[1].data, &scratch)
	require.NoError(t, err)
	require.Equal(t, uint64(2), f.counter)
	require.Equal(t, uint32(2), f.records[0].message)
}

func TestServoQueueAgeIsExplicitlyFailed(t *testing.T) {
	c, _ := newServoConnTest(t, false)
	c.mu.Lock()
	ap, _, _ := blinkAddress(blinkServerAddr)
	s, err := c.newSenderLocked(ap, time.Now())
	if err != nil {
		c.mu.Unlock()
		t.Fatal(err)
	}
	m := &servoMessage{id: 1, data: []byte{1}, accepted: time.Now().Add(-2 * servoQueueTTL)}
	m.elem = s.queue.PushBack(m)
	s.bytes = 1
	c.pendingItems = 1
	c.pendingBytes = 1
	c.stats.InnerAcceptedBytes = 1
	c.stats.InnerDatagrams = 1
	c.signalLocked()
	c.mu.Unlock()
	select {
	case e := <-c.ServoErrors():
		require.ErrorIs(t, e.Err, ErrServoQueueExpired)
		require.Equal(t, "queue-age", e.Operation)
	case <-time.After(time.Second):
		t.Fatal("aged message wasn't failed")
	}
	waitServoDrained(t, c)
	require.Zero(t, c.ServoStats().OuterPackets)
}

func TestServoAuthenticatedRestartCancelsOldQueuedSession(t *testing.T) {
	c, raw := newServoConnTest(t, true)
	servoTestRoute(t, c, 1, blinkClientAddr)
	raw.mu.Lock()
	raw.gate = make(chan struct{})
	gate := raw.gate
	raw.mu.Unlock()
	for range 2 {
		_, err := c.WriteTo(make([]byte, 1200), blinkClientAddr)
		require.NoError(t, err)
	}
	select {
	case <-raw.started:
	case <-time.After(time.Second):
		t.Fatal("initial write not started")
	}
	servoTestRoute(t, c, 2, blinkClientAddr)
	result := make(chan error, 1)
	go func() { _, err := c.WriteTo([]byte{1}, blinkClientAddr); result <- err }()
	close(gate)
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("new session admission not awakened")
	}
	waitServoDrained(t, c)
	require.Equal(t, uint64(2), c.ServoStats().CancelledMessages)
	require.Equal(t, uint64(1), c.ServoStats().CompletedSends)
	for range 2 {
		e := <-c.ServoErrors()
		require.ErrorIs(t, e.Err, ErrServoSessionReset)
	}
}
