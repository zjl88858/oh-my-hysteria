// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTasmanTestConn(t testing.TB) (*tasmanPacketConn, *servoTestSocket) {
	t.Helper()
	raw := newServoSocket()
	w, err := WrapPacketConnTasman(raw, TasmanOptions{Password: tasmanTestPassword, Trace: true})
	require.NoError(t, err)
	c := w.(*tasmanPacketConn)
	t.Cleanup(func() { c.Close() })
	return c, raw
}

func tasmanWrite(c *tasmanPacketConn, p []byte) (int, error) {
	return c.WriteToWithQUICBudget(p, blinkServerAddr, time.Now(), time.Now(), 2*len(p)+62)
}

func tasmanDrained(t *testing.T, c *tasmanPacketConn) {
	t.Helper()
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.items != 0 {
			return false
		}
		for _, s := range c.senders {
			if s.plan != nil {
				return false
			}
		}
		return true
	}, 3*time.Second, time.Millisecond)
}

func TestTasmanBudgetCopyTinyAndNonce(t *testing.T) {
	for _, length := range []int{1, 61, 62, 64, 256, 512, 1024, 1170, 1171, 1200} {
		t.Run(string(rune(length)), func(t *testing.T) {
			c, raw := newTasmanTestConn(t)
			p := bytes.Repeat([]byte{7}, length)
			_, err := tasmanWrite(c, p)
			require.NoError(t, err)
			clear(p)
			tasmanDrained(t, c)
			s := c.TasmanStats()
			require.Equal(t, uint64(length), s.InnerSentBytes)
			require.LessOrEqual(t, s.OuterSentBytes, 2*s.InnerAcceptedBytes+s.TinyExceptionBytes)
			require.Zero(t, s.ReservedData)
			require.Zero(t, s.ReservedRepair)
			require.GreaterOrEqual(t, s.Credit, int64(0))
			if length < 62 {
				require.Equal(t, uint64(62-length), s.TinyExceptionBytes)
			}
			r, err := newTasmanReceiver(tasmanTestPassword, 0)
			require.NoError(t, err)
			raw.mu.Lock()
			wires := append([]servoSocketWrite(nil), raw.writes...)
			raw.mu.Unlock()
			seen := map[uint64]bool{}
			for _, w := range wires {
				var scratch [1232]byte
				f, e := r.cipher.open(w.data, &scratch)
				require.NoError(t, e)
				require.False(t, seen[f.counter])
				seen[f.counter] = true
				require.NoError(t, r.receive(w.data, tasmanTestAddr, time.Now()))
			}
			out := make([]byte, 1200)
			n, _, err := r.pop(out)
			require.NoError(t, err)
			require.Equal(t, bytes.Repeat([]byte{7}, length), out[:n])
		})
	}
}

func TestTasmanNoPermitDeadlineBackpressureAndClose(t *testing.T) {
	c, raw := newTasmanTestConn(t)
	_, err := c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, ErrTasmanPermit)
	raw.mu.Lock()
	raw.gate = make(chan struct{})
	raw.mu.Unlock()
	for range 64 {
		_, err = tasmanWrite(c, make([]byte, 64))
		require.NoError(t, err)
	}
	result := make(chan error, 1)
	go func() { _, err := tasmanWrite(c, []byte{1}); result <- err }()
	require.NoError(t, c.SetWriteDeadline(time.Now().Add(10*time.Millisecond)))
	select {
	case err := <-result:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("quota wait stuck")
	}
	tasmanDrained(t, c)
	require.Equal(t, uint64(64), c.TasmanStats().FailedMessages)
	require.NoError(t, c.Close())
	require.Zero(t, c.TasmanStats().PendingBytes)
}

func TestTasmanAsyncFailuresAndCounterConsumed(t *testing.T) {
	for _, failure := range []error{syscall.EMSGSIZE, io.ErrClosedPipe} {
		t.Run(failure.Error(), func(t *testing.T) {
			c, raw := newTasmanTestConn(t)
			raw.mu.Lock()
			raw.nextError = failure
			raw.errorAt = 2
			raw.mu.Unlock()
			_, err := tasmanWrite(c, make([]byte, 1200))
			require.NoError(t, err)
			select {
			case e := <-c.TasmanErrors():
				require.ErrorIs(t, e.Err, failure)
			case <-time.After(time.Second):
				t.Fatal("missing asynchronous failure")
			}
			tasmanDrained(t, c)
			require.Zero(t, c.TasmanStats().InnerSentBytes)
			if errors.Is(failure, syscall.EMSGSIZE) {
				_, err = tasmanWrite(c, []byte{1})
				require.NoError(t, err)
				tasmanDrained(t, c)
			} else {
				_, err = tasmanWrite(c, []byte{1})
				require.Error(t, err)
			}
		})
	}
}

func TestTasmanConcurrentAdmissionAndZeroAllowance(t *testing.T) {
	c, _ := newTasmanTestConn(t)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			for range 4 {
				_, err := tasmanWrite(c, make([]byte, 64))
				if err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
	tasmanDrained(t, c)
	require.Equal(t, uint64(64), c.TasmanStats().CompletedSends)
	_, err := c.WriteToWithQUICBudget([]byte{1}, blinkServerAddr, time.Now(), time.Now(), 0)
	require.ErrorIs(t, err, ErrTasmanPermit)
	_, err = c.WriteToWithQUICBudget([]byte{1}, &net.TCPAddr{}, time.Now(), time.Now(), 64)
	require.Error(t, err)
}

func TestTasmanFeedbackAuthenticatedAndScoped(t *testing.T) {
	c, _ := newTasmanTestConn(t)
	_, err := tasmanWrite(c, make([]byte, 1200))
	require.NoError(t, err)
	tasmanDrained(t, c)
	c.mu.Lock()
	ap, _, _ := blinkAddress(blinkServerAddr)
	s := c.senders[ap]
	pad := make([]byte, 28)
	copy(pad, tasmanFeedbackTag)
	copy(pad[4:20], s.session[:])
	pad[27] = 1
	c.acceptFeedback(blinkServerAddr, pad)
	c.acceptFeedback(blinkServerAddr, pad)
	require.Equal(t, uint64(1), c.stats.ReportedRecoveredSources)
	pad[4] ^= 1
	pad[27] = 2
	c.acceptFeedback(blinkServerAddr, pad)
	require.Equal(t, uint64(1), c.stats.ReportedRecoveredSources)
	c.mu.Unlock()
	require.Equal(t, uint64(1), c.QUICOuterRecovery(blinkServerAddr))
	require.Zero(t, c.QUICOuterRecovery(blinkClientAddr))
}

func TestTasmanCountersRotateAndSessionIsolation(t *testing.T) {
	c, _ := newTasmanTestConn(t)
	_, err := tasmanWrite(c, make([]byte, 1200))
	require.NoError(t, err)
	tasmanDrained(t, c)
	ap, _, _ := blinkAddress(blinkServerAddr)
	for _, field := range []string{"message", "generation", "packet"} {
		c.mu.Lock()
		s := c.senders[ap]
		old := s.session
		switch field {
		case "message":
			s.nextMessage = 1 << 32
		case "generation":
			s.nextGeneration = 1 << 32
		case "packet":
			s.counter = ^uint64(0)
		}
		c.mu.Unlock()
		_, err = tasmanWrite(c, make([]byte, 1200))
		require.NoError(t, err)
		tasmanDrained(t, c)
		c.mu.Lock()
		newSession := c.senders[ap].session
		c.mu.Unlock()
		require.NotEqual(t, old, newSession)
	}
}

func TestTasmanPeerFairnessAndPermitNotBefore(t *testing.T) {
	raw := newServoSocket()
	wrapped, err := WrapPacketConnTasman(raw, TasmanOptions{Password: tasmanTestPassword, Server: true})
	require.NoError(t, err)
	c := wrapped.(*tasmanPacketConn)
	defer c.Close()
	raw.mu.Lock()
	raw.gate = make(chan struct{})
	gate := raw.gate
	raw.mu.Unlock()
	a := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 1234}
	b := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 1235}
	for i, addr := range []*net.UDPAddr{a, b} {
		f := tasmanTestFrame(tasmanShort)
		f.born = uint64(time.Now().Unix())
		f.session[0] = byte(i + 1)
		wire, err := c.rx.cipher.seal(&f)
		require.NoError(t, err)
		ap, _, _ := blinkAddress(addr)
		c.mu.Lock()
		err = c.rx.receive(wire, ap, time.Now())
		c.mu.Unlock()
		require.NoError(t, err)
	}
	for range 32 {
		p := make([]byte, 64)
		_, err = c.WriteToWithQUICBudget(p, a, time.Now(), time.Now(), 190)
		require.NoError(t, err)
	}
	select {
	case <-raw.started:
	case <-time.After(time.Second):
		t.Fatal("send not started")
	}
	_, err = c.WriteToWithQUICBudget(make([]byte, 64), b, time.Now(), time.Now(), 190)
	require.NoError(t, err)
	<-time.After(c.profile.collect + time.Millisecond)
	close(gate)
	tasmanDrained(t, c)
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
	require.LessOrEqual(t, index, 2)
	c2, raw2 := newTasmanTestConn(t)
	ready := time.Now().Add(30 * time.Millisecond)
	_, err = c2.WriteToWithQUICBudget([]byte{1}, blinkServerAddr, time.Now(), ready, 64)
	require.NoError(t, err)
	select {
	case <-raw2.started:
		require.False(t, time.Now().Before(ready))
	case <-time.After(time.Second):
		t.Fatal("permit wasn't used")
	}
	tasmanDrained(t, c2)
}

func TestTasmanTinyHeldCannotFinanceCoverAfterCancellation(t *testing.T) {
	c, _ := newTasmanTestConn(t)
	ready := time.Now().Add(50 * time.Millisecond)
	for range 64 {
		_, err := c.WriteToWithQUICBudget([]byte{1}, blinkServerAddr, time.Now(), ready, 64)
		require.NoError(t, err)
	}
	c.mu.Lock()
	ap, _, _ := blinkAddress(blinkServerAddr)
	s := c.senders[ap]
	require.Equal(t, int64(64*61), s.tinyHeld)
	require.Zero(t, s.credit())
	require.NoError(t, c.plan(s, time.Now())) // even a committed SHORT cannot mint unused exception credit
	require.Equal(t, int64(64*61), s.tinyHeld)
	require.Zero(t, c.stats.TinyExceptionBytes)
	c.cancel(s, io.ErrClosedPipe, "test-cancel")
	require.Zero(t, s.tinyHeld)
	require.Zero(t, s.exceptions)
	require.Zero(t, c.stats.TinyExceptionBytes)
	require.Equal(t, int64(128), s.credit())
	c.mu.Unlock()
	require.NoError(t, c.Close())
}
