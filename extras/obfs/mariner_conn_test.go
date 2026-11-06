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

func newMarinerTestConn(t testing.TB) (*marinerPacketConn, *servoTestSocket) {
	t.Helper()
	raw := newServoSocket()
	w, e := WrapPacketConnMariner(raw, MarinerOptions{Password: marinerTestPassword})
	require.NoError(t, e)
	c := w.(*marinerPacketConn)
	t.Cleanup(func() { c.Close() })
	return c, raw
}

func TestMarinerConcurrentNonceRotationAndCosts(t *testing.T) {
	c, raw := newMarinerTestConn(t)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			for _, n := range []int{1, 64, 256, 512, 900, 1200} {
				p := bytes.Repeat([]byte{7}, n)
				_, e := c.WriteTo(p, blinkServerAddr)
				if e != nil {
					errs <- e
					return
				}
				clear(p)
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
	r, e := newMarinerReceiver(marinerTestPassword, 0)
	require.NoError(t, e)
	var last uint64
	raw.mu.Lock()
	writes := append([]servoSocketWrite(nil), raw.writes...)
	raw.mu.Unlock()
	for i, w := range writes {
		var g marinerGraph
		require.NoError(t, r.profile.graph(len(w.data), &g))
		var raw, plain [1232]byte
		b, e := r.profile.decode(raw[:], w.data, &g)
		require.NoError(t, e)
		f, e := r.cipher.open(plain[:], b, &r.profile, len(w.data))
		require.NoError(t, e)
		if i > 0 {
			require.Greater(t, f.counter, last)
		}
		last = f.counter
		for _, x := range f.data {
			require.Equal(t, byte(7), x)
		}
	}
	s := c.MarinerStats()
	require.Equal(t, uint64(16*6), s.InnerDatagrams)
	require.Equal(t, s.InnerAcceptedBytes, s.InnerSentBytes)
	require.Equal(t, s.InnerSentBytes+62*s.OuterPackets+s.RelationBytes+s.PaddingBytes, s.OuterSentBytes)
	require.LessOrEqual(t, s.GraphEntries, 32)
	ap, _, _ := blinkAddress(blinkServerAddr)
	for _, field := range []string{"packet", "message", "age"} {
		c.mu.Lock()
		old := c.senders[ap].session
		switch field {
		case "packet":
			c.senders[ap].nextPacket = math.MaxUint64
		case "message":
			c.senders[ap].nextMessage = 1 << 32
		case "age":
			c.senders[ap].created = time.Now().Add(-11 * time.Minute)
		}
		c.mu.Unlock()
		_, e = c.WriteTo([]byte{1}, blinkServerAddr)
		require.NoError(t, e)
		require.NotEqual(t, old, c.senders[ap].session)
	}
}

func TestMarinerSynchronousFailuresAndClose(t *testing.T) {
	for _, failure := range []error{syscall.EMSGSIZE, io.ErrClosedPipe, nil} {
		t.Run(fmtMarinerError(failure), func(t *testing.T) {
			c, raw := newMarinerTestConn(t)
			raw.nextError = failure
			raw.errorAt = 2
			raw.short = failure == nil
			_, e := c.WriteTo(make([]byte, 1200), blinkServerAddr)
			require.Error(t, e)
			require.Zero(t, c.MarinerStats().InnerSentBytes)
			ap, _, _ := blinkAddress(blinkServerAddr)
			require.Equal(t, uint64(2), c.senders[ap].nextPacket)
			raw.short = false
			_, e = c.WriteTo([]byte{1}, blinkServerAddr)
			require.NoError(t, e)
		})
	}
	c, raw := newMarinerTestConn(t)
	raw.gate = make(chan struct{})
	done := make(chan error, 1)
	go func() { _, e := c.WriteTo(make([]byte, 1200), blinkServerAddr); done <- e }()
	<-raw.started
	require.NoError(t, c.SetWriteDeadline(time.Now().Add(5*time.Millisecond)))
	require.ErrorIs(t, <-done, os.ErrDeadlineExceeded)
	require.NoError(t, c.SetWriteDeadline(time.Time{}))
	go func() { _, e := c.WriteTo([]byte{1}, blinkServerAddr); done <- e }()
	<-raw.started
	require.NoError(t, c.Close())
	require.ErrorIs(t, <-done, net.ErrClosed)
	require.Zero(t, c.MarinerStats().Senders)
}

func fmtMarinerError(e error) string {
	if e == nil {
		return "short-write"
	}
	return e.Error()
}

func TestMarinerRandomFailureAndInvalidWrites(t *testing.T) {
	c, _ := newMarinerTestConn(t)
	c.random = bytes.NewReader(nil)
	_, e := c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, e, io.EOF)
	require.Empty(t, c.senders)
	for _, p := range [][]byte{nil, make([]byte, 1201)} {
		_, e = c.WriteTo(p, blinkServerAddr)
		require.Error(t, e)
	}
	_, e = c.WriteTo([]byte{1}, &net.TCPAddr{})
	require.Error(t, e)
	c2, _ := newMarinerTestConn(t)
	_, e = c2.WriteTo([]byte{1}, blinkServerAddr)
	require.NoError(t, e)
	_, e = c2.WriteTo([]byte{1}, blinkClientAddr)
	require.Error(t, e)
	_, e = WrapPacketConnMariner(nil, MarinerOptions{Password: marinerTestPassword})
	require.Error(t, e)
	require.False(t, errors.Is(e, io.EOF))
}

func TestMarinerServerRouteAfterCompletionAndSessionReset(t *testing.T) {
	raw := newServoSocket()
	wrapped, e := WrapPacketConnMariner(raw, MarinerOptions{Password: marinerTestPassword, Server: true})
	require.NoError(t, e)
	c := wrapped.(*marinerPacketConn)
	defer c.Close()
	_, e = c.WriteTo([]byte{1}, blinkClientAddr)
	require.ErrorContains(t, e, "authenticated route")
	f := marinerTestFrame(600)
	f.total = 1200
	f.born = uint64(time.Now().Unix())
	rx, e := newMarinerReceiver(marinerTestPassword, 0)
	require.NoError(t, e)
	done := make(chan error, 1)
	go func() {
		var out [1200]byte
		n, _, e := c.ReadFrom(out[:])
		if e == nil && n != 1200 {
			e = io.ErrUnexpectedEOF
		}
		done <- e
	}()
	raw.in <- blinkTestPacket{data: marinerTestSeal(t, rx, f, 0), addr: blinkClientAddr}
	require.Eventually(t, func() bool { return c.MarinerStats().Assemblies == 1 }, time.Second, time.Millisecond)
	_, e = c.WriteTo([]byte{1}, blinkClientAddr)
	require.ErrorContains(t, e, "authenticated route")
	f.offset = 600
	f.counter = 1
	raw.in <- blinkTestPacket{data: marinerTestSeal(t, rx, f, 0), addr: blinkClientAddr}
	require.NoError(t, <-done)
	_, e = c.WriteTo([]byte{1}, blinkClientAddr)
	require.NoError(t, e)
	ap, _, _ := blinkAddress(blinkClientAddr)
	old := c.senders[ap].session
	f = marinerTestFrame(1)
	f.born = uint64(time.Now().Unix())
	f.session[0] = 2
	raw.in <- blinkTestPacket{data: marinerTestSeal(t, rx, f, 0), addr: blinkClientAddr}
	var out [1200]byte
	_, _, e = c.ReadFrom(out[:])
	require.NoError(t, e)
	_, e = c.WriteTo([]byte{1}, blinkClientAddr)
	require.NoError(t, e)
	require.NotEqual(t, old, c.senders[ap].session)
	go func() { _, _, e := c.ReadFrom(out[:]); done <- e }()
	require.NoError(t, c.Close())
	require.ErrorIs(t, <-done, net.ErrClosed)
	require.Positive(t, c.MarinerStats().Receive.Completed)
}

func TestMarinerSameNATSessionIsolation(t *testing.T) {
	r, e := newMarinerReceiver(marinerTestPassword, 0)
	require.NoError(t, e)
	now := time.Unix(1700000000, 0)
	for i := range 32 {
		f := marinerTestFrame(1)
		f.session[0] = byte(i + 1)
		addr := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.9"), uint16(1000+i))
		require.NoError(t, r.receive(marinerTestSeal(t, r, f, 0), addr, now))
	}
	require.Equal(t, 32, len(r.state.peers))
	require.Equal(t, 32, r.state.queue.Len())
	f := marinerTestFrame(1)
	f.session[0] = 33
	require.ErrorIs(t, r.receive(marinerTestSeal(t, r, f, 0), netip.MustParseAddrPort("192.0.2.9:2000"), now), errServoResource)
}
