// SPDX-License-Identifier: MIT-0

package obfs

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

type netfrontPacket struct {
	buf     [prestoWireMax + 1]byte // extra byte distinguishes truncated / oversized UDP
	n, lane int
	addr    net.Addr
}

// One reader per physical port, not per client. Separate bounded inboxes
// prevent a busy side port from occupying the main port's entire queue.
type netfrontSockets struct {
	conns        []net.PacketConn
	main, side   chan *netfrontPacket
	pool         sync.Pool
	done, failed chan struct{}
	mainErr      error // published by closing failed
	wg           sync.WaitGroup
	deadlineMu   sync.Mutex
	readCtx      context.Context
	cancel       context.CancelFunc
	writeMu      sync.Mutex
	writeDue     time.Time
	sideMu       [netfrontMaxLanes]sync.Mutex
	sideDue      [netfrontMaxLanes]time.Time
}

func newNetfrontSockets(conns []net.PacketConn) *netfrontSockets {
	s := &netfrontSockets{
		conns: conns, main: make(chan *netfrontPacket, 32), side: make(chan *netfrontPacket, 16),
		done: make(chan struct{}), failed: make(chan struct{}), pool: sync.Pool{New: func() any { return new(netfrontPacket) }},
	}
	s.readCtx, s.cancel = context.WithCancel(context.Background())
	return s
}

func (s *netfrontSockets) pump(lane int) {
	defer s.wg.Done()
	in, limit := s.main, prestoWireMax
	if lane != 0 {
		in, limit = s.side, netfrontMaxSide
	}
	for {
		p := s.pool.Get().(*netfrontPacket)
		n, addr, err := s.conns[lane].ReadFrom(p.buf[:limit+1])
		if n > limit || errors.Is(err, syscall.EMSGSIZE) {
			s.pool.Put(p)
			continue
		}
		if err != nil {
			s.pool.Put(p)
			if lane == 0 {
				s.mainErr = err
				close(s.failed)
			} else if !errors.Is(err, net.ErrClosed) {
				// Asynchronous ICMP errors surface differently across OSes.
				// Keep the lane usable if its firewall later opens, without
				// spinning on a persistent socket error.
				timer := time.NewTimer(50 * time.Millisecond)
				select {
				case <-timer.C:
					continue
				case <-s.done:
					timer.Stop()
					return
				}
			}
			return
		}
		if lane != 0 && n < netfrontOverhead {
			s.pool.Put(p)
			continue
		}
		p.n, p.addr, p.lane = n, addr, lane
		select {
		case in <- p:
		case <-s.done:
			s.pool.Put(p)
			return
		}
	}
}

func (s *netfrontSockets) next() (*netfrontPacket, error) {
	for {
		s.deadlineMu.Lock()
		ctx := s.readCtx
		s.deadlineMu.Unlock()
		select {
		case <-s.done:
			return nil, net.ErrClosed
		case <-s.failed:
			return nil, s.mainErr
		default:
		}
		if ctx.Err() == context.DeadlineExceeded {
			return nil, os.ErrDeadlineExceeded
		}
		select {
		case p := <-s.main:
			return p, nil
		case p := <-s.side:
			return p, nil
		case <-ctx.Done(): // re-read: a replacement deadline may already be installed
		case <-s.done:
			return nil, net.ErrClosed
		case <-s.failed:
			return nil, s.mainErr
		}
	}
}

func (s *netfrontSockets) LocalAddr() net.Addr { return s.conns[0].LocalAddr() }

func (s *netfrontSockets) SetReadDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	s.cancel()
	if t.IsZero() {
		s.readCtx, s.cancel = context.WithCancel(context.Background())
	} else {
		s.readCtx, s.cancel = context.WithDeadline(context.Background(), t)
	}
	return nil
}

func netfrontEarlier(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// Only two writers can contend: one Presto foreground write and one offer.
// A backed-up optional socket must not hold the bulk writer indefinitely.
// An external deadline change can still interrupt the current kernel write.
func (s *netfrontSockets) writeSide(lane int, b []byte, addr net.Addr) (int, error) {
	i := lane - 1
	s.sideMu[i].Lock()
	defer s.sideMu[i].Unlock()
	s.writeMu.Lock()
	s.sideDue[i] = time.Now().Add(25 * time.Millisecond)
	err := s.conns[lane].SetWriteDeadline(netfrontEarlier(s.sideDue[i], s.writeDue))
	s.writeMu.Unlock()
	var n int
	if err == nil {
		n, err = s.conns[lane].WriteTo(b, addr)
	}
	s.writeMu.Lock()
	s.sideDue[i] = time.Time{}
	s.writeMu.Unlock()
	return n, err
}

func (s *netfrontSockets) SetWriteDeadline(t time.Time) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.writeDue = t
	var err error
	for i, c := range s.conns {
		due := t
		if i != 0 {
			due = netfrontEarlier(t, s.sideDue[i-1])
		}
		if e := c.SetWriteDeadline(due); e != nil {
			err = errors.Join(err, e)
		}
	}
	return err
}

func (s *netfrontSockets) SetDeadline(t time.Time) error {
	return errors.Join(s.SetReadDeadline(t), s.SetWriteDeadline(t))
}

func (s *netfrontSockets) Close() error {
	// The owning Presto PacketConn serializes Close with sync.Once.
	close(s.done)
	s.deadlineMu.Lock()
	s.cancel()
	s.deadlineMu.Unlock()
	var err error
	for _, c := range s.conns {
		if e := c.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}
	s.wg.Wait()
	return err
}
