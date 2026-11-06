// SPDX-License-Identifier: MIT-0

package obfs

import (
	"errors"
	"io"
	"math"
	"net"
	"os"
	"syscall"
	"time"
)

func servoPacketError(err error) bool {
	var e net.Error
	return (errors.As(err, &e) && (e.Timeout() || e.Temporary())) ||
		errors.Is(err, syscall.EMSGSIZE) || errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)
}

func (c *servoPacketConn) removePlannedLocked(s *servoSender, m *servoMessage) {
	p := s.packer.current
	if p == nil {
		return
	}
	var kept [servoRecordsMax]servoTxRecord
	n, data := 0, 0
	var due time.Time
	for i := range p.count {
		r := p.records[i]
		if r.message == m {
			continue
		}
		kept[n] = r
		n++
		data += r.size
		d := r.message.accepted.Add(s.packer.wait)
		if due.IsZero() || d.Before(due) {
			due = d
		}
	}
	if n == 0 {
		s.packer.current = nil
	} else {
		p.records, p.count, p.data, p.due = kept, n, data, due
	}
}

func earlierServo(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

func (c *servoPacketConn) selectContainerLocked(now time.Time) (*servoSender, *servoContainer, time.Time) {
	// Maintenance needs a timer even in the absence of arriving network data.
	c.rx.maintain(now)
	next := now.Add(time.Second)
	for addr, session := range c.routes {
		p := c.rx.peers[session]
		if p == nil || now.Sub(p.used) >= servoSessionTTL {
			delete(c.routes, addr)
			if s := c.senders[addr]; s != nil {
				s.reset = true
			}
		}
	}
	for range c.order.Len() {
		e := c.order.Front()
		s := e.Value.(*servoSender)
		c.order.MoveToBack(e)
		if s.reset {
			c.cancelSenderLocked(s, ErrServoSessionReset, "session-reset")
		}
		if !c.writeDeadline.IsZero() && !now.Before(c.writeDeadline) {
			c.cancelSenderLocked(s, os.ErrDeadlineExceeded, "deadline")
		}
		for s.queue.Len() > 0 {
			m := s.queue.Front().Value.(*servoMessage)
			if now.Sub(m.accepted) < servoQueueTTL {
				break
			}
			c.removePlannedLocked(s, m)
			c.releaseLocked(s, m, ErrServoQueueExpired, "queue-age")
		}
		if s.queue.Len() == 0 {
			if s.reset || now.Sub(s.used) >= time.Minute {
				delete(c.senders, s.addr)
				c.order.Remove(s.elem)
				c.signalLocked()
			}
			continue
		}
		next = earlierServo(next, s.queue.Front().Value.(*servoMessage).accepted.Add(servoQueueTTL))
		if err := s.packer.fill(s.queue); err != nil {
			c.cancelSenderLocked(s, err, "shape")
			c.failLocked(err)
			return nil, nil, next
		}
		if packet := s.packer.take(now); packet != nil {
			s.inflight = true
			return s, packet, next
		}
		if s.packer.current != nil {
			next = earlierServo(next, s.packer.current.due)
		}
	}
	if c.pendingItems > 0 {
		next = earlierServo(next, c.writeDeadline)
	}
	return nil, nil, next
}

func (c *servoPacketConn) traceLocked(s *servoSender, counter uint64, r servoTxRecord, wire int, start, end time.Time, err error) {
	if c.trace == nil {
		return
	}
	event := ServoTraceEvent{
		Remote: s.addr, Session: s.session, MessageID: r.message.id, Counter: counter,
		Offset: r.offset, Length: r.size, WireBytes: wire, Accepted: r.message.accepted,
		QUICSent: r.message.quicSent, Start: start, End: end,
	}
	if err != nil {
		event.Error = err.Error()
	}
	select {
	case c.trace <- event:
	default:
		c.stats.TraceDrops++ // instrumentation may drop; data/errors may NOT silently drop
	}
}

func (c *servoPacketConn) sendLoop() {
	defer c.wg.Done()
	defer c.closeSocket()
	for {
		c.mu.Lock()
		if err := c.terminalLocked(); err != nil {
			c.cancelAllLocked(err, "close")
			c.mu.Unlock()
			return
		}
		s, packet, next := c.selectContainerLocked(time.Now())
		if c.sticky != nil {
			if s != nil {
				s.inflight = false
			}
			c.mu.Unlock()
			continue
		}
		if packet == nil {
			wake := c.wake
			c.mu.Unlock()
			waitServo(wake, next)
			continue
		}
		if s.nextPacket == math.MaxUint64 {
			s.inflight = false
			c.cancelSenderLocked(s, errors.New("servo: counter exhausted before session rotation"), "counter")
			s.reset = true
			c.mu.Unlock()
			continue
		}
		counter := s.nextPacket
		s.nextPacket++ // allocated even if sealing or the eventual write fails
		frame := servoFrame{session: s.session, born: s.born, counter: counter, count: packet.count}
		for i := range packet.count {
			r := packet.records[i]
			frame.records[i] = servoRecord{
				message: r.message.id, total: uint16(len(r.message.data)),
				offset: uint16(r.offset), data: r.message.data[r.offset : r.offset+r.size],
			}
		}
		c.mu.Unlock()
		wire, err := c.tx.seal(&frame)
		start := time.Now()
		n := 0
		if err == nil {
			n, err = c.inner.WriteTo(wire, net.UDPAddrFromAddrPort(s.addr))
			if err == nil && n != len(wire) {
				err = io.ErrShortWrite
			}
		}
		end := time.Now()
		c.mu.Lock()
		s.inflight = false
		if err == nil {
			c.stats.OuterPackets++
			c.stats.OuterSentBytes += uint64(n)
			c.stats.Records += uint64(packet.count)
		} else if n > 0 {
			c.stats.PartialOuterBytes += uint64(min(n, len(wire)))
		}
		for i := range packet.count {
			r := packet.records[i]
			m := r.message
			c.traceLocked(s, counter, r, len(wire), start, end, err)
			if r.offset == 0 {
				wait := uint64(max(0, start.Sub(m.accepted)))
				c.stats.QueueWaitNanos += wait
				c.stats.QueueWaitMaxNanos = max(c.stats.QueueWaitMaxNanos, wait)
			}
			if err != nil {
				op := "write"
				if c.closed {
					op = "close"
				}
				c.releaseLocked(s, m, err, op)
				continue
			}
			m.sent += r.size
			if m.sent == len(m.data) {
				if !m.quicSent.IsZero() {
					delay := uint64(max(0, end.Sub(m.quicSent)))
					c.stats.QUICSendSamples++
					c.stats.QUICDelayNanos += delay
					c.stats.QUICDelayMaxNanos = max(c.stats.QUICDelayMaxNanos, delay)
				}
				c.releaseLocked(s, m, nil, "")
			}
		}
		if err != nil && !servoPacketError(err) && !c.closed {
			c.failLocked(err)
		}
		c.signalLocked()
		c.mu.Unlock()
	}
}

func (c *servoPacketConn) ServoStats() ServoStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.PendingBytes, s.PendingDatagrams, s.Senders = c.pendingBytes, c.pendingItems, len(c.senders)
	s.ReceiveSessions = len(c.rx.peers)
	s.Assemblies, s.ReassemblyBytes = c.rx.assemblyOrder.Len(), c.rx.assemblyBytes
	s.ReceiveQueueBytes, s.ReceiveQueueItems = c.rx.queueBytes, c.rx.queue.Len()
	r := c.rx.stats
	s.ReceivedPackets, s.ReceivedWireBytes = r.OuterPackets, r.OuterBytes
	s.AuthDrops, s.MalformedDrops, s.RateDrops = r.AuthDrops, r.MalformedDrops, r.RateDrops
	s.ReplayDrops = r.PacketReplayDrops + r.MessageReplayDrops
	s.ResourceDrops = r.ResourceDrops
	s.ExpiredAssemblies, s.ReceiveQueueDrops, s.DeliveredBytes = r.ExpiredAssemblies, r.QueueDrops, r.DeliveredBytes
	return s
}
