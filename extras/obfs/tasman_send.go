// SPDX-License-Identifier: MIT-0

package obfs

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"time"
)

type (
	tasmanTxFrame struct {
		kind, index, k byte
		generation     uint32
		width          int
		body, padding  []byte
		messages       []*tasmanMessage
	}
	tasmanPlan struct {
		frames                     []tasmanTxFrame
		pos                        int
		dataReserve, repairReserve int64
		tinyHold                   int64
		due                        time.Time
		accepted, sent             time.Time
	}
)

func (s *tasmanSender) credit() int64 {
	return 2*s.d + s.exceptions + s.tinyHeld - s.w - s.reserved - s.repairReserved
}

// Build a complete, independently executable plan BEFORE spending optional credit.
// No phantom future message is included. Fixed width and k are committed together.
func (c *tasmanPacketConn) plan(s *tasmanSender, now time.Time) error {
	first := s.queue.Front().Value.(*tasmanMessage)
	index, err := s.stream.below(4)
	if err != nil {
		return err
	}
	family, err := s.stream.below(2)
	if err != nil {
		return err
	}
	width := c.profile.wide[index]
	if family == 0 {
		width = c.profile.narrow[index]
	}
	var messages []*tasmanMessage
	var symbols [][]byte
	var owners [][]*tasmanMessage
	var totalReserve, totalTinyHold int64
	for e := s.queue.Front(); e != nil; e = e.Next() {
		m := e.Value.(*tasmanMessage)
		if now.Before(m.notBefore) {
			break
		}
		// Bound a generation to 8 symbols; don't begin a message without room.
		remaining := 0
		if len(symbols) > 0 {
			remaining = width - 2 - int(binary.BigEndian.Uint16(symbols[len(symbols)-1])) - 10
			remaining = max(0, remaining)
		}
		needed := (max(0, len(m.data)-remaining) + width - 13) / (width - 12)
		if len(symbols)+needed > 8 {
			break
		}
		messages = append(messages, m)
		totalReserve += m.reserve
		totalTinyHold += m.tinyHold
		for offset := 0; offset < len(m.data); {
			if len(symbols) == 0 || width-2-int(binary.BigEndian.Uint16(symbols[len(symbols)-1])) <= 10 {
				symbols = append(symbols, make([]byte, width))
				owners = append(owners, nil)
			}
			i := len(symbols) - 1
			b := symbols[i]
			used := int(binary.BigEndian.Uint16(b))
			n := min(len(m.data)-offset, width-2-used-10)
			r := tasmanRecord{message: m.id, total: uint16(len(m.data)), offset: uint16(offset), data: m.data[offset : offset+n]}
			used += encodeTasmanRecord(b[2+used:], r)
			binary.BigEndian.PutUint16(b, uint16(used))
			owners[i] = append(owners[i], m)
			offset += n
		}
	}
	dataCost := int64(len(symbols) * (width + 60))
	available := s.credit() + totalReserve - totalTinyHold
	if len(messages) == 0 || dataCost > totalReserve || dataCost > available {
		// A small isolated message has a guaranteed compact SHORT escape.
		if len(first.data) <= 1170 {
			body := make([]byte, 10+len(first.data))
			encodeTasmanRecord(body, tasmanRecord{message: first.id, total: uint16(len(first.data)), data: first.data})
			cost := int64(len(body) + 52)
			available = s.credit() + first.reserve - first.tinyHold
			extra := max(0, cost-available)
			if cost > available {
				if len(first.data) >= 62 || extra > first.tinyHold {
					return errors.New("tasman: compact reservation invariant violated")
				}
			}
			s.reserved -= first.reserve
			s.tinyHeld -= first.tinyHold
			first.tinyHold = 0
			s.tinyHeld += extra
			first.reserve = 0
			s.reserved += cost
			s.plan = &tasmanPlan{frames: []tasmanTxFrame{{kind: tasmanShort, body: body, messages: []*tasmanMessage{first}}}, dataReserve: cost, tinyHold: extra, due: maxTime(first.accepted.Add(c.profile.collect), first.notBefore), accepted: first.accepted, sent: first.sent}
			return nil
		}
		// The admitted wide-family reservation always covers a 1200B message.
		width = c.profile.wide[0]
		symbols = nil
		owners = nil
		messages = []*tasmanMessage{first}
		totalReserve = first.reserve
		totalTinyHold = first.tinyHold
		for offset := 0; offset < len(first.data); {
			b := make([]byte, width)
			n := min(len(first.data)-offset, width-12)
			used := encodeTasmanRecord(b[2:], tasmanRecord{message: first.id, total: uint16(len(first.data)), offset: uint16(offset), data: first.data[offset : offset+n]})
			binary.BigEndian.PutUint16(b, uint16(used))
			symbols = append(symbols, b)
			owners = append(owners, []*tasmanMessage{first})
			offset += n
		}
		dataCost = int64(len(symbols) * (width + 60))
	}
	if dataCost > totalReserve {
		return errors.New("tasman: infeasible source reservation")
	}
	s.reserved -= totalReserve
	s.tinyHeld -= totalTinyHold
	for _, m := range messages {
		m.reserve = 0
		m.tinyHold = 0
	}
	s.reserved += dataCost
	generation := uint32(s.nextGeneration)
	s.nextGeneration++
	p := &tasmanPlan{dataReserve: dataCost, accepted: first.accepted, sent: first.sent, due: maxTime(first.accepted.Add(c.profile.collect), first.notBefore)}
	slot, err := s.stream.below(int(c.profile.collect/time.Microsecond) + 1)
	if err != nil {
		return err
	}
	p.due = maxTime(first.notBefore, first.accepted.Add(time.Duration(slot)*time.Microsecond))
	if len(symbols) == 8 {
		p.due = maxTime(now, first.notBefore)
	}
	for i, b := range symbols {
		p.frames = append(p.frames, tasmanTxFrame{kind: tasmanSource, index: byte(i), generation: generation, width: width, body: b, messages: owners[i]})
	}
	// Only committed repairs reserve credit. There are no feedback retries.
	if len(symbols) >= 2 {
		for j := 0; j < c.profile.repairs; j++ {
			cost := int64(width + 60)
			if s.credit() < cost || s.permit-s.spent-s.reserved-s.repairReserved < cost {
				break
			}
			s.repairReserved += cost
			p.repairReserve += cost
			p.frames = append(p.frames, tasmanTxFrame{kind: tasmanRepair, index: byte(128 + j), k: byte(len(symbols)), generation: generation, width: width, body: tasmanEncode(symbols, j)})
		}
	}
	feedback := c.feedback(s)
	if len(feedback) > 0 && s.credit() >= int64(len(feedback)) && s.permit-s.spent-s.reserved-s.repairReserved >= int64(len(feedback)) {
		p.frames[0].padding = feedback
		s.reserved += int64(len(feedback))
		p.dataReserve += int64(len(feedback))
	}
	for i := range p.frames {
		if len(p.frames[i].padding) > 0 {
			continue
		}
		n, err := s.stream.below(c.profile.padding + 1)
		if err != nil {
			return err
		}
		n = min(n, int(max(0, min(s.credit(), s.permit-s.spent-s.reserved-s.repairReserved))))
		if n > 0 {
			p.frames[i].padding = make([]byte, n)
			s.reserved += int64(n)
			p.dataReserve += int64(n)
		}
	}
	s.plan = p
	return nil
}

func (c *tasmanPacketConn) selectFrame(now time.Time) (*tasmanSender, *tasmanTxFrame, time.Time) {
	c.rx.maintain(now)
	next := now.Add(time.Second)
	for range c.order.Len() {
		e := c.order.Front()
		s := e.Value.(*tasmanSender)
		c.order.MoveToBack(e)
		if s.counter == ^uint64(0) || s.nextGeneration > uint64(^uint32(0)) {
			c.cancel(s, errors.New("tasman: session counter exhausted before rotation"), "session-rotation")
			s.reset = true
		}
		if c.server {
			p := c.rx.peers[c.routes[s.addr]]
			if p == nil || !p.ready || now.Sub(p.used) >= 2*time.Minute {
				s.reset = true
			}
		}
		if s.reset {
			c.cancel(s, errors.New("tasman: authenticated session changed"), "session-reset")
		}
		if !c.writeDeadline.IsZero() && !now.Before(c.writeDeadline) {
			c.cancel(s, os.ErrDeadlineExceeded, "deadline")
		}
		if s.queue.Len() > 0 {
			m := s.queue.Front().Value.(*tasmanMessage)
			if now.Sub(m.accepted) >= 100*time.Millisecond {
				c.cancel(s, ErrTasmanExpired, "queue-age")
			}
		}
		if s.plan == nil && s.queue.Len() > 0 {
			m := s.queue.Front().Value.(*tasmanMessage)
			if now.Before(m.notBefore) {
				next = earlierServo(next, m.notBefore)
				continue
			}
			if err := c.plan(s, now); err != nil {
				c.cancel(s, err, "plan")
				c.fail(err)
				return nil, nil, next
			}
		}
		if p := s.plan; p != nil {
			if now.Before(p.due) {
				next = earlierServo(next, p.due)
				continue
			}
			f := &p.frames[p.pos]
			size := int64(60 + len(f.body) + len(f.padding))
			if f.kind == tasmanShort {
				size -= 8
			}
			if s.permit-s.spent < size {
				next = earlierServo(next, now.Add(time.Millisecond))
				continue
			} // never deadline-mint a permit
			s.inflight = true
			return s, f, next
		}
		if s.queue.Len() == 0 && s.plan == nil {
			if s.tails > 0 && now.Before(s.tailUntil) {
				if now.Before(s.nextTail) {
					next = earlierServo(next, s.nextTail)
					continue
				}
				n := min(32, int(max(0, s.credit()-60)))
				cost := int64(60 + n)
				if s.credit() >= cost && s.permit-s.spent >= cost {
					s.tails--
					s.nextTail = now.Add(c.profile.carrier)
					s.plan = &tasmanPlan{frames: []tasmanTxFrame{{kind: tasmanCover, padding: make([]byte, n)}}, dataReserve: cost, due: now}
					s.reserved += cost
					s.inflight = true
					return s, &s.plan.frames[0], next
				}
				s.tails = 0
			}
			if s.reset || now.Sub(s.used) >= time.Minute {
				delete(c.senders, s.addr)
				c.order.Remove(s.elem)
				c.signal()
			}
		}
	}
	if c.items > 0 {
		next = earlierServo(next, c.writeDeadline)
	}
	return nil, nil, next
}

func (c *tasmanPacketConn) sendLoop() {
	defer c.wg.Done()
	defer c.closeSocket()
	for {
		c.mu.Lock()
		if err := c.terminal(); err != nil {
			for _, s := range c.senders {
				c.cancel(s, err, "close")
			}
			c.mu.Unlock()
			return
		}
		s, f, next := c.selectFrame(time.Now())
		if c.sticky != nil {
			if s != nil {
				s.inflight = false
			}
			c.mu.Unlock()
			continue
		}
		if f == nil {
			wake := c.wake
			c.mu.Unlock()
			waitServo(wake, next)
			continue
		}
		p := s.plan
		counter := s.counter
		s.counter++
		frame := tasmanFrame{session: s.session, counter: counter, born: s.born, kind: f.kind, generation: f.generation, index: f.index, finalK: f.k, width: f.width, body: f.body, padding: f.padding}
		s.spent += int64(60 + len(f.body) + len(f.padding))
		if f.kind == tasmanShort {
			s.spent -= 8
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
		actual := max(0, min(n, len(wire)))
		s.w += int64(actual)
		c.stats.SpentPermitBytes += uint64(len(wire))
		if actual > 0 {
			c.stats.OuterSentBytes += uint64(actual)
		}
		cost := int64(len(wire))
		if f.kind == tasmanShort && p.tinyHold > 0 {
			extra := max(0, int64(actual)-(int64(52+len(f.body))-p.tinyHold))
			s.tinyHeld -= p.tinyHold
			p.tinyHold = 0
			if extra > 0 {
				s.exceptions += extra
				c.stats.TinyExceptionBytes += uint64(extra)
				c.stats.TinyOverheadException++
			}
		}
		if f.kind == tasmanRepair {
			s.repairReserved -= int64(f.width + 60)
			p.repairReserve -= int64(f.width + 60)
			s.reserved -= int64(len(f.padding))
			p.dataReserve -= int64(len(f.padding))
		} else {
			s.reserved -= cost
			p.dataReserve -= cost
		}
		if err != nil {
			if actual > 0 {
				c.stats.PartialOuterBytes += uint64(actual)
			}
		} else {
			c.stats.OuterPackets++
			c.stats.PaddingBytes += uint64(len(f.padding))
			switch f.kind {
			case tasmanSource:
				c.stats.SourcePackets++
				used := int(binary.BigEndian.Uint16(f.body))
				c.stats.ZeroTailBytes += uint64(len(f.body) - 2 - used)
			case tasmanRepair:
				c.stats.RepairPackets++
			case tasmanCover:
				c.stats.CoverPackets++
			case tasmanShort:
				c.stats.ShortPackets++
			}
		}
		if c.trace != nil {
			event := TasmanTraceEvent{Remote: s.addr, Session: s.session, Counter: counter, Generation: f.generation, Kind: f.kind, WireBytes: len(wire), Accepted: p.accepted, QUICSent: p.sent, Start: start, End: end}
			if err != nil {
				event.Error = err.Error()
			}
			select {
			case c.trace <- event:
			default:
				c.stats.TraceDrops++
			}
		}
		if err != nil {
			if f.kind == tasmanRepair || f.kind == tasmanCover {
				c.stats.AsyncErrors++
				select {
				case c.errors <- TasmanError{Remote: s.addr, Operation: "control-write", Err: err}:
				default:
					c.stats.AsyncErrorsLost++
					c.fail(ErrTasmanOverflow)
				}
			}
			c.cancel(s, err, "write")
			if !servoPacketError(err) && !c.closed {
				c.fail(err)
			}
		} else {
			var records [tasmanRecordsMax]tasmanRecord
			count := 0
			if f.kind == tasmanSource {
				count, _ = parseTasmanSymbol(f.body, &records)
			} else if f.kind == tasmanShort {
				count, _ = parseTasmanRecords(f.body, &records)
			}
			for i := range count {
				r := records[i]
				m := f.messages[i]
				m.completed += len(r.data)
				if m.completed == len(m.data) {
					delay := uint64(max(0, start.Sub(m.accepted)))
					c.stats.QueueWaitNanos += delay
					c.stats.QueueWaitMaxNanos = max(c.stats.QueueWaitMaxNanos, delay)
					c.release(s, m, nil, "")
				}
			}
			p.pos++
			if p.pos < len(p.frames) {
				delay, e := s.stream.below(int(c.profile.carrier/time.Microsecond)/8 + 1)
				if e != nil {
					c.cancel(s, e, "carrier")
					c.fail(e)
				} else {
					p.due = earlierServo(p.accepted.Add(c.profile.collect), end.Add(time.Duration(delay)*time.Microsecond))
				}
			}
			if p.pos == len(p.frames) {
				s.plan = nil
				if s.queue.Len() == 0 && f.kind != tasmanCover {
					s.tails = c.profile.tails
					s.nextTail = end.Add(c.profile.carrier)
					s.tailUntil = end.Add(time.Duration(c.profile.tails+1) * c.profile.carrier)
				}
			}
		}
		c.signal()
		c.mu.Unlock()
	}
}

func (c *tasmanPacketConn) TasmanStats() TasmanStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.PendingBytes, s.PendingDatagrams, s.Senders = c.bytes, c.items, len(c.senders)
	s.ReceiveSessions, s.Generations, s.SymbolBytes = len(c.rx.peers), c.rx.genOrder.Len(), c.rx.symbolBytes
	s.Assemblies, s.ReassemblyBytes = c.rx.assemblyOrder.Len(), c.rx.assemblyBytes
	s.Receive = c.rx.stats
	for _, p := range c.senders {
		s.ReservedData += p.reserved
		s.ReservedRepair += p.repairReserved
		s.ReservedTiny += p.tinyHeld
		s.Credit += p.credit()
	}
	return s
}
