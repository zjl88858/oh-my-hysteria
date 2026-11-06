// SPDX-License-Identifier: MIT-0

package obfs

import (
	"container/list"
	"time"
)

type servoMessage struct {
	id                   uint32
	data                 []byte
	accepted, quicSent   time.Time
	planned, sent, parts int
	elem                 *list.Element
}

type servoTxRecord struct {
	message *servoMessage
	offset  int
	size    int
}

type servoContainer struct {
	records  [servoRecordsMax]servoTxRecord
	count    int
	data     int
	capacity int
	due      time.Time
	ready    bool
}

// The next capacity is drawn ONCE, including when reservation fails. Only
// the send owner mutates a packer. Message buffers remain owned until every
// fragment is written or the message is explicitly failed/cancelled.
type servoPacker struct {
	current *servoContainer
	next    int
	sample  func() (int, error)
	wait    time.Duration
}

func (p *servoPacker) fill(queue *list.List) error {
	for e := queue.Front(); e != nil; e = e.Next() {
		m := e.Value.(*servoMessage)
		if m.planned == len(m.data) {
			continue
		}
		if p.current == nil {
			capacity := p.next
			if capacity == 0 {
				var err error
				capacity, err = p.sample()
				if err != nil {
					return err
				}
			}
			p.next = 0
			p.current = &servoContainer{capacity: capacity, due: m.accepted.Add(p.wait)}
		}
		c := p.current
		if c.ready {
			return nil
		}
		left, remaining := c.capacity-c.data, len(m.data)-m.planned
		if remaining > left {
			if p.next == 0 {
				var err error
				p.next, err = p.sample()
				if err != nil {
					return err
				}
			}
			if m.planned > 0 || remaining > left+p.next {
				// Not even two containers can cover this message at this
				// position. Flush old data; don't take a tiny first slice.
				c.ready = true
				return nil
			}
		}
		n := min(remaining, left)
		c.records[c.count] = servoTxRecord{message: m, offset: m.planned, size: n}
		c.count++
		c.data += n
		m.planned += n
		m.parts++
		if due := m.accepted.Add(p.wait); due.Before(c.due) {
			c.due = due
		}
		if c.data == c.capacity || c.count == servoRecordsMax {
			c.ready = true
			return nil
		}
	}
	return nil
}

func (p *servoPacker) take(now time.Time) *servoContainer {
	c := p.current
	if c == nil || c.count == 0 || (!c.ready && now.Before(c.due)) {
		return nil
	}
	p.current = nil
	return c
}
