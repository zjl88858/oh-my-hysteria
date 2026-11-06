package quic

import (
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	SendProbe(*packetBuffer, net.Addr, packetInfo)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type queueEntry struct {
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
	sentAt  time.Time
}

type sendQueue struct {
	pending     atomic.Int64
	onIdle      func()
	queue       chan queueEntry
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}
	conn        sendConn
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	h.SendAt(p, gsoSize, ecn, time.Time{})
}

func (h *sendQueue) SendAt(p *packetBuffer, gsoSize uint16, ecn protocol.ECN, sent time.Time) {
	h.pending.Add(1)
	select {
	case h.queue <- queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn, sentAt: sent}:
		// clear available channel if we've reached capacity
		if len(h.queue) == sendQueueCapacity {
			select {
			case <-h.available:
			default:
			}
		}
	case <-h.runStopped:
		h.pending.Add(-1)
	default:
		h.pending.Add(-1)
		panic("sendQueue.Send would have blocked")
	}
}

func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr, info packetInfo) {
	h.conn.WriteTo(p.Data, addr, info)
}

func (h *sendQueue) WouldBlock() bool {
	return len(h.queue) == sendQueueCapacity
}

func (h *sendQueue) Available() <-chan struct{} {
	return h.available
}

func (h *sendQueue) Run() error {
	defer close(h.runStopped)
	var shouldClose bool
	for {
		if shouldClose && len(h.queue) == 0 {
			return nil
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// make sure that all queued packets are actually sent out
			shouldClose = true
		case e := <-h.queue:
			var err error
			if timed, ok := h.conn.(interface {
				WriteWithQUICSendTime([]byte, uint16, protocol.ECN, time.Time) error
			}); ok && !e.sentAt.IsZero() {
				err = timed.WriteWithQUICSendTime(e.buf.Data, e.gsoSize, e.ecn, e.sentAt)
			} else {
				err = h.conn.Write(e.buf.Data, e.gsoSize, e.ecn)
			}
			if err != nil {
				// This additional check enables:
				// 1. Checking for "datagram too large" message from the kernel, as such,
				// 2. Path MTU discovery,and
				// 3. Eventual detection of loss PingFrame.
				var tooLarge *DatagramTooLargeError
				if !isSendMsgSizeErr(err) && !errors.As(err, &tooLarge) {
					return err
				}
			}
			e.buf.Release()
			if h.pending.Add(-1) == 0 && h.onIdle != nil {
				h.onIdle()
			}
			select {
			case h.available <- struct{}{}:
			default:
			}
		}
	}
}

func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
