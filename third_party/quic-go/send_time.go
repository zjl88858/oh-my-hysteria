// SPDX-License-Identifier: MIT-0

package quic

import (
	"io"
	"net"
	"time"

	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
)

// Observation only. Keep SentPacket's exact timestamp through the queue for
// opt-in asynchronous PacketConns. No RTT/CC accounting is silently rewritten.
func (c *Conn) enqueuePacket(buf *packetBuffer, gso uint16, ecn protocol.ECN, sent monotime.Time) {
	c.observeAsyncTransport(false)
	if queue, ok := c.sendQueue.(interface {
		SendAt(*packetBuffer, uint16, protocol.ECN, time.Time)
	}); ok {
		queue.SendAt(buf, gso, ecn, sent.ToTime())
		return
	}
	c.sendQueue.Send(buf, gso, ecn)
}

func (c *Conn) observeAsyncTransport(probe bool) {
	if send, ok := c.conn.(*sconn); ok {
		if raw, ok := send.rawConn.(*basicConn); ok {
			if observer, ok := raw.PacketConn.(interface {
				QUICTransportMetrics(net.Addr, time.Duration, time.Duration, uint64, bool)
			}); ok {
				observer.QUICTransportMetrics(send.RemoteAddr(), c.rttStats.LatestRTT(), c.rttStats.PTO(true), c.connStats.PacketsLost.Load(), probe)
			}
		}
	}
}

func (c *sconn) WriteWithQUICSendTime(b []byte, gso uint16, ecn protocol.ECN, sent time.Time) error {
	if basic, ok := c.rawConn.(*basicConn); ok && gso == 0 && ecn == protocol.ECNUnsupported {
		if reserved, ok := basic.PacketConn.(wireReservedPacketConn); ok && reserved.QUICWireReservation() {
			n, err := reserved.WriteToWithQUICBudget(b, c.RemoteAddr(), sent, time.Now(), 2*len(b)+62)
			if err == nil && n != len(b) {
				return io.ErrShortWrite
			}
			return err
		}
		if timed, ok := basic.PacketConn.(interface {
			WriteToWithQUICSendTime([]byte, net.Addr, time.Time) (int, error)
		}); ok {
			n, err := timed.WriteToWithQUICSendTime(b, c.RemoteAddr(), sent)
			if err == nil && n != len(b) {
				return io.ErrShortWrite
			}
			return err
		}
	}
	return c.Write(b, gso, ecn)
}
