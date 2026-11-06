// SPDX-License-Identifier: MIT-0

package quic

import (
	"net"
	"time"

	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
)

// Conservative opt-in reservation, NOT an outer-packet ACK estimator. Charging
// the full ceiling to flight and pacing prevents FEC/cover from free-riding on
// inner-byte pacing. Coalesced QUIC packets over-reserve (safe), never undercharge.
func (c *Conn) reservedPacketCost(n protocol.ByteCount) protocol.ByteCount {
	if send, ok := c.conn.(*sconn); ok {
		if raw, ok := send.rawConn.(*basicConn); ok {
			if reporter, ok := raw.PacketConn.(interface{ QUICOuterRecovery(net.Addr) uint64 }); ok {
				n := reporter.QUICOuterRecovery(send.RemoteAddr())
				if n > c.outerRecoveries {
					c.outerRecoveries = n
					if h, ok := c.sentPacketHandler.(interface{ ObserveOuterRecovery(monotime.Time) }); ok {
						h.ObserveOuterRecovery(monotime.Now())
					}
				}
			}
			if framed, ok := raw.PacketConn.(interface{ QUICWireReservation() bool }); ok && framed.QUICWireReservation() {
				return 2*n + 62
			}
		}
	}
	return n
}

type wireReservedPacketConn interface {
	QUICWireReservation() bool
	WriteToWithQUICBudget([]byte, net.Addr, time.Time, time.Time, int) (int, error)
}
