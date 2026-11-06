// SPDX-License-Identifier: MIT-0

package quic

import (
	"net"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

type reservedTestConn struct {
	net.PacketConn
	allowance int
	sent      time.Time
}

func (*reservedTestConn) QUICWireReservation() bool { return true }
func (c *reservedTestConn) WriteToWithQUICBudget(b []byte, _ net.Addr, sent, _ time.Time, n int) (int, error) {
	c.allowance = n
	c.sent = sent
	return len(b), nil
}
func TestTasmanWireReservationIsOptIn(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()
	r := &reservedTestConn{PacketConn: pc}
	send := newSendConn(&basicConn{PacketConn: r}, pc.LocalAddr(), packetInfo{}, utils.DefaultLogger)
	c := &Conn{conn: send}
	require.Equal(t, protocol.ByteCount(2462), c.reservedPacketCost(1200))
	sent := time.Now().Add(-time.Millisecond)
	require.NoError(t, send.WriteWithQUICSendTime(make([]byte, 1200), 0, protocol.ECNUnsupported, sent))
	require.Equal(t, 2462, r.allowance)
	require.Equal(t, sent, r.sent)
	c.conn = newSendConn(&basicConn{PacketConn: pc}, pc.LocalAddr(), packetInfo{}, utils.DefaultLogger)
	require.Equal(t, protocol.ByteCount(1200), c.reservedPacketCost(1200))
}
