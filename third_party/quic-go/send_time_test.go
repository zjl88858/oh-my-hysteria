// SPDX-License-Identifier: MIT-0

package quic

import (
	"net"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type timedTestPacketConn struct {
	net.PacketConn
	when time.Time
	data []byte
}

func (c *timedTestPacketConn) WriteToWithQUICSendTime(b []byte, _ net.Addr, at time.Time) (int, error) {
	c.when, c.data = at, append([]byte(nil), b...)
	return len(b), nil
}

func TestAsyncPacketConnSendTimeObservation(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()
	timed := &timedTestPacketConn{PacketConn: pc}
	c := newSendConn(&basicConn{PacketConn: timed}, pc.LocalAddr(), packetInfo{}, utils.DefaultLogger)
	now := time.Now().Add(-time.Second)
	require.NoError(t, c.WriteWithQUICSendTime([]byte("exact-buffer"), 0, protocol.ECNUnsupported, now))
	require.Equal(t, now, timed.when)
	require.Equal(t, []byte("exact-buffer"), timed.data)
}

type timedMockSendConn struct {
	*MockSendConn
	observed chan time.Time
}

func (c *timedMockSendConn) WriteWithQUICSendTime(_ []byte, _ uint16, _ protocol.ECN, at time.Time) error {
	c.observed <- at
	return nil
}

func TestSendQueuePreservesRegistrationTime(t *testing.T) {
	ctrl := gomock.NewController(t)
	c := &timedMockSendConn{MockSendConn: NewMockSendConn(ctrl), observed: make(chan time.Time, 1)}
	q := newSendQueue(c).(*sendQueue)
	done := make(chan error, 1)
	go func() { done <- q.Run() }()
	sent := time.Now().Add(-time.Second)
	q.SendAt(getPacketWithContents([]byte("queued-data")), 0, protocol.ECNUnsupported, sent)
	select {
	case got := <-c.observed:
		require.Equal(t, sent, got)
	case <-time.After(time.Second):
		t.Fatal("observation missing")
	}
	q.Close()
	require.NoError(t, <-done)
}
