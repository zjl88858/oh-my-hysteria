// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Opt-in real-clock soak across Presto's ten-minute sender rotation. Uses
// only local UDP sockets. Ordinary CI exercises the exact renewal boundaries
// with TestNetFrontRenewalInFlight instead of waiting ten minutes.
func TestNetFrontLongSocketSoak(t *testing.T) {
	if os.Getenv("OMHY_NETFRONT_SOAK") != "1" {
		t.Skip("manual real-clock loopback soak")
	}
	sr, ports := netfrontTestSockets(t, 3, false)
	cr, _ := netfrontTestSockets(t, 3, false)
	o := NetFrontOptions{[]byte(netfrontTestKey), ports}
	server, err := WrapPacketConnNetFront(sr[0], sr[1:], nil, o)
	require.NoError(t, err)
	defer server.Close()
	client, err := WrapPacketConnNetFront(cr[0], cr[1:], sr[0].LocalAddr().(*net.UDPAddr), o)
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, server.SetDeadline(time.Now().Add(11*time.Minute)))
	serverDone := make(chan error, 1)
	go func() {
		var buf [1200]byte
		for {
			n, a, e := server.ReadFrom(buf[:])
			if e == nil {
				_, e = server.WriteTo(buf[:n], a)
			}
			if e != nil {
				serverDone <- e
				return
			}
		}
	}()
	c, s := client.(*netfrontConn), server.(*netfrontConn)
	cid, sid := map[[16]byte]bool{}, map[[16]byte]bool{}
	destination, _, _ := blinkAddress(server.LocalAddr())
	origin, _, _ := blinkAddress(client.LocalAddr())
	start := time.Now()
	ticker := time.NewTicker(30 * time.Millisecond)
	defer ticker.Stop()
	var n int
	for time.Since(start) < 10*time.Minute+15*time.Second {
		<-ticker.C
		size := []int{16, 32, 96, 1200, 48, 24, 192, 80}[n%8]
		b := bytes.Repeat([]byte{byte(n)}, size)
		binary.BigEndian.PutUint32(b, uint32(n))
		require.NoError(t, c.SetDeadline(time.Now().Add(3*time.Second)))
		_, e := c.WriteTo(b, server.LocalAddr())
		require.NoError(t, e)
		var out [1200]byte
		got, a, e := c.ReadFrom(out[:])
		require.NoError(t, e, "at %d", n)
		require.Equal(t, server.LocalAddr().String(), a.String())
		require.Equal(t, b, out[:got], "at %d", n)
		c.wire.presto.mu.Lock()
		cid[c.wire.presto.senders[destination].session] = true
		c.wire.presto.mu.Unlock()
		s.wire.presto.mu.Lock()
		sid[s.wire.presto.senders[origin].session] = true
		s.wire.presto.mu.Unlock()
		n++
	}
	for _, x := range []*netfrontConn{c, s} {
		stats := x.NetFrontStats()
		require.Zero(t, stats.AuthDrops)
		require.Zero(t, stats.RateDrops)
		for _, lane := range stats.Lanes[1:] {
			require.Greater(t, lane.VerifiedPaths, uint64(15))
		}
		t.Logf("ports: %+v", stats)
	}
	require.GreaterOrEqual(t, len(cid), 2)
	require.GreaterOrEqual(t, len(sid), 2)
	t.Logf("actual duration %s, %d verified echoes, %d client / %d server sender IDs", time.Since(start), n, len(cid), len(sid))
	require.NoError(t, server.Close())
	require.ErrorIs(t, <-serverDone, net.ErrClosed)
}
