// SPDX-License-Identifier: MIT-0

package pmtud

import (
	"net"
	"testing"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/require"
)

type framedTestConn struct {
	net.PacketConn
	size int
}

func (c framedTestConn) QUICPacketSizeLimit() int { return c.size }
func TestPacketConnLimitsAreOptIn(t *testing.T) {
	conf := &quic.Config{InitialPacketSize: 1350, ChromeParrot: true}
	require.False(t, ApplyPacketConnLimit(nil, conf))
	require.EqualValues(t, 1350, conf.InitialPacketSize)
	require.True(t, conf.ChromeParrot)
	require.False(t, conf.DisablePathMTUDiscovery)
	require.True(t, ApplyPacketConnLimit(framedTestConn{size: 1200}, conf))
	require.EqualValues(t, 1200, conf.InitialPacketSize)
	require.False(t, conf.ChromeParrot)
	require.True(t, conf.DisablePathMTUDiscovery)
	require.Panics(t, func() { ApplyPacketConnLimit(framedTestConn{size: 1000}, conf) })
}
