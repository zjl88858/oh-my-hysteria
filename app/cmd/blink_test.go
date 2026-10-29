// SPDX-License-Identifier: MIT-0

package cmd

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
)

func blinkTestInt(n int) *int { return &n }
func blinkConfigFixture() configObfsBlink {
	return configObfsBlink{Password: "blink-test-only-secret", MaxPacketSize: 1232, PaddingMax: blinkTestInt(24), JunkPackets: blinkTestInt(1), Fragmentation: true, MaxSessions: 128, MaxReassemblyBytes: 65536, VerifyPacketsPerSecond: 4096}
}

func TestBlinkConfiguration(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()
	c := &clientConfig{Obfs: clientConfigObfs{Type: "BLINK", Blink: blinkConfigFixture()}}
	w, err := c.wrapObfs(pc)
	require.NoError(t, err)
	require.Equal(t, 1200, w.(interface{ QUICPacketSizeLimit() int }).QUICPacketSizeLimit())
	s := &serverConfig{Obfs: serverConfigObfs{Type: "blink", Blink: blinkConfigFixture()}}
	_, err = s.wrapObfs(pc)
	require.ErrorContains(t, err, "obfs.blink")
	s.Obfs.Blink.JunkPackets = blinkTestInt(0)
	_, err = s.wrapObfs(pc)
	require.NoError(t, err)
	c.Obfs.Blink.Password = "short"
	_, err = c.wrapObfs(pc)
	require.ErrorContains(t, err, "obfs.blink")
	c.Server = "127.0.0.1:4000-4001"
	hy := &client.Config{}
	require.NoError(t, c.fillServerAddr(hy))
	require.ErrorContains(t, c.fillConnFactory(hy), "port hopping")
}

func TestBlinkURIRoundTrip(t *testing.T) {
	c := &clientConfig{Server: "example.com:443", Obfs: clientConfigObfs{Type: "blink", Blink: blinkConfigFixture()}}
	var parsed clientConfig
	parsed.Server = c.URI()
	require.True(t, parsed.parseURI())
	require.Equal(t, "blink", parsed.Obfs.Type)
	require.Equal(t, c.Obfs.Blink.Password, parsed.Obfs.Blink.Password)
	require.Equal(t, c.Obfs.Blink.Fragmentation, parsed.Obfs.Blink.Fragmentation)
	require.Equal(t, c.Obfs.Blink.MaxPacketSize, parsed.Obfs.Blink.MaxPacketSize)
	require.Equal(t, c.Obfs.Blink.PaddingMax, parsed.Obfs.Blink.PaddingMax)
	require.Equal(t, c.Obfs.Blink.JunkPackets, parsed.Obfs.Blink.JunkPackets)
	parsed.Server = "hysteria2://example.com/?obfs=blink&obfs-password=blink-test-only-secret&blink-max-packet-size=bad&blink-padding-max=bad&blink-junk-packets=bad"
	require.True(t, parsed.parseURI())
	require.Equal(t, -1, parsed.Obfs.Blink.MaxPacketSize)
	require.Equal(t, -1, *parsed.Obfs.Blink.PaddingMax)
	require.Equal(t, -1, *parsed.Obfs.Blink.JunkPackets)
}
