// SPDX-License-Identifier: MIT-0

package cmd

import (
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
)

func TestServoConfigurationAndURI(t *testing.T) {
	const password = "servo-config-public-&=+/密码-32-byte-test"
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("obfs:\n  type: servo\n  servo:\n    password: "+password)))
	var c clientConfig
	require.NoError(t, v.Unmarshal(&c))
	require.Equal(t, password, c.Obfs.Servo.Password)
	c.Server = "example.com:443"
	c.Obfs.Type = "SeRvO"
	var parsed clientConfig
	parsed.Server = c.URI()
	require.True(t, parsed.parseURI())
	require.Equal(t, "servo", parsed.Obfs.Type)
	require.Equal(t, password, parsed.Obfs.Servo.Password)
	for _, server := range []bool{false, true} {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		var wrapped net.PacketConn
		if server {
			s := serverConfig{Obfs: serverConfigObfs{Type: "SERVO", Servo: c.Obfs.Servo}}
			wrapped, err = s.wrapObfs(pc)
		} else {
			wrapped, err = c.wrapObfs(pc)
		}
		require.NoError(t, err)
		require.Equal(t, 1200, wrapped.(interface{ QUICPacketSizeLimit() int }).QUICPacketSizeLimit())
		_, oob := wrapped.(quic.OOBCapablePacketConn)
		require.False(t, oob)
		require.NoError(t, wrapped.Close())
	}
	for _, password := range []string{"", "short", strings.Repeat("x", 1025)} {
		c.Obfs.Servo.Password = password
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		_, err = c.wrapObfs(pc)
		require.ErrorContains(t, err, "obfs.servo")
		s := serverConfig{Obfs: serverConfigObfs{Type: "servo", Servo: c.Obfs.Servo}}
		_, err = s.wrapObfs(pc)
		require.ErrorContains(t, err, "obfs.servo")
		pc.Close()
	}
	c.Server = "127.0.0.1:4000-4001"
	hy := &client.Config{}
	require.NoError(t, c.fillServerAddr(hy))
	require.ErrorContains(t, c.fillConnFactory(hy), "port hopping")
}

func TestServoReadmeExample(t *testing.T) {
	data, err := os.ReadFile("../../README.md")
	require.NoError(t, err)
	blocks := regexp.MustCompile("(?s)```yaml\\s*\n(.*?)\n```").FindAllSubmatch(data, -1)
	found := 0
	for _, block := range blocks {
		v := viper.New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader(string(block[1]))))
		if v.GetString("obfs.type") == "servo" {
			var c clientConfig
			require.NoError(t, v.Unmarshal(&c))
			require.GreaterOrEqual(t, len(c.Obfs.Servo.Password), 32)
			found++
		}
	}
	require.Equal(t, 1, found)
}

type servoTimedCleanupTestConn struct {
	net.PacketConn
	seen time.Time
}

func (c *servoTimedCleanupTestConn) WriteToWithQUICSendTime(p []byte, _ net.Addr, t time.Time) (int, error) {
	c.seen = t
	return len(p), nil
}

func TestServoCleanupPreservesLimitAndTiming(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	timed := &servoTimedCleanupTestConn{PacketConn: pc}
	cleaned := false
	c := &limitedCleanupPacketConn{cleanupPacketConn: &cleanupPacketConn{PacketConn: timed, cleanup: func() { cleaned = true }}, limit: 1200}
	sent := time.Now()
	_, err = c.WriteToWithQUICSendTime([]byte{1}, pc.LocalAddr(), sent)
	require.NoError(t, err)
	require.Equal(t, sent, timed.seen)
	require.Equal(t, 1200, c.QUICPacketSizeLimit())
	_, oob := any(c).(quic.OOBCapablePacketConn)
	require.False(t, oob)
	require.NoError(t, c.Close())
	require.True(t, cleaned)
}
