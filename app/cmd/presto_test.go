// SPDX-License-Identifier: MIT-0

package cmd

import (
	"net"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
)

func TestPrestoConfigurationAndURI(t *testing.T) {
	const password = "presto-config-test-only-password-32+"
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("obfs:\n  type: presto\n  presto:\n    password: "+password)))
	var c clientConfig
	require.NoError(t, v.Unmarshal(&c))
	require.Equal(t, password, c.Obfs.Presto.Password)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()
	c.Obfs.Type = "PRESTO"
	w, err := c.wrapObfs(pc)
	require.NoError(t, err)
	require.Equal(t, 1200, w.(interface{ QUICPacketSizeLimit() int }).QUICPacketSizeLimit())
	s := serverConfig{Obfs: serverConfigObfs{Type: "presto", Presto: c.Obfs.Presto}}
	_, err = s.wrapObfs(pc)
	require.NoError(t, err)
	c.Server = "example.com:443"
	var parsed clientConfig
	parsed.Server = c.URI()
	require.True(t, parsed.parseURI())
	require.Equal(t, "presto", parsed.Obfs.Type)
	require.Equal(t, password, parsed.Obfs.Presto.Password)
	c.Obfs.Presto.Password = "short"
	_, err = c.wrapObfs(pc)
	require.ErrorContains(t, err, "obfs.presto")
	s.Obfs.Presto.Password = "short"
	_, err = s.wrapObfs(pc)
	require.ErrorContains(t, err, "obfs.presto")
	c.Server = "127.0.0.1:4000-4001"
	hy := &client.Config{}
	require.NoError(t, c.fillServerAddr(hy))
	require.ErrorContains(t, c.fillConnFactory(hy), "port hopping")
}

func TestPrestoReadmeExample(t *testing.T) {
	data, err := os.ReadFile("../../README.md")
	require.NoError(t, err)
	blocks := regexp.MustCompile("(?s)```yaml\\s*\n(.*?)\n```").FindAllSubmatch(data, -1)
	found := 0
	for _, block := range blocks {
		v := viper.New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader(string(block[1]))))
		if v.GetString("obfs.type") == "presto" {
			var c clientConfig
			require.NoError(t, v.Unmarshal(&c))
			require.GreaterOrEqual(t, len(c.Obfs.Presto.Password), 32)
			found++
		}
	}
	require.Equal(t, 1, found)
}
