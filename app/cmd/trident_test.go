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

func TestTridentConfigurationAndURI(t *testing.T) {
	const password = "trident-test-only-&=+/Unicode-密码-32+"
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("obfs:\n  type: trident\n  trident:\n    password: "+password)))
	var c clientConfig
	require.NoError(t, v.Unmarshal(&c))
	require.Equal(t, password, c.Obfs.Trident.Password)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()
	c.Obfs.Type = "TRIDENT"
	w, err := c.wrapObfs(pc)
	require.NoError(t, err)
	require.Equal(t, 1200, w.(interface{ QUICPacketSizeLimit() int }).QUICPacketSizeLimit())
	s := serverConfig{Obfs: serverConfigObfs{Type: "trident", Trident: c.Obfs.Trident}}
	_, err = s.wrapObfs(pc)
	require.NoError(t, err)
	c.Server = "example.com:443"
	for _, scheme := range []string{"hysteria2", "hy2"} {
		parsed := clientConfig{Server: strings.Replace(c.URI(), "hysteria2://", scheme+"://", 1)}
		require.True(t, parsed.parseURI())
		require.Equal(t, "trident", parsed.Obfs.Type)
		require.Equal(t, password, parsed.Obfs.Trident.Password)
	}
	c.Obfs.Trident.Password = "short"
	_, err = c.wrapObfs(pc)
	require.ErrorContains(t, err, "obfs.trident")
	s.Obfs.Trident.Password = "short"
	_, err = s.wrapObfs(pc)
	require.ErrorContains(t, err, "obfs.trident")
	c.Server = "127.0.0.1:4000-4001"
	hy := &client.Config{}
	require.NoError(t, c.fillServerAddr(hy))
	require.ErrorContains(t, c.fillConnFactory(hy), "port hopping")
}

func TestTridentReadmeExample(t *testing.T) {
	data, err := os.ReadFile("../../README.md")
	require.NoError(t, err)
	blocks := regexp.MustCompile("(?s)```yaml\\s*\n(.*?)\n```").FindAllSubmatch(data, -1)
	found := 0
	for _, block := range blocks {
		v := viper.New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader(string(block[1]))))
		if v.GetString("obfs.type") == "trident" {
			var c clientConfig
			require.NoError(t, v.Unmarshal(&c))
			require.GreaterOrEqual(t, len(c.Obfs.Trident.Password), 32)
			found++
		}
	}
	require.Equal(t, 1, found)
}
