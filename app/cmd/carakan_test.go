// SPDX-License-Identifier: MIT-0

package cmd

import (
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
)

func carakanEntropyPointer(h float64) *float64 { return &h }

func TestCarakanConfigurationAndURI(t *testing.T) {
	const password = "carakan-test-only-&=+/Unicode-密码-32+"
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("obfs:\n  type: carakan\n  carakan:\n    password: "+password+"\n    targetEntropy: 4.5\n")))
	var c clientConfig
	require.NoError(t, v.Unmarshal(&c))
	require.Equal(t, password, c.Obfs.Carakan.Password)
	require.Equal(t, 4.5, *c.Obfs.Carakan.TargetEntropy)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()
	c.Obfs.Type = "CARAKAN"
	w, err := c.wrapObfs(pc)
	require.NoError(t, err)
	require.Equal(t, 1200, w.(interface{ QUICPacketSizeLimit() int }).QUICPacketSizeLimit())
	s := serverConfig{Obfs: serverConfigObfs{Type: "carakan", Carakan: c.Obfs.Carakan}}
	_, err = s.wrapObfs(pc)
	require.NoError(t, err)
	c.Server = "example.com:443"
	for _, scheme := range []string{"hysteria2", "hy2"} {
		parsed := clientConfig{Server: strings.Replace(c.URI(), "hysteria2://", scheme+"://", 1)}
		require.True(t, parsed.parseURI())
		require.Equal(t, "carakan", parsed.Obfs.Type)
		require.Equal(t, c.Obfs.Carakan, parsed.Obfs.Carakan)
	}
	u, err := url.Parse(c.URI())
	require.NoError(t, err)
	for _, value := range []string{"", "abc", "0", "0.5", "8", "4.001", "NaN", "+Inf"} {
		q := u.Query()
		q.Set("carakan-target-entropy", value)
		u.RawQuery = q.Encode()
		parsed := clientConfig{Server: u.String()}
		require.True(t, parsed.parseURI())
		_, err := parsed.wrapObfs(pc)
		require.ErrorContains(t, err, "obfs.carakan")
	}
	c.Obfs.Carakan.TargetEntropy = nil
	parsed := clientConfig{Server: c.URI()}
	require.True(t, parsed.parseURI())
	require.Nil(t, parsed.Obfs.Carakan.TargetEntropy)
	_, err = parsed.wrapObfs(pc)
	require.NoError(t, err)
	c.Obfs.Carakan.Password = "short"
	_, err = c.wrapObfs(pc)
	require.ErrorContains(t, err, "obfs.carakan")
	s.Obfs.Carakan.TargetEntropy = carakanEntropyPointer(0)
	_, err = s.wrapObfs(pc)
	require.ErrorContains(t, err, "obfs.carakan")
	c.Server = "127.0.0.1:4000-4001"
	hy := &client.Config{}
	require.NoError(t, c.fillServerAddr(hy))
	require.ErrorContains(t, c.fillConnFactory(hy), "port hopping")
}

func TestCarakanReadmeExample(t *testing.T) {
	data, err := os.ReadFile("../../README.md")
	require.NoError(t, err)
	blocks := regexp.MustCompile("(?s)```yaml\\s*\n(.*?)\n```").FindAllSubmatch(data, -1)
	found := 0
	for _, block := range blocks {
		v := viper.New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader(string(block[1]))))
		if v.GetString("obfs.type") == "carakan" {
			var c clientConfig
			require.NoError(t, v.Unmarshal(&c))
			require.GreaterOrEqual(t, len(c.Obfs.Carakan.Password), 32)
			require.Equal(t, 4.0, *c.Obfs.Carakan.TargetEntropy)
			found++
		}
	}
	require.Equal(t, 1, found)
}
