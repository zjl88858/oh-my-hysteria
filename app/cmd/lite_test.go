// SPDX-License-Identifier: MIT-0

package cmd

import (
	"bytes"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/server"
)

func TestLiteModeConfigAndShare(t *testing.T) {
	const pass = "lite-share-test-only-32-bytes+&=密码#"
	options := configObfsNetFront{pass, []int{42003, 42001, 42002}}
	for _, kind := range []string{"prestolite", "netfrontlite"} {
		t.Run(kind, func(t *testing.T) {
			c := clientConfig{Server: "127.0.0.1:41010", Auth: "user:pw", Obfs: clientConfigObfs{
				Type: strings.ToUpper(kind), PrestoLite: configObfsPresto{pass}, NetFrontLite: options,
				Presto: configObfsPresto{"wrong"}, NetFront: configObfsNetFront{"wrong", []int{9, 8}},
			}}
			link, err := url.Parse(c.URI())
			require.NoError(t, err)
			q := link.Query()
			require.Equal(t, kind, q.Get("obfs"))
			require.Equal(t, pass, q.Get("obfs-password"))
			require.False(t, q.Has("netfront-extra-ports"))
			require.Equal(t, kind == "netfrontlite", q.Has("netfrontlite-extra-ports"))
			parsed := clientConfig{Server: link.String()}
			cfg, err := parsed.Config()
			require.NoError(t, err)
			require.Equal(t, c.Auth, parsed.Auth)
			if kind == "netfrontlite" {
				require.Equal(t, options, parsed.Obfs.NetFrontLite)
			} else {
				require.Equal(t, pass, parsed.Obfs.PrestoLite.Password)
			}
			w, err := cfg.ConnFactory.New(cfg.ServerAddr)
			require.NoError(t, err)
			require.Equal(t, 1200, w.(interface{ QUICPacketSizeLimit() int }).QUICPacketSizeLimit())
			require.NoError(t, w.Close())

			parsed.Server = "127.0.0.1:41010-41012"
			_, err = parsed.Config()
			require.ErrorContains(t, err, "obfs."+kind)
			s := serverConfig{Listen: parsed.Server, Obfs: serverConfigObfs{Type: kind}}
			require.ErrorContains(t, s.fillConn(&server.Config{}), "obfs."+kind)
			if kind == "netfrontlite" {
				q.Del("netfrontlite-extra-ports")
				q.Set("netfront-extra-ports", "42003,42001,42002")
				link.RawQuery = q.Encode()
				parsed.Server = link.String()
				_, err = parsed.Config() // must clear the earlier valid list
				require.ErrorContains(t, err, "extraPorts")
				c.Mimic.Enabled = true
				require.ErrorContains(t, c.validateMimic(), "obfs.netfrontlite")
				c.Mimic.Enabled = false
				c.Server = "realm+http://test@127.0.0.1/r"
				_, err = c.Config()
				require.ErrorContains(t, err, "obfs.netfrontlite")
				s.Listen = c.Server
				require.ErrorContains(t, s.fillConn(&server.Config{}), "obfs.netfrontlite")
			}
			// Just the standard section cannot turn on the corresponding Lite mode.
			c.Server = "127.0.0.1:41010"
			c.Obfs.NetFront, c.Obfs.Presto = options, configObfsPresto{pass}
			c.Obfs.NetFrontLite, c.Obfs.PrestoLite = configObfsNetFront{}, configObfsPresto{}
			cfg, err = c.Config()
			if err == nil {
				_, err = cfg.ConnFactory.New(cfg.ServerAddr)
			}
			require.ErrorContains(t, err, "obfs."+kind)
		})
	}
}

func TestLiteReadmeConfigs(t *testing.T) {
	doc, err := os.ReadFile("../../README.md")
	require.NoError(t, err)
	seen := map[string]int{}
	for _, block := range regexp.MustCompile("(?s)```yaml\\s*\n(.*?)\n```").FindAllSubmatch(doc, -1) {
		v := viper.New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(bytes.NewReader(block[1])))
		kind := v.GetString("obfs.type")
		if kind != "prestolite" && kind != "netfrontlite" {
			continue
		}
		var c clientConfig
		var s serverConfig
		require.NoError(t, v.Unmarshal(&c))
		require.NoError(t, v.Unmarshal(&s))
		c.Server = "127.0.0.1:443"
		h, err := c.Config()
		require.NoError(t, err)
		w, err := h.ConnFactory.New(h.ServerAddr)
		require.NoError(t, err)
		require.NoError(t, w.Close())
		if kind == "prestolite" {
			require.Equal(t, c.Obfs.PrestoLite, s.Obfs.PrestoLite)
		} else {
			require.Equal(t, c.Obfs.NetFrontLite, s.Obfs.NetFrontLite)
		}
		seen[kind]++
	}
	require.Equal(t, map[string]int{"prestolite": 1, "netfrontlite": 1}, seen)
}

func TestNetFrontLiteBindRollback(t *testing.T) {
	raw, ports := netfrontLocalGroup(t, "127.0.0.1", 3)
	config := serverConfig{Listen: raw[0].LocalAddr().String(), Obfs: serverConfigObfs{
		Type: "netfrontlite", NetFrontLite: configObfsNetFront{netfrontCLISecret, ports[1:]},
	}}
	require.NoError(t, raw[0].Close())
	require.NoError(t, raw[1].Close())
	require.ErrorContains(t, config.fillConn(&server.Config{}), "obfs.netfrontlite")
	// Prove both sockets opened prior to the conflict were released.
	for _, pc := range raw[:2] {
		rebound, err := net.ListenUDP("udp4", pc.LocalAddr().(*net.UDPAddr))
		require.NoError(t, err)
		require.NoError(t, rebound.Close())
	}
}
