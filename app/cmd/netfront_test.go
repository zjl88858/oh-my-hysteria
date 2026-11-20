// SPDX-License-Identifier: MIT-0

package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
	"github.com/zjl88858/oh-my-hysteria/core/v2/server"
	"github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"
)

const netfrontCLISecret = "netfront-public-test-密码-32-bytes+&=%"

func TestNetFrontConfigurationAndURI(t *testing.T) {
	cfg := configObfsNetFront{netfrontCLISecret, []int{41012, 41011}}
	c := clientConfig{Server: "[::1]:41010", Auth: "user:pw", Obfs: clientConfigObfs{Type: "NeTfRoNt", NetFront: cfg}}
	var parsed clientConfig
	parsed.Server = c.URI()
	h, err := parsed.Config()
	require.NoError(t, err)
	require.Equal(t, "[::1]:41010", h.ServerAddr.String())
	require.Equal(t, cfg, parsed.Obfs.NetFront)
	require.Equal(t, c.Auth, parsed.Auth)
	for _, bad := range []string{"", "&netfront-extra-ports=1", "&netfront-extra-ports=41010,3", "&netfront-extra-ports=5,5", "&netfront-extra-ports=1,2,3,4", "&netfront-extra-ports=1,65536", "&netfront-extra-ports=9-11,12", "&netfront-extra-ports=3,4&netfront-extra-ports=5,6"} {
		c2 := c
		c2.Server = "hy2://127.0.0.1:41010/?obfs=netfront&obfs-password=public-32-bytes-for-configuration-checks" + bad
		_, err := c2.Config()
		require.ErrorContains(t, err, "extraPorts", bad)
	}
	c.Obfs.NetFront.Password = "short"
	_, err = c.Config()
	require.ErrorContains(t, err, "password")
	c.Obfs.NetFront = cfg
	for _, addr := range []string{"127.0.0.1:0", "127.0.0.1:41010-41012", "realm+http://test@127.0.0.1/r"} {
		c.Server = addr
		_, err = c.Config()
		require.ErrorContains(t, err, "obfs.netfront")
	}
	c.Server = "127.0.0.1:41010"
	c.Mimic.Enabled = true
	_, err = c.Config()
	require.ErrorContains(t, err, "Mimic")
	uri := c.URI()
	v := clientConfig{Server: uri, Mimic: mimicConfig{Enabled: true}}
	require.ErrorContains(t, v.validateMimic(), "Mimic")
	for _, ports := range []string{"[true, 80]", "[41012.75, 80]", "[-1, 80]", "[65536, 80]"} {
		vp := viper.New()
		vp.SetConfigType("yaml")
		require.NoError(t, vp.ReadConfig(strings.NewReader("obfs:\n  type: netfront\n  netfront:\n    extraPorts: "+ports)))
		var c2 clientConfig
		require.ErrorContains(t, vp.Unmarshal(&c2), "extraPorts")
	}
	for _, addr := range []string{"127.0.0.1:41010,41015", "127.0.0.1:0", "realm+http://test@127.0.0.1/r"} {
		s := serverConfig{Listen: addr, Obfs: serverConfigObfs{Type: "NETFRONT", NetFront: cfg}}
		require.ErrorContains(t, s.fillConn(&server.Config{}), "obfs.netfront")
	}
}

func TestNetFrontReadmeExample(t *testing.T) {
	doc, err := os.ReadFile("../../README.md")
	require.NoError(t, err)
	var found int
	for _, block := range regexp.MustCompile("(?s)```yaml\\s*\n(.*?)\n```").FindAllSubmatch(doc, -1) {
		v := viper.New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(bytes.NewReader(block[1])))
		if v.GetString("obfs.type") != "netfront" {
			continue
		}
		var c clientConfig
		var s serverConfig
		require.NoError(t, v.Unmarshal(&c))
		require.NoError(t, v.Unmarshal(&s))
		require.Equal(t, s.Obfs.NetFront, c.Obfs.NetFront)
		c.Server = "127.0.0.1:443"
		_, err = c.Config()
		require.NoError(t, err)
		found++
	}
	require.Equal(t, 1, found)
}

// Reserve an entire group at once so a kernel-selected port isn't reused
// within a test. CLI listeners are fixed ports, not :0 wildcard allocations.
func netfrontLocalGroup(t *testing.T, host string, count int) ([]net.PacketConn, []int) {
	t.Helper()
	network := "udp4"
	if host == "::1" {
		network = "udp6"
	}
	var sockets []net.PacketConn
	var ports []int
	for range count {
		pc, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
		if err != nil && network == "udp6" && len(sockets) == 0 {
			t.Skipf("no IPv6 loopback: %v", err)
		}
		require.NoError(t, err)
		t.Cleanup(func() { pc.Close() })
		sockets = append(sockets, pc)
		ports = append(ports, pc.LocalAddr().(*net.UDPAddr).Port)
	}
	return sockets, ports
}

func TestNetFrontBindRollback(t *testing.T) {
	res, ports := netfrontLocalGroup(t, "127.0.0.1", 4)
	cfg := serverConfig{Listen: res[0].LocalAddr().String(), Obfs: serverConfigObfs{Type: "netfront", NetFront: configObfsNetFront{netfrontCLISecret, ports[1:]}}}
	for _, s := range res[:3] {
		require.NoError(t, s.Close())
	}
	hy := &server.Config{}
	require.ErrorContains(t, cfg.fillConn(hy), strconv.Itoa(ports[3]))
	require.Nil(t, hy.Conn)
	require.NoError(t, res[3].Close())
	// A later TLS configuration failure must also release the whole group.
	_, err := cfg.Config()
	require.Error(t, err)
	require.NoError(t, cfg.fillConn(hy))
	require.NoError(t, hy.Conn.Close())
}

func TestNetFrontTLSAndTransfer(t *testing.T) {
	cert, roots := carakanDiagnosticCertificate(t)
	for _, tc := range []struct {
		host, kind string
		lanes      int
	}{{"127.0.0.1", "netfront", 3}, {"::1", "netfront", 2}, {"127.0.0.1", "netfrontlite", 2}, {"127.0.0.1", "netfrontlite", 3}} {
		t.Run(fmt.Sprintf("%s-%s-%d", tc.host, tc.kind, tc.lanes), func(t *testing.T) {
			res, ports := netfrontLocalGroup(t, tc.host, tc.lanes+1)
			listen := res[0].LocalAddr().String()
			for _, r := range res {
				require.NoError(t, r.Close())
			}
			cfg := configObfsNetFront{netfrontCLISecret, ports[1:]}
			sc := serverConfig{Listen: listen, Obfs: serverConfigObfs{Type: tc.kind}}
			cc := clientConfig{Server: listen, Auth: "test-only-auth", Obfs: clientConfigObfs{Type: tc.kind}, TLS: clientConfigTLS{SNI: "localhost"}}
			if tc.kind == "netfrontlite" {
				sc.Obfs.NetFrontLite, cc.Obfs.NetFrontLite = cfg, cfg
			} else {
				sc.Obfs.NetFront, cc.Obfs.NetFront = cfg, cfg
			}
			hy := &server.Config{TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{cert}}, Authenticator: geckoTestAuth{}}
			require.NoError(t, sc.fillConn(hy))
			_, oob := hy.Conn.(quic.OOBCapablePacketConn)
			require.False(t, oob)
			require.Equal(t, 1200, hy.Conn.(interface{ QUICPacketSizeLimit() int }).QUICPacketSizeLimit())
			srv, err := server.NewServer(hy)
			require.NoError(t, err)
			defer srv.Close()
			go srv.Serve()
			shared := clientConfig{Server: cc.URI()}
			ch, err := shared.Config()
			require.NoError(t, err)
			ch.TLSConfig.RootCAs = roots
			proxy, _, err := client.NewClient(ch)
			require.NoError(t, err)
			defer proxy.Close()

			tcp, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer tcp.Close()
			go func() {
				c, e := tcp.Accept()
				if e == nil {
					defer c.Close()
					c.SetDeadline(time.Now().Add(15 * time.Second))
					io.Copy(c, c)
				}
			}()
			stream, err := proxy.TCP(tcp.Addr().String())
			require.NoError(t, err)
			defer stream.Close()
			require.NoError(t, stream.SetDeadline(time.Now().Add(15*time.Second)))
			b := make([]byte, 64<<10)
			rand.Read(b)
			result := make(chan error, 1)
			go func() { _, e := stream.Write(b); result <- e }()
			got := make([]byte, len(b))
			_, err = io.ReadFull(stream, got)
			require.NoError(t, err)
			require.NoError(t, <-result)
			require.Equal(t, b, got)
			udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer udp.Close()
			go func() {
				var buf [1200]byte
				for {
					n, a, e := udp.ReadFrom(buf[:])
					if e != nil {
						return
					}
					udp.WriteTo(buf[:n], a)
				}
			}()
			us, err := proxy.UDP()
			require.NoError(t, err)
			defer us.Close()
			go func() {
				for i := range 32 {
					b := bytes.Repeat([]byte{byte(i)}, 11+i*11)
					if e := us.Send(b, udp.LocalAddr().String()); e != nil {
						result <- e
						return
					}
					got, _, e := us.Receive()
					if e != nil {
						result <- e
						return
					}
					if !bytes.Equal(b, got) {
						result <- fmt.Errorf("bad UDP echo %d", i)
						return
					}
				}
				result <- nil
			}()
			select {
			case err = <-result:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("proxy UDP timeout")
			}
			stats := hy.Conn.(interface{ NetFrontStats() obfs.NetFrontStats }).NetFrontStats()
			t.Logf("TLS/TCP/UDP %s: %+v", tc.host, stats)
		})
	}
}
