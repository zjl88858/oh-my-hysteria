// SPDX-License-Identifier: MIT-0

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
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

type marinerIntegrationFactory struct {
	network, listen string
	server, loss    bool
	conn            net.PacketConn
	raw             *servoObservedSocket
}

func (f *marinerIntegrationFactory) New(net.Addr) (net.PacketConn, error) {
	pc, e := net.ListenPacket(f.network, f.listen)
	if e != nil {
		return nil, e
	}
	f.raw = &servoObservedSocket{UDPConn: pc.(*net.UDPConn), dropFirst: f.loss}
	f.conn, e = obfs.WrapPacketConnMariner(f.raw, obfs.MarinerOptions{Password: []byte("mariner-integration-public-password-32+"), Server: f.server})
	if e != nil {
		pc.Close()
	}
	return f.conn, e
}

func TestMarinerConfigurationAndURI(t *testing.T) {
	const password = "mariner-config-public-&=+/密码-32-byte-test"
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("obfs:\n  type: MaRiNeR\n  mariner:\n    password: "+password)))
	var c clientConfig
	require.NoError(t, v.Unmarshal(&c))
	require.Equal(t, password, c.Obfs.Mariner.Password)
	c.Server = "example.com:443"
	var parsed clientConfig
	parsed.Server = c.URI()
	require.True(t, parsed.parseURI())
	require.Equal(t, "mariner", parsed.Obfs.Type)
	require.Equal(t, password, parsed.Obfs.Mariner.Password)
	for _, isServer := range []bool{false, true} {
		pc, e := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, e)
		var w net.PacketConn
		if isServer {
			s := serverConfig{Obfs: serverConfigObfs{Type: "MARINER", Mariner: c.Obfs.Mariner}}
			w, e = s.wrapObfs(pc)
		} else {
			w, e = c.wrapObfs(pc)
		}
		require.NoError(t, e)
		require.Equal(t, 1200, w.(interface{ QUICPacketSizeLimit() int }).QUICPacketSizeLimit())
		_, oob := w.(quic.OOBCapablePacketConn)
		require.False(t, oob)
		require.NoError(t, w.Close())
	}
	for _, password := range []string{"", "short", strings.Repeat("x", 1025)} {
		c.Obfs.Mariner.Password = password
		pc, e := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, e)
		_, e = c.wrapObfs(pc)
		require.ErrorContains(t, e, "obfs.mariner")
		s := serverConfig{Obfs: serverConfigObfs{Type: "mariner", Mariner: c.Obfs.Mariner}}
		_, e = s.wrapObfs(pc)
		require.ErrorContains(t, e, "obfs.mariner")
		pc.Close()
	}
	c.Server = "127.0.0.1:4000-4001"
	hy := &client.Config{}
	require.NoError(t, c.fillServerAddr(hy))
	require.ErrorContains(t, c.fillConnFactory(hy), "port hopping")
}

func TestMarinerTLSAndTransfer(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, e)
	cert, e := x509.ParseCertificate(der)
	require.NoError(t, e)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, tc := range []struct {
		name, network, listen string
		loss                  bool
	}{{"ipv4", "udp4", "127.0.0.1:0", false}, {"ipv6", "udp6", "[::1]:0", false}, {"initial-loss", "udp4", "127.0.0.1:0", true}} {
		t.Run(tc.name, func(t *testing.T) {
			sf := &marinerIntegrationFactory{network: tc.network, listen: tc.listen, server: true}
			pc, e := sf.New(nil)
			if tc.network == "udp6" && e != nil {
				t.Skipf("IPv6 unavailable: %v", e)
			}
			require.NoError(t, e)
			srv, e := server.NewServer(&server.Config{Conn: pc, Authenticator: geckoTestAuth{}, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, IgnoreClientBandwidth: true})
			require.NoError(t, e)
			defer srv.Close()
			go srv.Serve()
			cf := &marinerIntegrationFactory{network: tc.network, listen: tc.listen, loss: tc.loss}
			c, _, e := client.NewClient(&client.Config{ConnFactory: cf, ServerAddr: pc.LocalAddr(), Auth: "test-only-auth", TLSConfig: client.TLSConfig{ServerName: "localhost", RootCAs: roots}})
			require.NoError(t, e)
			defer c.Close()
			echo, e := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, e)
			defer echo.Close()
			go func() {
				conn, e := echo.Accept()
				if e == nil {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(30 * time.Second))
					io.Copy(conn, conn)
				}
			}()
			conn, e := c.TCP(echo.Addr().String())
			require.NoError(t, e)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
			data := make([]byte, 64<<10)
			_, e = rand.Read(data)
			require.NoError(t, e)
			done := make(chan error, 1)
			go func() { _, e := conn.Write(data); done <- e }()
			got := make([]byte, len(data))
			_, e = io.ReadFull(conn, got)
			require.NoError(t, e)
			require.NoError(t, <-done)
			require.Equal(t, data, got)
			if os.Getenv("OMHY_MARINER_TCP_ONLY") != "1" {
				udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, e)
				defer udp.Close()
				go func() {
					var b [1500]byte
					for {
						n, a, e := udp.ReadFrom(b[:])
						if e != nil {
							return
						}
						udp.WriteTo(b[:n], a)
					}
				}()
				session, e := c.UDP()
				require.NoError(t, e)
				defer session.Close()
				go func() {
					for i := range 16 {
						p := bytes.Repeat([]byte{byte(i)}, 1000)
						if e := session.Send(p, udp.LocalAddr().String()); e != nil {
							done <- e
							return
						}
						got, _, e := session.Receive()
						if e != nil {
							done <- e
							return
						}
						if !bytes.Equal(p, got) {
							done <- io.ErrUnexpectedEOF
							return
						}
					}
					done <- nil
				}()
				select {
				case e := <-done:
					require.NoError(t, e)
				case <-time.After(10 * time.Second):
					t.Fatal("Mariner UDP timeout")
				}
			}
			for _, f := range []*marinerIntegrationFactory{sf, cf} {
				stats := f.conn.(interface{ MarinerStats() obfs.MarinerStats }).MarinerStats()
				require.Positive(t, stats.InnerSentBytes)
				require.Zero(t, stats.WriteErrors)
				require.LessOrEqual(t, stats.GraphEntries, 64)
				f.raw.mu.Lock()
				sizes := append([]int(nil), f.raw.sizes...)
				oob := f.raw.oobWrites
				f.raw.mu.Unlock()
				require.Zero(t, oob)
				for _, n := range sizes {
					require.LessOrEqual(t, n, 1232)
				}
				t.Logf("Mariner %s %+v", tc.name, stats)
			}
			if dir := os.Getenv("OMHY_MARINER_WIRE_AUDIT"); dir != "" {
				b, e := json.Marshal(map[string]string{"server": sf.conn.LocalAddr().String(), "client": cf.conn.LocalAddr().String()})
				require.NoError(t, e)
				require.NoError(t, os.WriteFile(filepath.Join(dir, tc.name+".json"), b, 0o600))
			}
		})
	}
}
