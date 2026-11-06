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

type tasmanIntegrationFactory struct {
	network, listen string
	server, loss    bool
	conn            net.PacketConn
	raw             *servoObservedSocket
}

func (f *tasmanIntegrationFactory) New(net.Addr) (net.PacketConn, error) {
	pc, err := net.ListenPacket(f.network, f.listen)
	if err != nil {
		return nil, err
	}
	f.raw = &servoObservedSocket{UDPConn: pc.(*net.UDPConn), dropFirst: f.loss}
	f.conn, err = obfs.WrapPacketConnTasman(f.raw, obfs.TasmanOptions{Password: []byte("tasman-integration-public-password-32+"), Server: f.server})
	if err != nil {
		pc.Close()
	}
	return f.conn, err
}

func TestTasmanConfigurationAndURI(t *testing.T) {
	const password = "tasman-test-public-&=+/密码-long-password"
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("obfs:\n  type: TaSmAn\n  tasman:\n    password: "+password)))
	var c clientConfig
	require.NoError(t, v.Unmarshal(&c))
	require.Equal(t, password, c.Obfs.Tasman.Password)
	c.Server = "example.com:443"
	var parsed clientConfig
	parsed.Server = c.URI()
	require.True(t, parsed.parseURI())
	require.Equal(t, "tasman", parsed.Obfs.Type)
	require.Equal(t, password, parsed.Obfs.Tasman.Password)
	for _, server := range []bool{false, true} {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		var w net.PacketConn
		if server {
			s := serverConfig{Obfs: serverConfigObfs{Type: "TASMAN", Tasman: c.Obfs.Tasman}}
			w, err = s.wrapObfs(pc)
		} else {
			w, err = c.wrapObfs(pc)
		}
		require.NoError(t, err)
		require.Equal(t, 1200, w.(interface{ QUICPacketSizeLimit() int }).QUICPacketSizeLimit())
		_, oob := w.(quic.OOBCapablePacketConn)
		require.False(t, oob)
		require.True(t, w.(interface{ QUICWireReservation() bool }).QUICWireReservation())
		require.NoError(t, w.Close())
	}
	for _, password := range []string{"", "short", strings.Repeat("x", 1025)} {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		c.Obfs.Tasman.Password = password
		_, err = c.wrapObfs(pc)
		require.ErrorContains(t, err, "obfs.tasman")
		pc.Close()
	}
	c.Server = "127.0.0.1:4000-4001"
	hy := &client.Config{}
	require.NoError(t, c.fillServerAddr(hy))
	require.ErrorContains(t, c.fillConnFactory(hy), "port hopping")
}

func TestTasmanTLSAndTransfer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, tc := range []struct {
		name, network, listen string
		loss                  bool
	}{{"ipv4", "udp4", "127.0.0.1:0", false}, {"ipv6", "udp6", "[::1]:0", false}, {"initial-loss", "udp4", "127.0.0.1:0", true}} {
		t.Run(tc.name, func(t *testing.T) {
			sf := &tasmanIntegrationFactory{network: tc.network, listen: tc.listen, server: true}
			pc, err := sf.New(nil)
			if tc.network == "udp6" && err != nil {
				t.Skipf("IPv6 unavailable: %v", err)
			}
			require.NoError(t, err)
			srv, err := server.NewServer(&server.Config{Conn: pc, Authenticator: geckoTestAuth{}, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, IgnoreClientBandwidth: true})
			require.NoError(t, err)
			defer srv.Close()
			go srv.Serve()
			cf := &tasmanIntegrationFactory{network: tc.network, listen: tc.listen, loss: tc.loss}
			c, _, err := client.NewClient(&client.Config{ConnFactory: cf, ServerAddr: pc.LocalAddr(), Auth: "test-only-auth", TLSConfig: client.TLSConfig{ServerName: "localhost", RootCAs: roots}})
			require.NoError(t, err)
			defer c.Close()
			echo, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer echo.Close()
			go func() {
				conn, err := echo.Accept()
				if err == nil {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(20 * time.Second))
					io.Copy(conn, conn)
				}
			}()
			conn, err := c.TCP(echo.Addr().String())
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
			data := make([]byte, 64<<10)
			_, err = rand.Read(data)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { _, err := conn.Write(data); done <- err }()
			got := make([]byte, len(data))
			_, err = io.ReadFull(conn, got)
			require.NoError(t, err)
			require.NoError(t, <-done)
			require.Equal(t, data, got)
			if os.Getenv("OMHY_TASMAN_TCP_ONLY") != "1" {
				udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, err)
				defer udp.Close()
				go func() {
					var b [1500]byte
					for {
						n, addr, err := udp.ReadFrom(b[:])
						if err != nil {
							return
						}
						udp.WriteTo(b[:n], addr)
					}
				}()
				session, err := c.UDP()
				require.NoError(t, err)
				defer session.Close()
				go func() {
					for i := range 16 {
						data := bytes.Repeat([]byte{byte(i)}, 1000)
						if err := session.Send(data, udp.LocalAddr().String()); err != nil {
							done <- err
							return
						}
						got, _, err := session.Receive()
						if err != nil {
							done <- err
							return
						}
						if !bytes.Equal(got, data) {
							done <- io.ErrUnexpectedEOF
							return
						}
					}
					done <- nil
				}()
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-time.After(10 * time.Second):
					t.Fatal("Tasman UDP timeout")
				}
			}
			for _, f := range []*tasmanIntegrationFactory{sf, cf} {
				stats := f.conn.(interface{ TasmanStats() obfs.TasmanStats }).TasmanStats()
				require.Positive(t, stats.QUICSendSamples)
				require.Positive(t, stats.QUICMetricSamples)
				require.Zero(t, stats.AsyncErrors)
				require.LessOrEqual(t, stats.OuterSentBytes, 2*stats.InnerAcceptedBytes+stats.TinyExceptionBytes)
				f.raw.mu.Lock()
				sizes := append([]int(nil), f.raw.sizes...)
				oob := f.raw.oobWrites
				f.raw.mu.Unlock()
				require.Zero(t, oob)
				for _, n := range sizes {
					require.LessOrEqual(t, n, 1232)
				}
				t.Logf("Tasman %s %+v", tc.name, stats)
			}
			if dir := os.Getenv("OMHY_TASMAN_WIRE_AUDIT"); dir != "" {
				data, err := json.Marshal(map[string]string{"server": sf.conn.LocalAddr().String(), "client": cf.conn.LocalAddr().String()})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(dir, tc.name+".json"), data, 0o600))
			}
		})
	}
}
