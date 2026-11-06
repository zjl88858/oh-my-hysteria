// SPDX-License-Identifier: MIT-0

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
	"github.com/zjl88858/oh-my-hysteria/core/v2/server"
	"github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"
)

type servoObservedSocket struct {
	*net.UDPConn
	mu        sync.Mutex
	sizes     []int
	dropFirst bool
	oobWrites int
}

func (s *servoObservedSocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	s.mu.Lock()
	s.sizes = append(s.sizes, len(p))
	drop := s.dropFirst
	s.dropFirst = false
	s.mu.Unlock()
	if drop {
		return len(p), nil // explicit synthetic loss, not claimed as wire capture
	}
	return s.UDPConn.WriteTo(p, addr)
}

func (s *servoObservedSocket) WriteMsgUDP(p, oob []byte, addr *net.UDPAddr) (int, int, error) {
	s.mu.Lock()
	s.oobWrites++
	s.mu.Unlock()
	return s.UDPConn.WriteMsgUDP(p, oob, addr)
}

type servoIntegrationFactory struct {
	network, listen string
	server, loss    bool
	conn            net.PacketConn
	raw             *servoObservedSocket
}

func (f *servoIntegrationFactory) New(net.Addr) (net.PacketConn, error) {
	pc, err := net.ListenPacket(f.network, f.listen)
	if err != nil {
		return nil, err
	}
	f.raw = &servoObservedSocket{UDPConn: pc.(*net.UDPConn), dropFirst: f.loss}
	f.conn, err = obfs.WrapPacketConnServo(f.raw, obfs.ServoOptions{Password: []byte("servo-integration-public-random-test-32+"), Server: f.server})
	if err != nil {
		pc.Close()
	}
	return f.conn, err
}

func TestServoTLSAndTransfer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, tc := range []struct {
		name, network, listen string
		loss                  bool
	}{
		{"ipv4", "udp4", "127.0.0.1:0", false},
		{"ipv6", "udp6", "[::1]:0", false},
		{"first-initial-fragment-loss", "udp4", "127.0.0.1:0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sf := &servoIntegrationFactory{network: tc.network, listen: tc.listen, server: true}
			pc, err := sf.New(nil)
			if tc.network == "udp6" && err != nil {
				t.Skipf("IPv6 unavailable: %v", err)
			}
			require.NoError(t, err)
			srv, err := server.NewServer(&server.Config{Conn: pc, Authenticator: geckoTestAuth{}, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, IgnoreClientBandwidth: true})
			require.NoError(t, err)
			defer srv.Close()
			go srv.Serve()
			cf := &servoIntegrationFactory{network: tc.network, listen: tc.listen, loss: tc.loss}
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
					conn.SetDeadline(time.Now().Add(15 * time.Second))
					io.Copy(conn, conn)
				}
			}()
			conn, err := c.TCP(echo.Addr().String())
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(15*time.Second)))
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
			if os.Getenv("OMHY_SERVO_TCP_ONLY") == "1" {
				for _, factory := range []*servoIntegrationFactory{sf, cf} {
					t.Logf("Servo damaged TCP stats %+v", factory.conn.(interface{ ServoStats() obfs.ServoStats }).ServoStats())
				}
				return // QUIC DATAGRAM proxy UDP isn't reliable under simulated loss.
			}
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
				t.Fatal("Servo proxy UDP timeout")
			}
			for _, factory := range []*servoIntegrationFactory{sf, cf} {
				_, oob := factory.conn.(quic.OOBCapablePacketConn)
				require.False(t, oob)
				factory.raw.mu.Lock()
				sizes := append([]int(nil), factory.raw.sizes...)
				bypasses := factory.raw.oobWrites
				factory.raw.mu.Unlock()
				require.Zero(t, bypasses)
				require.NotEmpty(t, sizes)
				for _, n := range sizes {
					require.LessOrEqual(t, n, 1232)
					require.GreaterOrEqual(t, n, 63)
				}
				stats := factory.conn.(interface{ ServoStats() obfs.ServoStats }).ServoStats()
				require.Positive(t, stats.QUICSendSamples)
				require.Positive(t, stats.QUICMetricSamples)
				require.Positive(t, stats.QUICPTO)
				require.Zero(t, stats.AsyncErrors)
				t.Logf("Servo %s stats: %+v", tc.name, stats)
			}
			if dir := os.Getenv("OMHY_SERVO_WIRE_AUDIT"); dir != "" {
				metadata := struct {
					Server string `json:"server"`
					Client string `json:"client"`
				}{Server: sf.conn.LocalAddr().String(), Client: cf.conn.LocalAddr().String()}
				data, err := json.Marshal(metadata)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(dir, tc.name+".json"), data, 0o600))
			}
		})
	}
}
