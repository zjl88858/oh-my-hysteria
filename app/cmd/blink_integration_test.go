// SPDX-License-Identifier: MIT-0

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
	"github.com/zjl88858/oh-my-hysteria/core/v2/server"
	"github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"
)

type blinkIntegrationFactory struct {
	network, listen string
	options         obfs.BlinkOptions
	conn            net.PacketConn
}

func (f *blinkIntegrationFactory) New(net.Addr) (net.PacketConn, error) {
	pc, err := net.ListenPacket(f.network, f.listen)
	if err != nil {
		return nil, err
	}
	w, err := obfs.WrapPacketConnBlink(pc, f.options)
	if err != nil {
		pc.Close()
		return nil, err
	}
	f.conn = w
	return w, nil
}

func TestBlinkTLSAndTransfer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, tc := range []struct {
		name, network, listen string
		fragment              bool
		wire                  int
	}{
		{"default-ipv4", "udp4", "127.0.0.1:0", false, 1400},
		{"ipv6-min-mtu", "udp6", "[::1]:0", true, 1232},
		{"small-wire", "udp4", "127.0.0.1:0", true, 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := obfs.BlinkOptions{Password: []byte("blink-integration-only-password"), Server: true, Fragmentation: tc.fragment, MaxPacketSize: tc.wire}
			sf := &blinkIntegrationFactory{network: tc.network, listen: tc.listen, options: options}
			pc, err := sf.New(nil)
			if tc.network == "udp6" && err != nil {
				t.Skipf("IPv6 unavailable: %v", err)
			}
			require.NoError(t, err)
			srv, err := server.NewServer(&server.Config{Conn: pc, Authenticator: geckoTestAuth{}, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, IgnoreClientBandwidth: true})
			require.NoError(t, err)
			defer srv.Close()
			go srv.Serve()
			// An oversized unauthenticated UDP datagram must not kill the
			// listener (in particular, WSAEMSGSIZE on Windows).
			noise, err := net.ListenPacket(tc.network, tc.listen)
			require.NoError(t, err)
			_, err = noise.WriteTo(make([]byte, 4096), pc.LocalAddr())
			require.NoError(t, err)
			require.NoError(t, noise.Close())
			options.Server = false
			cf := &blinkIntegrationFactory{network: tc.network, listen: tc.listen, options: options}
			c, _, err := client.NewClient(&client.Config{ConnFactory: cf, ServerAddr: pc.LocalAddr(), Auth: "test-only-auth", TLSConfig: client.TLSConfig{ServerName: "localhost", RootCAs: roots}})
			require.NoError(t, err)
			defer c.Close()
			t.Cleanup(func() {
				for _, wrapped := range []net.PacketConn{sf.conn, cf.conn} {
					if wrapped != nil {
						t.Logf("Blink %s final stats: %+v", tc.name, wrapped.(interface{ BlinkStats() obfs.BlinkStats }).BlinkStats())
					}
				}
			})
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(15 * time.Second))
				io.Copy(conn, conn)
			}()
			conn, err := c.TCP(listener.Addr().String())
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(15*time.Second)))
			data := make([]byte, 1024*1024)
			_, err = rand.Read(data)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { _, err := conn.Write(data); done <- err }()
			got := make([]byte, len(data))
			_, err = io.ReadFull(conn, got)
			require.NoError(t, err)
			require.NoError(t, <-done)
			require.Equal(t, sha256.Sum256(data), sha256.Sum256(got))
			// This is a separate UDP correctness phase, not a promise of
			// lossless QUIC DATAGRAMs during a localhost TCP flood. Refill
			// the default source token burst (2048 / 8192 = 250ms); no
			// production sleep or hidden UDP retry is added to Blink.
			time.Sleep(250 * time.Millisecond)
			udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer udp.Close()
			go func() {
				buf := make([]byte, 2048)
				for {
					n, addr, err := udp.ReadFrom(buf)
					if err != nil {
						return
					}
					udp.WriteTo(buf[:n], addr)
				}
			}()
			session, err := c.UDP()
			require.NoError(t, err)
			defer session.Close()
			result := make(chan error, 1)
			go func() {
				for i := range 32 {
					payload := bytes.Repeat([]byte{byte(i)}, 1000)
					if err := session.Send(payload, udp.LocalAddr().String()); err != nil {
						result <- err
						return
					}
					reply, _, err := session.Receive()
					if err != nil {
						result <- err
						return
					}
					if !bytes.Equal(reply, payload) {
						result <- io.ErrUnexpectedEOF
						return
					}
				}
				result <- nil
			}()
			select {
			case err := <-result:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("Blink UDP timeout")
			}
			for _, wrapped := range []net.PacketConn{sf.conn, cf.conn} {
				s := wrapped.(interface{ BlinkStats() obfs.BlinkStats }).BlinkStats()
				require.LessOrEqual(t, s.PaddingBytes, s.SentInnerBytes/10)
				require.LessOrEqual(t, s.ReassemblyBytes, 1024*1024)
				t.Logf("Blink %s stats: %+v", tc.name, s)
			}
			// Concurrent snapshots while Close unblocks the read side are race-tested.
			var wg sync.WaitGroup
			wg.Go(func() {
				for range 100 {
					sf.conn.(interface{ BlinkStats() obfs.BlinkStats }).BlinkStats()
				}
			})
			wg.Wait()
		})
	}
}
