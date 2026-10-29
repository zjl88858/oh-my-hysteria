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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
	"github.com/zjl88858/oh-my-hysteria/core/v2/server"
	"github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"
)

type geckoTestFactory struct{}

func (geckoTestFactory) New(net.Addr) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	wrapped, err := obfs.WrapPacketConnGecko(pc, obfs.GeckoOptions{Password: []byte("test-only-gecko-password")})
	if err != nil {
		pc.Close()
	}
	return wrapped, err
}

type geckoTestAuth struct{}

func (geckoTestAuth) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return auth == "test-only-auth", "integration"
}

func TestGeckoBBR3AndBBRFallbackTransfer(t *testing.T) {
	testGeckoCongestionTransfer(t, []struct{ mode, profile string }{{"bbr3", ""}, {"bbr3", "conservative"}, {"bbr3", "aggressive"}, {"bbr", ""}})
}

func TestGeckoCopaTransfer(t *testing.T) {
	testGeckoCongestionTransfer(t, []struct{ mode, profile string }{{"copa", ""}})
}

func TestGeckoGeodesicTransfer(t *testing.T) {
	testGeckoCongestionTransfer(t, []struct{ mode, profile string }{{"geodesic", ""}})
}

func testGeckoCongestionTransfer(t *testing.T, cases []struct{ mode, profile string }) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, tc := range cases {
		t.Run(tc.mode+"/"+tc.profile, func(t *testing.T) {
			pc, err := (geckoTestFactory{}).New(nil)
			require.NoError(t, err)
			sc := &server.Config{Conn: pc, Authenticator: geckoTestAuth{}, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, IgnoreClientBandwidth: true}
			require.NoError(t, (&serverConfig{Congestion: serverConfigCongestion{Type: tc.mode, BBRProfile: tc.profile}}).fillCongestionConfig(sc))
			srv, err := server.NewServer(sc)
			require.NoError(t, err)
			defer srv.Close()
			go srv.Serve()
			cc := &client.Config{ConnFactory: geckoTestFactory{}, ServerAddr: pc.LocalAddr(), Auth: "test-only-auth", TLSConfig: client.TLSConfig{ServerName: "localhost", RootCAs: roots}}
			require.NoError(t, (&clientConfig{Congestion: clientConfigCongestion{Type: tc.mode, BBRProfile: tc.profile}}).fillCongestionConfig(cc))
			c, _, err := client.NewClient(cc)
			require.NoError(t, err)
			defer c.Close()
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
					if !bytes.Equal(payload, reply) {
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
				t.Fatal("Gecko UDP transfer timeout")
			}
		})
	}
}
