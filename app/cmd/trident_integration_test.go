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

type tridentIntegrationWire struct {
	net.PacketConn
	mu    sync.Mutex
	sizes []int
}

func (c *tridentIntegrationWire) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	c.mu.Lock()
	c.sizes = append(c.sizes, len(p))
	c.mu.Unlock()
	return n, err
}

func (c *tridentIntegrationWire) snapshot() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.sizes...)
}

type tridentIntegrationFactory struct {
	network, listen string
	options         obfs.TridentOptions
	conn            net.PacketConn
	wire            *tridentIntegrationWire
}

func (f *tridentIntegrationFactory) New(net.Addr) (net.PacketConn, error) {
	pc, err := net.ListenPacket(f.network, f.listen)
	if err != nil {
		return nil, err
	}
	f.wire = &tridentIntegrationWire{PacketConn: pc}
	w, err := obfs.WrapPacketConnTrident(f.wire, f.options)
	if err != nil {
		pc.Close()
		return nil, err
	}
	f.conn = w
	return w, nil
}

func TestTridentTLSAndTransfer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, tc := range []struct{ name, network, listen, password string }{
		{"dialect-a-ipv4", "udp4", "127.0.0.1:0", "trident-integration-test-dialect-A-32+"},
		{"dialect-b-ipv4", "udp4", "127.0.0.1:0", "trident-integration-test-dialect-B-32+"},
		{"dialect-a-ipv6", "udp6", "[::1]:0", "trident-integration-test-dialect-A-32+"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sf := &tridentIntegrationFactory{network: tc.network, listen: tc.listen, options: obfs.TridentOptions{Password: []byte(tc.password), Server: true}}
			pc, err := sf.New(nil)
			if tc.network == "udp6" && err != nil {
				t.Skipf("IPv6 unavailable: %v", err)
			}
			require.NoError(t, err)
			srv, err := server.NewServer(&server.Config{Conn: pc, Authenticator: geckoTestAuth{}, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, IgnoreClientBandwidth: true})
			require.NoError(t, err)
			defer srv.Close()
			go srv.Serve()
			noise, err := net.ListenPacket(tc.network, tc.listen)
			require.NoError(t, err)
			_, err = noise.WriteTo(make([]byte, 4096), pc.LocalAddr())
			require.NoError(t, err)
			noise.Close()
			cf := &tridentIntegrationFactory{network: tc.network, listen: tc.listen, options: obfs.TridentOptions{Password: []byte(tc.password)}}
			c, _, err := client.NewClient(&client.Config{ConnFactory: cf, ServerAddr: pc.LocalAddr(), Auth: "test-only-auth", TLSConfig: client.TLSConfig{ServerName: "localhost", RootCAs: roots}})
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
				conn.SetDeadline(time.Now().Add(20 * time.Second))
				io.Copy(conn, conn)
			}()
			conn, err := c.TCP(listener.Addr().String())
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
			data := make([]byte, 256*1024)
			_, err = rand.Read(data)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { _, err := conn.Write(data); done <- err }()
			got := make([]byte, len(data))
			_, err = io.ReadFull(conn, got)
			require.NoError(t, err)
			require.NoError(t, <-done)
			require.Equal(t, sha256.Sum256(data), sha256.Sum256(got))
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
					if err != nil || !bytes.Equal(payload, reply) {
						if err == nil {
							err = io.ErrUnexpectedEOF
						}
						result <- err
						return
					}
				}
				result <- nil
			}()
			select {
			case err := <-result:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("Trident proxy UDP timeout")
			}
			for _, f := range []*tridentIntegrationFactory{sf, cf} {
				stats := f.conn.(interface{ TridentStats() obfs.TridentStats }).TridentStats()
				require.Positive(t, stats.FragmentedMessages)
				require.LessOrEqual(t, stats.ReassemblyBytes, 600*1024)
				lengths := f.wire.snapshot()
				require.NotEmpty(t, lengths)
				maximum := 0
				for _, size := range lengths {
					require.LessOrEqual(t, size, 1232)
					maximum = max(maximum, size)
				}
				t.Logf("Trident %s stats %+v; observed UDP payload max=%d", tc.name, stats, maximum)
			}
		})
	}
}
