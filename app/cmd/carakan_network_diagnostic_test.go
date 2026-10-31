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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
	"github.com/zjl88858/oh-my-hysteria/core/v2/server"
	"github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"
)

// A loopback-only fault injector. Delays are scheduled from enqueue time, not
// added serially per fragment. It preserves accepted-packet order, has one
// worker, and reports every deliberately lost packet. No payload is archived.
type carakanDiagnosticWire struct {
	net.PacketConn
	mu               sync.Mutex
	random           *mathrand.Rand
	delay            time.Duration
	lossPercent      uint32
	burstEvery       uint64
	burstLength      uint64
	packets, dropped uint64
	written, read    uint64
	maxPayload       int
	queue            chan carakanDiagnosticPacket
	stop, done       chan struct{}
	closeOnce        sync.Once
	err              error
}

type carakanDiagnosticPacket struct {
	data []byte
	addr net.Addr
	due  time.Time
}

type carakanDiagnosticWireStats struct {
	Attempted, InjectedDrops, Written, Read uint64
	MaxPayload                              int
	WorkerError                             string `json:",omitempty"`
}

func newCarakanDiagnosticWire(t *testing.T, delay time.Duration, loss uint32, seed string) *carakanDiagnosticWire {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	require.NoError(t, pc.SetReadBuffer(2*1024*1024))
	w := &carakanDiagnosticWire{
		PacketConn: pc, random: mathrand.New(mathrand.NewChaCha8(sha256.Sum256([]byte(seed)))),
		delay: delay, lossPercent: loss, queue: make(chan carakanDiagnosticPacket, 4096),
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go w.run()
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func (w *carakanDiagnosticWire) WriteTo(data []byte, addr net.Addr) (int, error) {
	w.mu.Lock()
	w.packets++
	w.maxPayload = max(w.maxPayload, len(data))
	drop := w.random.Uint32N(100) < w.lossPercent
	if w.burstEvery > 0 {
		drop = (w.packets-1)%w.burstEvery < w.burstLength
	}
	if drop {
		w.dropped++
	}
	w.mu.Unlock()
	if drop {
		return len(data), nil // UDP loss, not a sender-side write error.
	}
	packet := carakanDiagnosticPacket{data: bytes.Clone(data), addr: addr, due: time.Now().Add(w.delay)}
	select {
	case w.queue <- packet:
		return len(data), nil
	case <-w.stop:
		return 0, net.ErrClosed
	}
}

func (w *carakanDiagnosticWire) run() {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			return
		case packet := <-w.queue:
			timer := time.NewTimer(max(0, time.Until(packet.due)))
			select {
			case <-w.stop:
				timer.Stop()
				return
			case <-timer.C:
			}
			n, err := w.PacketConn.WriteTo(packet.data, packet.addr)
			w.recordWrite(n, len(packet.data), err)
		}
	}
}

func (w *carakanDiagnosticWire) recordWrite(n, wanted int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err != nil {
		select {
		case <-w.stop:
			if !errors.Is(err, net.ErrClosed) {
				w.err = err
			}
		default:
			w.err = err
		}
	} else if n != wanted {
		w.err = io.ErrShortWrite
	} else {
		w.written++
	}
}

func TestCarakanDiagnosticWriteAccounting(t *testing.T) {
	w := &carakanDiagnosticWire{stop: make(chan struct{})}
	w.recordWrite(100, 100, nil)
	require.Equal(t, uint64(1), w.snapshot().Written)
	w.recordWrite(0, 100, net.ErrClosed)
	require.ErrorIs(t, w.err, net.ErrClosed)
	require.Equal(t, uint64(1), w.snapshot().Written)
	w.err = nil
	close(w.stop)
	w.recordWrite(0, 100, net.ErrClosed)
	require.NoError(t, w.err)
	require.Equal(t, uint64(1), w.snapshot().Written)
	w.recordWrite(20, 100, nil)
	require.ErrorIs(t, w.err, io.ErrShortWrite)
}

func (w *carakanDiagnosticWire) ReadFrom(data []byte) (int, net.Addr, error) {
	n, addr, err := w.PacketConn.ReadFrom(data)
	if err == nil {
		w.mu.Lock()
		w.read++
		w.mu.Unlock()
	}
	return n, addr, err
}

func (w *carakanDiagnosticWire) Close() error {
	w.closeOnce.Do(func() {
		close(w.stop)
		_ = w.PacketConn.Close()
		<-w.done
	})
	return nil
}

func (w *carakanDiagnosticWire) snapshot() carakanDiagnosticWireStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := carakanDiagnosticWireStats{Attempted: w.packets, InjectedDrops: w.dropped, Written: w.written, Read: w.read, MaxPayload: w.maxPayload}
	if w.err != nil {
		s.WorkerError = w.err.Error()
	}
	return s
}

type carakanDiagnosticFactory struct{ conn net.PacketConn }

func (f carakanDiagnosticFactory) New(net.Addr) (net.PacketConn, error) { return f.conn, nil }

type carakanDiagnosticCase struct {
	Name                    string
	Entropy                 float64
	PasswordNumber          int
	OneWayDelayMS           int
	ServerToClientLoss      uint32
	BurstEvery, BurstLength uint64
	Seed                    string
}

type carakanDiagnosticResult struct {
	Case                        carakanDiagnosticCase
	LoopbackOnly, NormalTLS     bool
	Connected, TransferComplete bool
	Error                       string `json:",omitempty"`
	ConnectSeconds              float64
	EchoBytes                   int
	Client, Server              obfs.CarakanStats
	ClientWire, ServerWire      carakanDiagnosticWireStats
}

func carakanDiagnosticCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func runCarakanDiagnostic(t *testing.T, tc carakanDiagnosticCase, cert tls.Certificate, roots *x509.CertPool) carakanDiagnosticResult {
	t.Helper()
	password := sha256.Sum256([]byte(fmt.Sprintf("public-local-diagnostic-password-%d", tc.PasswordNumber)))
	sw := newCarakanDiagnosticWire(t, time.Duration(tc.OneWayDelayMS)*time.Millisecond, tc.ServerToClientLoss, tc.Seed+"/server")
	sw.burstEvery, sw.burstLength = tc.BurstEvery, tc.BurstLength
	cw := newCarakanDiagnosticWire(t, time.Duration(tc.OneWayDelayMS)*time.Millisecond, 0, tc.Seed+"/client")
	sc, err := obfs.WrapPacketConnCarakan(sw, obfs.CarakanOptions{Password: password[:], TargetEntropy: &tc.Entropy, Server: true})
	require.NoError(t, err)
	cc, err := obfs.WrapPacketConnCarakan(cw, obfs.CarakanOptions{Password: password[:], TargetEntropy: &tc.Entropy})
	require.NoError(t, err)
	srv, err := server.NewServer(&server.Config{
		Conn: sc, Authenticator: geckoTestAuth{}, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{cert}}, IgnoreClientBandwidth: true,
	})
	require.NoError(t, err)
	serveDone := make(chan struct{})
	go func() { _ = srv.Serve(); close(serveDone) }()
	defer func() { _ = srv.Close(); <-serveDone }()
	result := carakanDiagnosticResult{Case: tc, LoopbackOnly: true, NormalTLS: true}
	started := time.Now()
	c, info, err := client.NewClient(&client.Config{
		ConnFactory: carakanDiagnosticFactory{cc}, ServerAddr: sc.LocalAddr(), Auth: "test-only-auth",
		TLSConfig: client.TLSConfig{ServerName: "localhost", RootCAs: roots},
	})
	result.ConnectSeconds = time.Since(started).Seconds()
	if err != nil {
		result.Error = err.Error()
	} else {
		result.Connected = true
		require.Zero(t, info.Tx)
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
			_, _ = io.Copy(conn, conn)
		}()
		conn, err := c.TCP(listener.Addr().String())
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
			data := bytes.Repeat([]byte("carakan-loopback-diagnostic\x00"), 128)
			done := make(chan error, 1)
			go func() { _, err := io.Copy(conn, bytes.NewReader(data)); done <- err }()
			got := make([]byte, len(data))
			_, err = io.ReadFull(conn, got)
			if writeErr := <-done; err == nil {
				err = writeErr
			}
			result.TransferComplete = err == nil && bytes.Equal(got, data)
			if result.TransferComplete {
				result.EchoBytes = len(data)
			}
			_ = conn.Close()
		}
		if err != nil {
			result.Error = err.Error()
		}
		_ = c.Close()
	}
	result.Client = cc.(interface{ CarakanStats() obfs.CarakanStats }).CarakanStats()
	result.Server = sc.(interface{ CarakanStats() obfs.CarakanStats }).CarakanStats()
	result.ClientWire, result.ServerWire = cw.snapshot(), sw.snapshot()
	for _, s := range []carakanDiagnosticWireStats{result.ClientWire, result.ServerWire} {
		require.Empty(t, s.WorkerError)
		require.LessOrEqual(t, s.MaxPayload, 1232)
	}
	// Impairment results are observations, not assertions that a chosen entropy
	// must fail. Never select a seed or hide a passing/failing impaired sample.
	if tc.ServerToClientLoss == 0 && tc.BurstEvery == 0 {
		require.True(t, result.Connected && result.TransferComplete, "%+v", result)
		for _, s := range []obfs.CarakanStats{result.Client, result.Server} {
			require.Zero(t, s.AuthDrops+s.MalformedDrops+s.RateDrops+s.ResourceDrops+s.FreshnessDrops+s.ExpiredAssemblies+s.EvictedAssemblies)
		}
	}
	return result
}

// Explicitly opt in: this records synthetic loopback impairments, not a public
// diagnosis or a stable threshold. Ordinary test runs must not run a long sweep.
func TestCarakanNetworkDiagnostic(t *testing.T) {
	out := os.Getenv("OMHY_CARAKAN_DIAGNOSTIC_DIR")
	if out == "" {
		t.Skip("set OMHY_CARAKAN_DIAGNOSTIC_DIR to a new output directory for loopback diagnostics")
	}
	require.NoError(t, os.Mkdir(out, 0o700))
	cert, roots := carakanDiagnosticCertificate(t)
	cases := make([]carakanDiagnosticCase, 0, 24)
	for password := range 3 {
		for _, h := range []float64{1, 1.5, 1.99, 2, 4} {
			cases = append(cases, carakanDiagnosticCase{Name: fmt.Sprintf("lossless-key%d-h%.2f", password, h), Entropy: h, PasswordNumber: password, Seed: "fixed-diagnostic-0"})
		}
	}
	for _, loss := range []uint32{0, 5, 20} {
		for _, h := range []float64{1.5, 2, 4} {
			cases = append(cases, carakanDiagnosticCase{Name: fmt.Sprintf("delay50-loss%d-h%.2f", loss, h), Entropy: h, OneWayDelayMS: 50, ServerToClientLoss: loss, Seed: "fixed-diagnostic-1"})
		}
	}
	if path := os.Getenv("OMHY_CARAKAN_DIAGNOSTIC_PLAN"); path != "" {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &cases))
		require.NotEmpty(t, cases)
		seen := make(map[string]bool)
		for _, tc := range cases {
			require.Equal(t, filepath.Base(tc.Name), tc.Name)
			require.NotContains(t, tc.Name, "..")
			require.False(t, seen[tc.Name])
			seen[tc.Name] = true
			require.LessOrEqual(t, tc.ServerToClientLoss, uint32(100))
			require.GreaterOrEqual(t, tc.OneWayDelayMS, 0)
			require.LessOrEqual(t, tc.OneWayDelayMS, 500)
			require.True(t, tc.BurstEvery == 0 || tc.BurstLength <= tc.BurstEvery)
		}
	}
	plan, err := json.MarshalIndent(cases, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(out, "plan.json"), plan, 0o600))
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			result := runCarakanDiagnostic(t, tc, cert, roots)
			encoded, err := json.MarshalIndent(result, "", "  ")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(out, tc.Name+".json"), encoded, 0o600))
			t.Logf("local only H=%.2f loss=%d%% delay=%dms connected=%v transfer=%v connect=%.3fs dropped=%d client_delivered=%d client_expired=%d error=%s", tc.Entropy, tc.ServerToClientLoss, tc.OneWayDelayMS, result.Connected, result.TransferComplete, result.ConnectSeconds, result.ServerWire.InjectedDrops, result.Client.DeliveredBytes, result.Client.ExpiredAssemblies, result.Error)
		})
	}
}
