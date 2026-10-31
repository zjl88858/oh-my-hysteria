// SPDX-License-Identifier: MIT-0

// carakan-diagnostic is a bounded diagnostic endpoint, NOT a release binary.
// It uses the unchanged core and Carakan wrapper, adding in-memory fingerprints
// on both sides of that wrapper. It never stores packet payloads or credentials.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
	"github.com/zjl88858/oh-my-hysteria/core/v2/server"
	"github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"
)

type config struct {
	Role, Address, Password, Auth, Cert, Key, CA, ServerName, Output string
	Entropy                                                          float64
	Bytes, LifetimeSeconds                                           int
}

type event struct {
	Layer, Op, Digest string
	AtUS              int64
	Group             uint64
	Bytes             int
	Error             string `json:",omitempty"`
}

type sample struct {
	AtUS  int64
	Stats obfs.CarakanStats
}

type record struct {
	Role, Platform, WireDomain           string
	TargetEntropy                        float64
	StartedUnix                          float64
	Connected, Complete                  bool
	ApplicationSent, ApplicationReceived int
	ConnectSeconds                       float64
	Error                                string `json:",omitempty"`
	Stats                                obfs.CarakanStats
	Events                               []event
	Samples                              []sample
	TraceOverflows                       int
	PayloadsOrSecretsRecorded            bool
	NormalTLS                            bool
}

type recorder struct {
	mu       sync.Mutex
	start    time.Time
	group    atomic.Uint64
	events   []event
	samples  []sample
	overflow int
}

func (r *recorder) packet(layer, op string, group uint64, data []byte, err error) {
	digest := sha256.Sum256(data)
	e := event{Layer: layer, Op: op, Group: group, Bytes: len(data), Digest: hex.EncodeToString(digest[:16]), AtUS: time.Since(r.start).Microseconds()}
	if err != nil {
		e.Error = err.Error()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) >= 8192 {
		r.overflow++
		return
	}
	r.events = append(r.events, e)
}

type wireProbe struct {
	conn *net.UDPConn
	r    *recorder
}

func (p *wireProbe) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := p.conn.ReadFrom(b)
	if n > 0 {
		p.r.packet("outer", "read", 0, b[:n], err)
	}
	return n, a, err
}

func (p *wireProbe) WriteTo(b []byte, a net.Addr) (int, error) {
	n, err := p.conn.WriteTo(b, a)
	p.r.packet("outer", "write", p.r.group.Load(), b[:max(0, min(n, len(b)))], err)
	return n, err
}

func (p *wireProbe) Close() error                          { return p.conn.Close() }
func (p *wireProbe) LocalAddr() net.Addr                   { return p.conn.LocalAddr() }
func (p *wireProbe) SetDeadline(t time.Time) error         { return p.conn.SetDeadline(t) }
func (p *wireProbe) SetReadDeadline(t time.Time) error     { return p.conn.SetReadDeadline(t) }
func (p *wireProbe) SetWriteDeadline(t time.Time) error    { return p.conn.SetWriteDeadline(t) }
func (p *wireProbe) SetReadBuffer(n int) error             { return p.conn.SetReadBuffer(n) }
func (p *wireProbe) SetWriteBuffer(n int) error            { return p.conn.SetWriteBuffer(n) }
func (p *wireProbe) SyscallConn() (syscall.RawConn, error) { return p.conn.SyscallConn() }

type innerProbe struct {
	net.PacketConn
	r       *recorder
	writeMu sync.Mutex
}

func (p *innerProbe) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := p.PacketConn.ReadFrom(b)
	if n > 0 {
		p.r.packet("inner", "read", 0, b[:n], err)
	}
	return n, a, err
}

func (p *innerProbe) WriteTo(b []byte, a net.Addr) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	group := p.r.group.Add(1)
	n, err := p.PacketConn.WriteTo(b, a)
	p.r.packet("inner", "write", group, b[:max(0, min(n, len(b)))], err)
	return n, err
}

func (p *innerProbe) QUICPacketSizeLimit() int { return 1200 }
func (p *innerProbe) SetReadBuffer(n int) error {
	return p.PacketConn.(interface{ SetReadBuffer(int) error }).SetReadBuffer(n)
}

func (p *innerProbe) SetWriteBuffer(n int) error {
	return p.PacketConn.(interface{ SetWriteBuffer(int) error }).SetWriteBuffer(n)
}

func (p *innerProbe) SyscallConn() (syscall.RawConn, error) {
	return p.PacketConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}).SyscallConn()
}

type factory struct{ conn net.PacketConn }

func (f factory) New(net.Addr) (net.PacketConn, error) { return f.conn, nil }

type auth struct {
	secret   string
	accepted *atomic.Bool
}

func (a auth) Authenticate(_ net.Addr, value string, _ uint64) (bool, string) {
	ok := subtle.ConstantTimeCompare([]byte(value), []byte(a.secret)) == 1
	if ok {
		a.accepted.Store(true)
	}
	return ok, "diagnostic"
}

// No unrestricted proxy is exposed by the diagnostic server.
type echoOutbound struct{}

func (echoOutbound) TCP(addr string) (net.Conn, error) {
	if addr != "carakan-diagnostic-echo" {
		return nil, errors.New("diagnostic destination only")
	}
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		_ = b.SetDeadline(time.Now().Add(15 * time.Second))
		_, _ = io.Copy(b, b)
	}()
	return a, nil
}

func (echoOutbound) UDP(string) (server.UDPConn, error) {
	return nil, errors.New("diagnostic UDP proxy disabled")
}
func (echoOutbound) CheckUDP(string) error { return errors.New("diagnostic UDP proxy disabled") }

func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", data, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func run(cfg config) (int, error) {
	if (cfg.Role != "server" && cfg.Role != "client") || cfg.Bytes < 1 || cfg.Bytes > 4096 || cfg.LifetimeSeconds < 1 || cfg.LifetimeSeconds > 30 || cfg.ServerName == "" {
		return 1, errors.New("invalid bounded diagnostic configuration")
	}
	if _, err := os.Stat(cfg.Output); !errors.Is(err, os.ErrNotExist) {
		return 1, errors.New("refuse overwriting diagnostic output")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.LifetimeSeconds)*time.Second)
	defer cancel()
	listen := "127.0.0.1:0"
	if cfg.Role == "server" {
		listen = cfg.Address
	} else {
		listen = "0.0.0.0:0"
	}
	a, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		return 1, err
	}
	udp, err := net.ListenUDP("udp4", a)
	if err != nil {
		return 1, err
	}
	defer udp.Close()
	r := &recorder{start: time.Now()}
	w := &wireProbe{conn: udp, r: r}
	wrapped, err := obfs.WrapPacketConnCarakan(w, obfs.CarakanOptions{Password: []byte(cfg.Password), TargetEntropy: &cfg.Entropy, Server: cfg.Role == "server"})
	if err != nil {
		return 1, err
	}
	defer wrapped.Close()
	pc := &innerProbe{PacketConn: wrapped, r: r}
	stats := wrapped.(interface{ CarakanStats() obfs.CarakanStats })
	stopTimeout := context.AfterFunc(ctx, func() { _ = pc.Close() })
	defer stopTimeout()
	done, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				s := sample{AtUS: time.Since(r.start).Microseconds(), Stats: stats.CarakanStats()}
				r.mu.Lock()
				r.samples = append(r.samples, s)
				r.mu.Unlock()
			}
		}
	}()
	result := record{
		Role: cfg.Role, Platform: runtime.GOOS + "/" + runtime.GOARCH, WireDomain: "oh-my-hysteria/carakan/v3", TargetEntropy: cfg.Entropy,
		StartedUnix: float64(r.start.UnixNano()) / 1e9, NormalTLS: true,
	}
	defer func() { close(done); <-sampled }()
	if cfg.Role == "server" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return 1, err
		}
		var accepted atomic.Bool
		srv, err := server.NewServer(&server.Config{
			Conn: pc, Authenticator: auth{cfg.Auth, &accepted}, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{cert}},
			IgnoreClientBandwidth: true, DisableUDP: true, Outbound: echoOutbound{},
		})
		if err != nil {
			return 1, err
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- srv.Serve() }()
		if err := writeJSON(cfg.Output+".ready", map[string]any{"ready": true, "address": pc.LocalAddr().String(), "role": cfg.Role}); err != nil {
			_ = srv.Close()
			return 1, err
		}
		select {
		case <-ctx.Done():
		case err := <-serveDone:
			if ctx.Err() == nil {
				result.Error = err.Error()
			}
		}
		result.Stats = stats.CarakanStats()
		result.Connected = accepted.Load()
		_ = srv.Close()
	} else {
		pem, err := os.ReadFile(cfg.CA)
		if err != nil {
			return 1, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return 1, errors.New("no diagnostic CA")
		}
		destination, err := net.ResolveUDPAddr("udp4", cfg.Address)
		if err != nil {
			return 1, err
		}
		started := time.Now()
		c, _, err := client.NewClient(&client.Config{
			ConnFactory: factory{pc}, ServerAddr: destination, Auth: cfg.Auth,
			TLSConfig: client.TLSConfig{ServerName: cfg.ServerName, RootCAs: roots},
		})
		result.ConnectSeconds = time.Since(started).Seconds()
		if err == nil {
			result.Connected = true
			conn, openErr := c.TCP("carakan-diagnostic-echo")
			err = openErr
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				data := make([]byte, cfg.Bytes)
				_, err = rand.Read(data)
				if err == nil {
					type sent struct {
						n   int
						err error
					}
					sentCh := make(chan sent, 1)
					go func() { n, err := io.Copy(conn, bytes.NewReader(data)); sentCh <- sent{int(n), err} }()
					got := make([]byte, len(data))
					result.ApplicationReceived, err = io.ReadFull(conn, got)
					txResult := <-sentCh
					result.ApplicationSent = txResult.n
					if err == nil {
						err = txResult.err
					}
					result.Complete = err == nil && bytes.Equal(got, data)
				}
				_ = conn.Close()
			}
			result.Stats = stats.CarakanStats()
			_ = c.Close()
		} else {
			result.Stats = stats.CarakanStats()
		}
		if err != nil {
			result.Error = err.Error()
		}
	}
	stopTimeout()
	r.mu.Lock()
	result.Events = append([]event(nil), r.events...)
	result.Samples = append([]sample(nil), r.samples...)
	result.TraceOverflows = r.overflow
	r.mu.Unlock()
	if err := writeJSON(cfg.Output, result); err != nil {
		return 1, err
	}
	if result.Error != "" || (cfg.Role == "client" && !result.Complete) || result.TraceOverflows != 0 {
		return 1, errors.New("diagnostic sample failed; trace retained")
	}
	return 0, nil
}

func main() {
	path := flag.String("config", "", "private diagnostic JSON configuration")
	flag.Parse()
	data, err := os.ReadFile(*path)
	var cfg config
	if err == nil {
		err = json.Unmarshal(data, &cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "diagnostic configuration error")
		os.Exit(1)
	}
	status, err := run(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(status)
}
