// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const netfrontTestKey = "public-netfront-loopback-test-secret-32+"

func TestNetFrontReferenceFrames(t *testing.T) {
	// Independent Python struct.pack(">B16sQ16sH"), HKDF/HChaCha from
	// tests/servo_reference.py, cryptography's IETF ChaCha20Poly1305.
	// Nonce 00..17, SID 00..0f, padding 00..08, AAD 03 02.
	for _, tc := range []struct {
		kind byte
		wire string
	}{
		{nfProbe, "000102030405060708090a0b0c0d0e0f101112131415161711251e9eb15c8188db78bd784fd4709d7c0516bd4b208821ef514bd42eaddf3bf597236f4973d95d68f0653b7f5d477e806a361e69493a5a7f7e26f22a5e71873c1770e7"},
		{nfOffer, "000102030405060708090a0b0c0d0e0f10111213141516170cf4eb0c58482052f9b8800b7816570d3cf61546262c6b4ed1a7d419aa92d50a0f9c139380165db458036effe1d272aa0bef74b0f247c19862d97a32898c905f0dee98ea"},
	} {
		p, err := prestoStandard.compileNetfront(NetFrontOptions{[]byte(netfrontTestKey), []int{1, 2, 3}}, tc.kind == nfProbe)
		require.NoError(t, err)
		require.Equal(t, "10ba75e0c92d265548a75e05916fbeab9aca678fef934b940e310f2f4f08d84f", hex.EncodeToString(p.prestoKey))
		b, err := hex.DecodeString(tc.wire)
		require.NoError(t, err)
		f, ok := openNetfront(b, p.rx, 3, 2)
		require.True(t, ok)
		require.Equal(t, tc.kind, f.kind)
		require.Equal(t, uint64(0x0102030405060708), f.seq)
		for i := range 16 {
			require.Equal(t, byte(i), f.session[i])
			if tc.kind == nfOffer {
				require.Equal(t, byte(i+16), f.token[i])
			}
		}
	}
}

func TestNetFrontSideAuthentication(t *testing.T) {
	o := NetFrontOptions{[]byte(netfrontTestKey), []int{4011, 4012, 4013}}
	c, err := prestoStandard.compileNetfront(o, false)
	require.NoError(t, err)
	s, err := prestoStandard.compileNetfront(o, true)
	require.NoError(t, err)
	o.Password = append(o.Password, 'x')
	other, err := prestoStandard.compileNetfront(o, true)
	require.NoError(t, err)
	a := netfrontAction{lane: 1, wire: 311, frame: netfrontFrame{kind: nfData, session: [16]byte{1}, seq: 12, token: [16]byte{5}, body: bytes.Repeat([]byte("x"), 121)}}
	wire := a.seal(make([]byte, netfrontMaxSide), c.tx, 3)
	f, ok := openNetfront(bytes.Clone(wire), s.rx, 3, 1)
	require.True(t, ok)
	require.Equal(t, a.frame, f)
	for _, decode := range []func([]byte) bool{
		func(b []byte) bool { _, ok := openNetfront(b, s.rx, 3, 2); return ok },
		func(b []byte) bool { _, ok := openNetfront(b, s.rx, 2, 1); return ok },
		func(b []byte) bool { _, ok := openNetfront(b, c.rx, 3, 1); return ok },
		func(b []byte) bool { _, ok := openNetfront(b, other.rx, 3, 1); return ok },
		func(b []byte) bool { b[100] ^= 1; _, ok := openNetfront(b, s.rx, 3, 1); return ok },
	} {
		require.False(t, decode(bytes.Clone(wire)))
	}
	tx, _, err := prestoStandard.prestoCiphers([]byte(netfrontTestKey), false)
	require.NoError(t, err)
	_, rx, err := prestoStandard.prestoCiphers(s.prestoKey, true)
	require.NoError(t, err)
	b := prestoTestFrame(tx, prestoTestHeader(), []byte("legacy"), 0)
	_, err = rx.Open(nil, b[:prestoNonce], b[prestoNonce:], nil)
	require.Error(t, err)
}

func TestNetFrontReachabilityAndSessionBinding(t *testing.T) {
	c, _ := newPrestoTest(t, true)
	p, err := prestoStandard.compileNetfront(NetFrontOptions{[]byte(netfrontTestKey), []int{10, 11}}, true)
	require.NoError(t, err)
	w := netfrontWire{presto: c, profile: p}
	now := time.Now()
	main, source, _ := blinkAddress(blinkClientAddr)
	side := netip.AddrPortFrom(main.Addr(), 45000)
	other := netip.AddrPortFrom(main.Addr(), 45001)
	h := prestoHeaderFields{session: [16]byte{1}, born: uint64(now.Unix()), total: 1, size: 1, count: 1}
	probe := netfrontFrame{kind: nfProbe, session: h.session, seq: 1}
	accept := func(f netfrontFrame, addr netip.AddrPort, lane int, at time.Time) (netip.AddrPort, netfrontAction, bool) {
		return w.acceptSide(f, addr, lane, 105, at)
	}
	_, a, ok := accept(probe, side, 1, now)
	require.False(t, ok)
	require.Zero(t, a.wire)
	_, ok = c.accept(main, source, h, []byte{1}, now)
	require.True(t, ok)
	_, _, ok = accept(probe, netip.MustParseAddrPort("192.0.2.99:4000"), 1, now)
	require.False(t, ok)
	_, a, ok = accept(probe, side, 1, now)
	require.True(t, ok)
	require.Equal(t, 105, a.wire)
	require.Equal(t, side, a.addr)
	_, _, ok = accept(probe, other, 1, now)
	require.False(t, ok) // replay cannot redirect the reply
	f := a.frame
	f.kind = nfData
	for _, bad := range []struct {
		addr netip.AddrPort
		lane int
	}{{other, 1}, {side, 2}} {
		_, _, ok := accept(f, bad.addr, bad.lane, now)
		require.False(t, ok)
	}
	bad := f
	bad.token[1] ^= 1
	_, _, ok = accept(bad, side, 1, now)
	require.False(t, ok)
	require.False(t, c.routes[main].netfront.lanes[0].verified)
	got, _, ok := accept(f, side, 1, now)
	require.True(t, ok)
	require.Equal(t, main, got)
	_, _, ok = accept(f, side, 1, now.Add(netfrontLease))
	require.False(t, ok)
	probe.seq++
	_, a, ok = accept(probe, other, 1, now.Add(2*time.Second))
	require.True(t, ok)
	_, _, ok = accept(f, side, 1, now.Add(2*time.Second))
	require.False(t, ok)
	f = a.frame
	f.kind = nfData
	got, _, ok = accept(f, other, 1, now.Add(2*time.Second))
	require.True(t, ok)
	require.Equal(t, main, got)
	w.fromSide = true
	require.True(t, w.acceptSource(main, h))
	h.session[0]++
	require.False(t, w.acceptSource(main, h)) // cannot introduce a new Presto peer through a side socket
	_, ok = c.accept(main, source, h, []byte{2}, now)
	require.True(t, ok)
	_, _, ok = accept(f, other, 1, now.Add(2*time.Second))
	require.False(t, ok)
}

func TestNetFrontTrafficShapes(t *testing.T) {
	// Same input and artificial clock. Vary only key/session. Check wire
	// budgets for every prefix, not just a final average across many sessions.
	type totals struct {
		main, size, side, wire int
		counts                 [3]int
	}
	run := func(key []byte, id [16]byte) totals {
		p, err := prestoStandard.compileNetfront(NetFrontOptions{key, []int{10, 11, 12}}, false)
		require.NoError(t, err)
		s := p.newSession(id)
		start := time.Unix(100000, 0)
		for i := range s.lanes {
			s.lanes[i] = netfrontLane{seq: 1, verified: true, until: start.Add(time.Hour)}
		}
		var v totals
		for i := range 6000 {
			n := []int{97, 115, 901, 1136, 127, 190, 281}[i%7]
			a := s.choose(&p, nil, n, start.Add(time.Duration(i)*5*time.Millisecond))
			if a.lane != 0 {
				v.side++
				v.counts[a.lane-1]++
				v.wire += a.wire
				require.LessOrEqual(t, a.wire, netfrontMaxSide)
			}
			if a.frame.kind != nfData {
				s.credit(n)
				v.main++
				v.size += n
			}
			require.LessOrEqual(t, v.side*4, v.main)
			require.LessOrEqual(t, v.wire*8, v.size)
		}
		for _, n := range v.counts {
			require.Positive(t, n)
		}
		return v
	}
	seen := map[[3]int]bool{}
	for i := range 8 {
		key := sha256.Sum256([]byte(fmt.Sprintf("netfront-shape-%d", i)))
		first := run(key[:], [16]byte{1})
		second := run(key[:], [16]byte{2})
		require.NotEqual(t, first.counts, second.counts)
		seen[first.counts] = true
		t.Logf("key %d, side packets by port %v / %v, main %d / %d", i, first.counts, second.counts, first.main, second.main)
	}
	require.Len(t, seen, 8)
}

type netfrontTap struct {
	net.PacketConn
	mu                sync.Mutex
	packets, maxBytes int
	drop              bool
	ambiguous         bool // send the UDP packet, then report an ambiguous failure
}

func (s *netfrontTap) WriteTo(b []byte, a net.Addr) (int, error) {
	s.mu.Lock()
	s.packets++
	s.maxBytes = max(s.maxBytes, len(b))
	s.mu.Unlock()
	if s.drop {
		return len(b), nil
	}
	n, err := s.PacketConn.WriteTo(b, a)
	if err == nil && s.ambiguous && len(b) > 160 {
		return 0, io.ErrShortWrite
	}
	return n, err
}

func TestNetFrontSharedListenerAndAmbiguousWrites(t *testing.T) {
	// Two clients share an IP/password, but have six different physical
	// source endpoints. One also retries real side data on main after an
	// ambiguous socket error. Neither duplicates nor cross-delivery are OK.
	sr, ports := netfrontTestSockets(t, 2, false)
	o := NetFrontOptions{[]byte(netfrontTestKey), ports}
	server, err := WrapPacketConnNetFront(sr[0], sr[1:], nil, o)
	require.NoError(t, err)
	defer server.Close()
	until := time.Now().Add(8 * time.Second)
	require.NoError(t, server.SetDeadline(until))
	var clients [2]net.PacketConn
	for i := range clients {
		cr, _ := netfrontTestSockets(t, 2, false)
		for _, sock := range cr[1:] {
			sock.(*netfrontTap).ambiguous = i == 0
		}
		clients[i], err = WrapPacketConnNetFront(cr[0], cr[1:], sr[0].LocalAddr().(*net.UDPAddr), o)
		require.NoError(t, err)
		defer clients[i].Close()
		require.NoError(t, clients[i].SetDeadline(until))
	}
	const count = 180
	results := make(chan error, 3)
	go func() {
		next := [2]int{}
		for range 2 * count {
			var b [32]byte
			n, a, e := server.ReadFrom(b[:])
			if e != nil {
				results <- e
				return
			}
			idx := int(b[0])
			if n != len(b) || idx >= 2 || int(b[1]) != next[idx] || a.String() != clients[idx].LocalAddr().String() {
				results <- fmt.Errorf("duplicate or wrong primary: packet %x at %s, expected %v", b[:2], a, next)
				return
			}
			next[idx]++
			if _, e = server.WriteTo(b[:n], a); e != nil {
				results <- e
				return
			}
		}
		results <- nil
	}()
	for idx, c := range clients {
		go func() {
			for i := range count {
				var b, out [32]byte
				b[0], b[1] = byte(idx), byte(i)
				if _, e := c.WriteTo(b[:], server.LocalAddr()); e != nil {
					results <- e
					return
				}
				n, a, e := c.ReadFrom(out[:])
				if e != nil {
					results <- e
					return
				}
				if n != len(b) || b != out || a.String() != server.LocalAddr().String() {
					results <- fmt.Errorf("wrong reply %x for %x", out[:2], b[:2])
					return
				}
			}
			results <- nil
		}()
	}
	for range 3 {
		require.NoError(t, <-results)
	}
	first := clients[0].(*netfrontConn).NetFrontStats()
	require.Positive(t, first.Lanes[1].WriteErrors+first.Lanes[2].WriteErrors)
	seen := server.(*netfrontConn).NetFrontStats()
	for _, lane := range seen.Lanes[1:3] {
		require.GreaterOrEqual(t, lane.VerifiedPaths, uint64(2))
	}
}

func netfrontTestSockets(t *testing.T, count int, dropSides bool) ([]net.PacketConn, []int) {
	t.Helper()
	socks := make([]net.PacketConn, count+1)
	var ports []int
	for i := range socks {
		s, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { s.Close() })
		socks[i] = &netfrontTap{PacketConn: s, drop: dropSides && i > 0}
		if i > 0 {
			ports = append(ports, s.LocalAddr().(*net.UDPAddr).Port)
		}
	}
	return socks, ports
}

func TestNetFrontLoopbackPorts(t *testing.T) {
	for _, mode := range []string{"three", "blocked", "swapped", "two-lite", "three-lite", "blocked-lite"} {
		t.Run(mode, func(t *testing.T) {
			count := 2
			if mode == "three" || mode == "three-lite" {
				count = 3
			}
			wrap := WrapPacketConnNetFront
			lite := mode == "two-lite" || mode == "three-lite" || mode == "blocked-lite"
			if lite {
				wrap = WrapPacketConnNetFrontLite
			}
			blocked := mode == "blocked" || mode == "blocked-lite"
			reachable := !blocked && mode != "swapped"
			sr, ports := netfrontTestSockets(t, count, false)
			cr, _ := netfrontTestSockets(t, count, blocked)
			o := NetFrontOptions{[]byte(netfrontTestKey), ports}
			server, err := wrap(sr[0], sr[1:], nil, o)
			require.NoError(t, err)
			defer server.Close()
			if mode == "swapped" {
				o.ExtraPorts = []int{ports[1], ports[0]}
			}
			client, err := wrap(cr[0], cr[1:], sr[0].LocalAddr().(*net.UDPAddr), o)
			require.NoError(t, err)
			defer client.Close()
			require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))
			require.NoError(t, server.SetDeadline(time.Now().Add(10*time.Second)))
			echoErr := make(chan error, 1)
			const messages = 240
			go func() {
				var b [1200]byte
				for range messages {
					n, a, e := server.ReadFrom(b[:])
					if e == nil && a.String() != client.LocalAddr().String() {
						e = fmt.Errorf("QUIC saw side source %v", a)
					}
					if e == nil {
						_, e = server.WriteTo(b[:n], a)
					}
					if e != nil {
						echoErr <- e
						return
					}
				}
				echoErr <- nil
			}()
			for i := range messages {
				size := 16
				// Begin with small messages so the first eligible burst can
				// carry real data regardless of the session's random cadence.
				if i >= 140 && i%5 == 0 {
					size = 1200
				}
				b := bytes.Repeat([]byte{byte(i)}, size)
				_, e := client.WriteTo(b, server.LocalAddr())
				require.NoError(t, e)
				var out [1200]byte
				n, a, e := client.ReadFrom(out[:])
				require.NoError(t, e)
				require.Equal(t, server.LocalAddr().String(), a.String())
				require.Equal(t, b, out[:n])
			}
			require.NoError(t, <-echoErr)
			for i, pc := range []net.PacketConn{client, server} {
				raw := [][]net.PacketConn{cr, sr}[i]
				require.Equal(t, lite, pc.(*netfrontConn).wire.presto.lite != nil)
				stats := pc.(*netfrontConn).NetFrontStats()
				var totalSide, sideData uint64
				for j := 1; j <= count; j++ {
					l := stats.Lanes[j]
					tap := raw[j].(*netfrontTap)
					tap.mu.Lock()
					n, size := tap.packets, tap.maxBytes
					tap.mu.Unlock()
					require.Equal(t, int(l.SentPackets), n)
					require.LessOrEqual(t, size, netfrontMaxSide)
					if reachable {
						require.Positive(t, l.VerifiedPaths, "port %d: %+v", j, stats)
						require.Positive(t, l.Data+l.Cover)
					} else {
						require.Zero(t, l.VerifiedPaths)
						require.Zero(t, l.Data+l.Cover)
						if i == 0 {
							require.Positive(t, l.Probes)
						} else {
							require.Zero(t, l.Offers)
						}
					}
					totalSide += l.SentPackets
					sideData += l.Data
				}
				if reachable {
					require.Positive(t, sideData, "both directions carry real small frames")
				}
				require.Less(t, totalSide, stats.Lanes[0].SentPackets)
				t.Logf("%s end %d: %+v", mode, i, stats)
			}
		})
	}
}

func TestNetFrontDeadlineAndClose(t *testing.T) {
	raw, ports := netfrontTestSockets(t, 2, false)
	pc, err := WrapPacketConnNetFront(raw[0], raw[1:], nil, NetFrontOptions{[]byte(netfrontTestKey), ports})
	require.NoError(t, err)
	defer pc.Close()
	read := func() chan error {
		done := make(chan error, 1)
		go func() { _, _, e := pc.ReadFrom(make([]byte, 1200)); done <- e }()
		return done
	}
	wait := func(done chan error, want error) {
		select {
		case e := <-done:
			require.ErrorIs(t, e, want)
		case <-time.After(2 * time.Second):
			t.Fatal("reader did not wake")
		}
	}
	done := read()
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(time.Millisecond)))
	wait(done, os.ErrDeadlineExceeded)
	require.NoError(t, pc.SetReadDeadline(time.Time{}))
	done = read()
	require.NoError(t, pc.Close())
	wait(done, net.ErrClosed)
	for _, s := range raw {
		_, err = s.WriteTo([]byte{1}, s.LocalAddr())
		require.ErrorIs(t, err, net.ErrClosed)
	}
}

// Keep io's standard short-write behavior explicit for partial UDP writes.
type netfrontShortWrite struct{ net.PacketConn }

func (s netfrontShortWrite) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b) - 1, nil }

func TestNetFrontMainWriteFailure(t *testing.T) {
	raw, ports := netfrontTestSockets(t, 2, false)
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:443"))
	pc, err := WrapPacketConnNetFront(netfrontShortWrite{raw[0]}, raw[1:], remote, NetFrontOptions{[]byte(netfrontTestKey), ports})
	require.NoError(t, err)
	defer pc.Close()
	n, err := pc.WriteTo([]byte("test"), remote)
	require.Zero(t, n)
	require.ErrorIs(t, err, io.ErrShortWrite)
}
