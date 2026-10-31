// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var prestoTestPassword = []byte("presto-test-only-32-byte-secret!!")

func newPrestoTest(t testing.TB, server bool) (*prestoPacketConn, *blinkTestConn) {
	t.Helper()
	raw := &blinkTestConn{}
	w, err := WrapPacketConnPresto(raw, PrestoOptions{Password: prestoTestPassword, Server: server})
	require.NoError(t, err)
	return w.(*prestoPacketConn), raw
}

func prestoTestFrame(aead cipher.AEAD, h prestoHeaderFields, payload []byte, pad int) []byte {
	out := make([]byte, prestoOverhead+len(payload)+pad)
	_, _ = rand.Read(out[:prestoNonce])
	h.encode(out[prestoNonce:])
	copy(out[prestoNonce+prestoHeader:], payload)
	return aead.Seal(out[:prestoNonce], out[:prestoNonce], out[prestoNonce:len(out)-16], nil)
}

func prestoTestHeader() prestoHeaderFields {
	return prestoHeaderFields{session: [16]byte{1}, born: uint64(time.Now().Unix()), total: 1200, size: 600, count: 2}
}

func TestPrestoCompilerAndPlanner(t *testing.T) {
	g, err := compilePrestoGenome(prestoTestPassword, false)
	require.NoError(t, err)
	again, err := compilePrestoGenome(prestoTestPassword, false)
	require.NoError(t, err)
	require.Equal(t, g, again)
	reverse, err := compilePrestoGenome(prestoTestPassword, true)
	require.NoError(t, err)
	require.NotEqual(t, g, reverse)
	t.Logf("v1 compiler golden: %x", sha256.Sum256([]byte(fmt.Sprintf("%#v", g))))
	require.Equal(t, "f8f10d7795fd2d4465a89a942840e828d6232ba254dec091f7fbc30ff9f7d0f5", fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%#v", g)))))
	seen := make(map[string]bool)
	for password := range 64 {
		key := sha256.Sum256([]byte(fmt.Sprintf("presto-planner-%d", password)))
		g, err := compilePrestoGenome(key[:], password%2 == 0)
		require.NoError(t, err)
		seed := sha256.Sum256([]byte(fmt.Sprintf("runtime-seed-%d", password)))
		s := newPrestoGrammar(g, seed)
		seen[fmt.Sprint(g)] = true
		for size := 1; size <= 1200; size++ {
			p := s.plan(size)
			require.GreaterOrEqual(t, p.count, 1)
			require.LessOrEqual(t, p.count, 4)
			offset, padding := 0, 0
			for _, part := range p.parts[:p.count] {
				require.Equal(t, offset, part.offset)
				require.Positive(t, part.size)
				require.LessOrEqual(t, part.wire, prestoWireMax)
				require.GreaterOrEqual(t, part.wire, part.size+prestoOverhead)
				offset += part.size
				padding += part.wire - part.size - prestoOverhead
				require.LessOrEqual(t, s.gap(part.mode), 2500*time.Microsecond)
			}
			require.Equal(t, size, offset)
			require.LessOrEqual(t, padding, size/3)
		}
		for _, server := range []bool{false, true} {
			for range 16 {
				prelude := s.prelude(server)
				total := 0
				for _, n := range prelude {
					total += n
				}
				if server {
					require.LessOrEqual(t, len(prelude), 3)
					require.LessOrEqual(t, total, 480)
				} else {
					require.LessOrEqual(t, len(prelude), 4)
					require.LessOrEqual(t, total, 768)
				}
			}
		}
	}
	require.Len(t, seen, 64)
}

func TestPrestoOptionsAndSocketContract(t *testing.T) {
	_, err := WrapPacketConnPresto(nil, PrestoOptions{Password: prestoTestPassword})
	require.Error(t, err)
	for _, n := range []int{0, 1, 31, 1025} {
		_, err := WrapPacketConnPresto(fakePlainConn{}, PrestoOptions{Password: bytes.Repeat([]byte{1}, n)})
		require.Error(t, err)
	}
	w, err := WrapPacketConnPresto(fakeUDPLikeConn{}, PrestoOptions{Password: prestoTestPassword})
	require.NoError(t, err)
	udp := w.(*prestoPacketConnUDP)
	require.Equal(t, 1200, udp.QUICPacketSizeLimit())
	_, err = udp.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, udp.SetReadBuffer(100))
	require.NoError(t, udp.SetWriteBuffer(100))
	require.NotNil(t, udp.LocalAddr())
	require.NoError(t, udp.SetDeadline(time.Time{}))
	_, bypass := w.(interface {
		ReadMsgUDP([]byte, []byte) (int, int, int, *net.UDPAddr, error)
	})
	require.False(t, bypass)
	require.NoError(t, w.Close())
	require.NoError(t, w.Close())
	require.ErrorIs(t, w.SetWriteDeadline(time.Now()), net.ErrClosed)
}

func TestPrestoAuthenticationAndCodec(t *testing.T) {
	tx, rx, err := prestoCiphers(prestoTestPassword, false)
	require.NoError(t, err)
	_, srx, err := prestoCiphers(prestoTestPassword, true)
	require.NoError(t, err)
	h := prestoTestHeader()
	h.total = 6
	h.size = 6
	h.count = 1
	wire := prestoTestFrame(tx, h, []byte("secret"), 32)
	plain, err := srx.Open(nil, wire[:prestoNonce], wire[prestoNonce:], nil)
	require.NoError(t, err)
	got, payload, err := decodePrestoHeader(plain)
	require.NoError(t, err)
	require.Equal(t, h, got)
	require.Equal(t, []byte("secret"), payload)
	_, err = rx.Open(nil, wire[:prestoNonce], wire[prestoNonce:], nil)
	require.Error(t, err)
	_, wrong, _ := prestoCiphers(bytes.Repeat([]byte{2}, 32), true)
	_, err = wrong.Open(nil, wire[:prestoNonce], wire[prestoNonce:], nil)
	require.Error(t, err)
	_, blinkRX, _ := blinkCiphers(prestoTestPassword, true)
	_, err = blinkRX.Open(nil, wire[:prestoNonce], wire[prestoNonce:], nil)
	require.Error(t, err)
	for _, i := range []int{0, 24, len(wire) - 1} {
		bad := bytes.Clone(wire)
		bad[i] ^= 1
		_, err = srx.Open(nil, bad[:prestoNonce], bad[prestoNonce:], nil)
		require.Error(t, err)
	}
	for _, size := range []int{0, 1, 43} {
		_, _, err = decodePrestoHeader(make([]byte, size))
		require.Error(t, err)
	}
	for _, change := range []func([]byte){
		func(p []byte) { clear(p[:16]) }, func(p []byte) { clear(p[24:32]) }, func(p []byte) { p[41] = 2 }, func(p []byte) { p[42] = 1 }, func(p []byte) { p[43] = 1 },
		func(p []byte) { p[39] = 0 }, func(p []byte) { p[39] = 5 }, func(p []byte) { p[38] = 1 }, func(p []byte) { p[40] = 2 }, func(p []byte) { p[32] = 255 }, func(p []byte) { p[35] = 1 }, func(p []byte) { p[37] = 7 },
	} {
		bad := bytes.Clone(plain)
		change(bad)
		_, _, err = decodePrestoHeader(bad)
		require.Error(t, err)
	}
	h = prestoHeaderFields{session: [16]byte{1}, born: 1, count: 1, kind: prestoCover}
	buf := make([]byte, prestoHeader)
	h.encode(buf)
	_, _, err = decodePrestoHeader(buf)
	require.NoError(t, err)
	h.total = 1
	h.encode(buf)
	_, _, err = decodePrestoHeader(buf)
	require.Error(t, err)
	h.total = 0
	buf = make([]byte, prestoHeader+80)
	h.encode(buf)
	_, _, err = decodePrestoHeader(buf)
	require.Error(t, err)
}

func TestPrestoWireRoundTripReorderAndBudgets(t *testing.T) {
	c, cr := newPrestoTest(t, false)
	s, sr := newPrestoTest(t, true)
	_, err := s.WriteTo([]byte{1}, blinkClientAddr)
	require.ErrorContains(t, err, "route")
	require.Empty(t, sr.output)
	original := bytes.Repeat([]byte{0xa1}, 1200)
	_, err = c.WriteTo(original, blinkServerAddr)
	require.NoError(t, err)
	// Junk, reverse-order data, duplicates and an oversized unauthenticated
	// packet must not be delivered or kill a UDP listener.
	sr.readErrors = []error{syscall.EMSGSIZE}
	sr.input = append(sr.input, blinkTestPacket{make([]byte, 4096), blinkClientAddr})
	for i := len(cr.output) - 1; i >= 0; i-- {
		sr.input = append(sr.input, blinkTestPacket{cr.output[i], blinkClientAddr}, blinkTestPacket{cr.output[i], blinkClientAddr})
	}
	out := make([]byte, 1200)
	n, addr, err := s.ReadFrom(out)
	require.NoError(t, err)
	require.Equal(t, original, out[:n])
	require.Equal(t, blinkClientAddr, addr)
	_, err = s.WriteTo(original, addr)
	require.NoError(t, err)
	for _, p := range sr.output {
		cr.input = append(cr.input, blinkTestPacket{p, blinkServerAddr})
	}
	n, _, err = c.ReadFrom(out)
	require.NoError(t, err)
	require.Equal(t, original, out[:n])
	require.Positive(t, c.PrestoStats().ReceivedCoverPackets)
	for range 32 {
		_, err = c.WriteTo(original, blinkServerAddr)
		require.NoError(t, err)
	}
	stats := c.PrestoStats()
	require.LessOrEqual(t, stats.PreludePackets, uint64(4))
	require.LessOrEqual(t, stats.PreludeBytes, uint64(768))
	require.LessOrEqual(t, stats.PaddingBytes, stats.SentInnerBytes/3)
	require.Equal(t, stats.SentInnerBytes+(stats.SentPackets-stats.PreludePackets)*prestoOverhead+stats.PaddingBytes+stats.PreludeBytes, stats.SentWireBytes)
	for _, p := range cr.output {
		require.LessOrEqual(t, len(p), 1232)
	}
	for _, p := range sr.output {
		require.LessOrEqual(t, len(p), 1232)
	}
	// Complete the queued duplicates: no second delivery.
	_, _, err = s.ReadFrom(out)
	require.ErrorIs(t, err, io.EOF)
	require.Positive(t, s.PrestoStats().ReplayDrops)
	require.NoError(t, c.Close())
	require.NoError(t, s.Close())
}

func TestPrestoResourceLimitsAndFreshness(t *testing.T) {
	c, _ := newPrestoTest(t, true)
	now := time.Now()
	ap, source, _ := blinkAddress(blinkClientAddr)
	h := prestoTestHeader()
	for i := range 40 {
		h.message = uint64(i)
		_, ready := c.accept(ap, source, h, make([]byte, 600), now)
		require.False(t, ready)
	}
	require.Len(t, c.assemblies, 32)
	require.Equal(t, uint64(8), c.stats.EvictedAssemblies)
	// A different endpoint cannot replay the same live session.
	other := netip.AddrPortFrom(ap.Addr(), ap.Port()+1)
	c.accept(other, source, h, make([]byte, 600), now)
	require.Positive(t, c.stats.ReplayDrops)
	for i := 1; i < 9; i++ {
		h.session = [16]byte{byte(i + 1)}
		c.accept(other, source, h, make([]byte, 600), now)
	}
	require.Len(t, c.peers, 8)
	require.Positive(t, c.stats.ResourceDrops)
	c.maintain(now.Add(4*time.Second), 1024)
	require.Zero(t, c.assemblyBytes)
	c.maintain(now.Add(3*time.Minute), 1024)
	require.Empty(t, c.peers)
	require.Empty(t, c.senders)
	require.Empty(t, c.sources)
	c.accept(ap, source, h, make([]byte, 600), now.Add(3*time.Minute))
	require.Positive(t, c.stats.FreshnessDrops)
	require.Empty(t, c.peers)
	h.born = math.MaxUint64
	c.accept(ap, source, h, make([]byte, 600), now)
	require.Empty(t, c.peers)
	// Global slots cannot be reclaimed by a different peer.
	c, _ = newPrestoTest(t, true)
	h = prestoTestHeader()
	h.born = uint64(now.Unix()) // Keep one session's birth fixed across wall-clock seconds.
	for i := range 512 {
		h.session = [16]byte{byte(i/32 + 1)}
		h.message = uint64(i % 32)
		ap, source, _ = blinkAddress(&net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(i/32+1)), Port: 1234})
		c.accept(ap, source, h, make([]byte, 600), now)
	}
	require.Len(t, c.assemblies, 512)
	require.Equal(t, 600*1024, c.assemblyBytes)
	h.session = [16]byte{99}
	c.accept(ap, source, h, make([]byte, 600), now)
	require.Len(t, c.assemblies, 512)
	require.Positive(t, c.stats.ResourceDrops)
	require.NoError(t, c.Close())
	require.Zero(t, c.PrestoStats().ReassemblyBytes)
}

func TestPrestoOverlapGapsConflictsAndTTL(t *testing.T) {
	for _, name := range []string{"overlap", "gap", "total", "count", "single", "expired", "born", "cover"} {
		t.Run(name, func(t *testing.T) {
			c, _ := newPrestoTest(t, name != "cover")
			now := time.Now()
			ap, source, _ := blinkAddress(blinkClientAddr)
			h := prestoTestHeader()
			c.accept(ap, source, h, make([]byte, 600), now)
			h.index = 1
			h.offset = 600
			switch name {
			case "overlap":
				h.offset = 500
			case "gap":
				h.size = 500
			case "total":
				h.total = 1199
				h.size = 599
			case "count":
				h.count = 3
			case "single":
				h.count = 1
				h.index = 0
				h.offset = 0
				h.size = 1200
			case "expired":
				now = now.Add(3 * time.Second)
			case "born":
				h.born++
			case "cover":
				h.kind = prestoCover
				h.size = 0
				h.total = 0
				h.offset = 0
				h.index = 0
				h.count = 1
			}
			_, ready := c.accept(ap, source, h, make([]byte, h.size), now)
			require.False(t, ready)
			if name != "born" && name != "count" {
				require.Empty(t, c.assemblies)
			}
		})
	}
}

func TestPrestoInvalidInputAndWriteErrors(t *testing.T) {
	c, raw := newPrestoTest(t, true)
	for range 10000 {
		raw.input = append(raw.input, blinkTestPacket{make([]byte, 100), blinkClientAddr})
	}
	_, _, err := c.ReadFrom(make([]byte, 1200))
	require.ErrorIs(t, err, io.EOF)
	stats := c.PrestoStats()
	require.Zero(t, stats.Sessions)
	require.Zero(t, stats.ReassemblyBytes)
	require.Positive(t, stats.AuthDrops)
	require.Positive(t, stats.RateDrops)
	require.Empty(t, raw.output)
	c, raw = newPrestoTest(t, false)
	for _, data := range [][]byte{nil, make([]byte, 1201)} {
		_, err = c.WriteTo(data, blinkServerAddr)
		require.ErrorIs(t, err, ErrPrestoPacketSize)
	}
	_, err = c.WriteTo([]byte{1}, nil)
	require.Error(t, err)
	raw.short = true
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, io.ErrShortWrite)
	raw.short = false
	raw.fail = true
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	raw.fail = false
	_, err = c.WriteTo([]byte{1}, blinkClientAddr)
	require.ErrorContains(t, err, "one UDP endpoint")
	s := c.senders[netip.MustParseAddrPort("127.0.0.1:30002")]
	s.next = math.MaxUint64
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorContains(t, err, "counter exhausted")
	require.NoError(t, c.Close())
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, net.ErrClosed)
	server, sr := newPrestoTest(t, true)
	tx, _, _ := prestoCiphers(prestoTestPassword, false)
	h := prestoTestHeader()
	h.count = 1
	h.total = 200
	h.size = 200
	sr.input = []blinkTestPacket{{prestoTestFrame(tx, h, make([]byte, 200), 0), blinkClientAddr}}
	_, _, err = server.ReadFrom(make([]byte, 1))
	require.ErrorIs(t, err, io.ErrShortBuffer)
}

func TestPrestoWaitCloseAndDeadline(t *testing.T) {
	for _, closeIt := range []bool{false, true} {
		c, _ := newPrestoTest(t, false)
		done := make(chan error, 1)
		go func() { done <- c.waitUntil(time.Now().Add(time.Hour)) }()
		if closeIt {
			require.NoError(t, c.Close())
		} else {
			require.NoError(t, c.SetWriteDeadline(time.Now().Add(-time.Second)))
		}
		select {
		case err := <-done:
			if closeIt {
				require.ErrorIs(t, err, net.ErrClosed)
			} else {
				require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			}
		case <-time.After(time.Second):
			t.Fatal("wait not interrupted")
		}
	}
	c, _ := newPrestoTest(t, false)
	require.NoError(t, c.waitUntil(time.Now().Add(time.Microsecond)))
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			c.PrestoStats()
		}
	})
	wg.Go(func() {
		for range 100 {
			_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		}
	})
	wg.Go(func() { _ = c.Close() })
	wg.Wait()
}

func TestPrestoSenderRotationAndRandomness(t *testing.T) {
	c, _ := newPrestoTest(t, false)
	ap, _, _ := blinkAddress(blinkServerAddr)
	now := time.Now()
	s, err := c.sender(ap, now)
	require.NoError(t, err)
	same, err := c.sender(ap, now.Add(10*time.Second))
	require.NoError(t, err)
	require.Same(t, s, same)
	rotated, err := c.sender(ap, now.Add(2*time.Minute))
	require.NoError(t, err)
	require.NotEqual(t, s.session, rotated.session)
	rotated.used = now.Add(11 * time.Minute)
	again, err := c.sender(ap, now.Add(13*time.Minute))
	require.NoError(t, err)
	require.NotEqual(t, again.session, rotated.session)
	seen := map[[16]byte]bool{}
	for range 32 {
		c, _ := newPrestoTest(t, false)
		s, err := c.sender(ap, now)
		require.NoError(t, err)
		require.False(t, seen[s.session])
		seen[s.session] = true
	}
}

func TestPrestoNewClientSameEndpointGetsFreshServerSession(t *testing.T) {
	c, _ := newPrestoTest(t, true)
	now := time.Now()
	ap, source, _ := blinkAddress(blinkClientAddr)
	h := prestoTestHeader()
	h.count = 1
	h.total = 1
	h.size = 1
	_, ready := c.accept(ap, source, h, []byte{1}, now)
	require.True(t, ready)
	old, err := c.sender(ap, now)
	require.NoError(t, err)
	h.session = [16]byte{2}
	h.born = uint64(now.Add(time.Minute).Unix())
	_, ready = c.accept(ap, source, h, []byte{1}, now.Add(time.Minute))
	require.True(t, ready)
	fresh, err := c.sender(ap, now.Add(time.Minute))
	require.NoError(t, err)
	require.NotEqual(t, old.session, fresh.session)
	require.Equal(t, h.born, fresh.born)
}

func FuzzPrestoDecode(f *testing.F) {
	f.Add([]byte{})
	h := prestoTestHeader()
	seed := make([]byte, prestoHeader+600)
	h.encode(seed)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 2048 {
			in = in[:2048]
		}
		h, p, err := decodePrestoHeader(in)
		if err == nil && (len(p) != int(h.size) || h.count > 4 || h.index >= h.count || int(h.offset)+int(h.size) > 1200) {
			t.Fatal("invalid accepted header")
		}
	})
}

func FuzzPrestoReceive(f *testing.F) {
	f.Add([]byte{})
	tx, _, _ := prestoCiphers(prestoTestPassword, false)
	h := prestoTestHeader()
	f.Add(prestoTestFrame(tx, h, make([]byte, 600), 0))
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 2048 {
			in = in[:2048]
		}
		c, raw := newPrestoTest(t, true)
		raw.input = []blinkTestPacket{{in, blinkClientAddr}, {in, blinkClientAddr}}
		_, _, err := c.ReadFrom(make([]byte, 1200))
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		s := c.PrestoStats()
		if s.Sessions > 1024 || s.Assemblies > 512 || s.ReassemblyBytes > 600*1024 {
			t.Fatal(s)
		}
	})
}

func FuzzPrestoAuthenticatedState(f *testing.F) {
	f.Add([]byte{0, 2, 0, 0, 10, 20, 30, 40, 1, 2, 1, 0, 60, 80, 90, 100})
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 2048 {
			in = in[:2048]
		}
		c, raw := newPrestoTest(t, true)
		tx, _, _ := prestoCiphers(prestoTestPassword, false)
		for i := 0; i+8 <= len(in); i += 8 {
			b := in[i : i+8]
			h := prestoTestHeader()
			h.session = [16]byte{1 + b[0]%16}
			h.message = uint64(b[1])
			h.count = 1 + b[2]%4
			h.index = b[3] % h.count
			h.total = 1 + uint16(b[4])*4
			h.offset = uint16(b[5]) * 2
			h.size = 1 + uint16(b[6])*3
			if h.count == 1 {
				h.offset = 0
				h.size = h.total
			}
			if b[7]&8 != 0 {
				h.born = 1
			}
			if b[7]&16 != 0 {
				h.kind = prestoCover
			}
			wire := prestoTestFrame(tx, h, make([]byte, h.size), int(b[7])%64)
			raw.input = append(raw.input, blinkTestPacket{wire, blinkClientAddr})
		}
		for {
			_, _, err := c.ReadFrom(make([]byte, 1200))
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		s := c.PrestoStats()
		if s.Sessions > 8 || s.Assemblies > 256 || s.ReassemblyBytes > 600*1024 {
			t.Fatal(s)
		}
		c.mu.Lock()
		c.maintain(time.Now().Add(3*time.Minute), 1024)
		c.mu.Unlock()
		if c.PrestoStats().ReassemblyBytes != 0 {
			t.Fatal("expired state retained")
		}
	})
}

func BenchmarkPrestoPlanner(b *testing.B) {
	g, err := compilePrestoGenome(prestoTestPassword, false)
	if err != nil {
		b.Fatal(err)
	}
	s := newPrestoGrammar(g, sha256.Sum256([]byte("benchmark-runtime-seed")))
	b.ReportAllocs()
	b.SetBytes(1200)
	b.ResetTimer()
	for range b.N {
		p := s.plan(1200)
		for _, part := range p.parts[:p.count] {
			s.gap(part.mode)
		}
	}
}
