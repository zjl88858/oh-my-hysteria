// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	blinkTestPassword = []byte("test-only-blink-32-byte-password!")
	blinkClientAddr   = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30001}
	blinkServerAddr   = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30002}
)

func blinkInt(n int) *int { return &n }

type (
	blinkTestPacket struct {
		data []byte
		addr net.Addr
	}
	blinkTestConn struct {
		fakePlainConn
		input      []blinkTestPacket
		output     [][]byte
		short      bool
		fail       bool
		closed     bool
		readErrors []error
	}
)

func (c *blinkTestConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.readErrors) > 0 {
		err := c.readErrors[0]
		c.readErrors = c.readErrors[1:]
		return 0, nil, err
	}
	if len(c.input) == 0 {
		return 0, nil, io.EOF
	}
	packet := c.input[0]
	c.input = c.input[1:]
	return copy(p, packet.data), packet.addr, nil
}

func (c *blinkTestConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.fail {
		return 0, io.ErrClosedPipe
	}
	if c.short {
		return len(p) - 1, nil
	}
	c.output = append(c.output, bytes.Clone(p))
	return len(p), nil
}
func (c *blinkTestConn) Close() error { c.closed = true; return nil }
func newBlinkTest(t testing.TB, opts BlinkOptions) (*blinkPacketConn, *blinkTestConn) {
	t.Helper()
	opts.Password = blinkTestPassword
	raw := &blinkTestConn{}
	w, err := WrapPacketConnBlink(raw, opts)
	require.NoError(t, err)
	return w.(*blinkPacketConn), raw
}

func blinkTestFrame(aead cipher.AEAD, h blinkHeaderFields, payload []byte, pad int) []byte {
	out := make([]byte, blinkNonce+blinkHeader+len(payload)+pad+16)
	_, _ = rand.Read(out[:blinkNonce])
	h.encode(out[blinkNonce:])
	copy(out[blinkNonce+blinkHeader:], payload)
	return aead.Seal(out[:blinkNonce], out[:blinkNonce], out[blinkNonce:len(out)-16], nil)
}

func TestBlinkOptionsAndUDPContract(t *testing.T) {
	_, err := WrapPacketConnBlink(nil, BlinkOptions{})
	require.Error(t, err)
	for _, o := range []BlinkOptions{
		{},
		{Password: []byte("short")},
		{Password: bytes.Repeat([]byte{1}, 1025)},
		{MaxPacketSize: 511},
		{MaxPacketSize: 1401},
		{MaxPacketSize: 1232},
		{PaddingMax: blinkInt(-1)},
		{PaddingMax: blinkInt(129)},
		{JunkPackets: blinkInt(5)},
		{Server: true, JunkPackets: blinkInt(1)},
		{MaxSessions: -1},
		{MaxSessions: 4097},
		{MaxReassemblyBytes: 1},
		{MaxReassemblyBytes: 8*1024*1024 + 1},
		{VerifyPacketsPerSecond: 63},
		{VerifyPacketsPerSecond: 262145},
	} {
		if o.Password == nil && (o.MaxPacketSize != 0 || o.PaddingMax != nil || o.JunkPackets != nil || o.MaxSessions != 0 || o.MaxReassemblyBytes != 0 || o.VerifyPacketsPerSecond != 0) {
			o.Password = blinkTestPassword
		}
		_, err := WrapPacketConnBlink(fakePlainConn{}, o)
		require.Error(t, err)
	}
	pad := 12
	w, err := WrapPacketConnBlink(fakeUDPLikeConn{}, BlinkOptions{Password: blinkTestPassword, PaddingMax: &pad})
	require.NoError(t, err)
	udp := w.(*blinkPacketConnUDP)
	pad = 99
	require.Equal(t, 12, *udp.opts.PaddingMax)
	_, err = udp.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, udp.SetReadBuffer(10))
	require.NoError(t, udp.SetWriteBuffer(10))
	require.Equal(t, 1200, udp.QUICPacketSizeLimit())
	_, oob := w.(interface {
		ReadMsgUDP([]byte, []byte) (int, int, int, *net.UDPAddr, error)
	})
	require.False(t, oob)
}

func TestBlinkCodecAuthenticationAndValidation(t *testing.T) {
	tx, rx, err := blinkCiphers(blinkTestPassword, false)
	require.NoError(t, err)
	_, serverRX, err := blinkCiphers(blinkTestPassword, true)
	require.NoError(t, err)
	h := blinkHeaderFields{session: [16]byte{1}, message: 42, total: 6, size: 6, count: 1}
	wire := blinkTestFrame(tx, h, []byte("secret"), 32)
	plain, err := serverRX.Open(nil, wire[:blinkNonce], wire[blinkNonce:], nil)
	require.NoError(t, err)
	got, payload, err := decodeBlinkHeader(plain)
	require.NoError(t, err)
	require.Equal(t, h, got)
	require.Equal(t, []byte("secret"), payload)
	_, err = rx.Open(nil, wire[:blinkNonce], wire[blinkNonce:], nil)
	require.Error(t, err, "direction keys prevent reflection")
	for _, i := range []int{0, 24, len(wire) - 1} {
		bad := bytes.Clone(wire)
		bad[i] ^= 1
		_, err = serverRX.Open(nil, bad[:blinkNonce], bad[blinkNonce:], nil)
		require.Error(t, err)
	}
	for _, size := range []int{0, 1, 31} {
		_, _, err = decodeBlinkHeader(make([]byte, size))
		require.Error(t, err)
	}
	for _, change := range []func([]byte){
		func(p []byte) { p[30] = 2 }, func(p []byte) { p[31] = 1 }, func(p []byte) { clear(p[:16]) },
		func(p []byte) { p[29] = 0 }, func(p []byte) { p[29] = 5 }, func(p []byte) { p[28] = 1 },
		func(p []byte) { p[24] = 255 }, func(p []byte) { p[27] = 7 },
	} {
		bad := bytes.Clone(plain)
		change(bad)
		_, _, err = decodeBlinkHeader(bad)
		require.Error(t, err)
	}
}

func TestBlinkWirePaddingFragmentAndPreludeBudgets(t *testing.T) {
	for _, fragment := range []bool{false, true} {
		c, raw := newBlinkTest(t, BlinkOptions{Fragmentation: fragment, JunkPackets: blinkInt(4)})
		for range 256 {
			n, err := c.WriteTo(bytes.Repeat([]byte{0xab}, 1200), blinkServerAddr)
			require.NoError(t, err)
			require.Equal(t, 1200, n)
		}
		s := c.BlinkStats()
		require.Equal(t, uint64(4), s.JunkPackets)
		require.LessOrEqual(t, s.JunkBytes, uint64(768))
		require.LessOrEqual(t, s.PaddingBytes, s.SentInnerBytes/10)
		require.LessOrEqual(t, s.SentPackets-s.JunkPackets, uint64(256+256/4))
		require.Equal(t, s.SentInnerBytes+(s.SentPackets-s.JunkPackets)*blinkOverhead+s.PaddingBytes+s.JunkBytes, s.SentWireBytes)
		for _, p := range raw.output {
			require.LessOrEqual(t, len(p), 1400)
		}
		if fragment {
			require.Positive(t, s.FragmentedMessages)
		} else {
			require.Zero(t, s.FragmentedMessages)
		}
		n, err := c.WriteTo(make([]byte, 1201), blinkServerAddr)
		require.Zero(t, n)
		require.ErrorIs(t, err, ErrBlinkPacketSize)
		_, err = c.WriteTo(nil, blinkServerAddr)
		require.Error(t, err)
		_, err = c.WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30003})
		require.Error(t, err)
	}
}

func TestBlinkReorderDuplicateRoundTripAndClose(t *testing.T) {
	client, clientRaw := newBlinkTest(t, BlinkOptions{MaxPacketSize: 512, Fragmentation: true, JunkPackets: blinkInt(0)})
	server, serverRaw := newBlinkTest(t, BlinkOptions{Server: true, Fragmentation: true})
	_, err := server.WriteTo([]byte("no reflection"), blinkClientAddr)
	require.Error(t, err)
	require.Empty(t, serverRaw.output)
	original := bytes.Repeat([]byte{0x80}, 1200)
	_, err = client.WriteTo(original, blinkServerAddr)
	require.NoError(t, err)
	require.Len(t, clientRaw.output, 3)
	for _, i := range []int{2, 2, 0, 1} {
		serverRaw.input = append(serverRaw.input, blinkTestPacket{clientRaw.output[i], blinkClientAddr})
	}
	buf := make([]byte, 1200)
	n, addr, err := server.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, blinkClientAddr, addr)
	require.Equal(t, original, buf[:n])
	require.Equal(t, uint64(1), server.BlinkStats().ReplayDrops)
	require.Zero(t, server.BlinkStats().ReassemblyBytes)
	_, err = server.WriteTo([]byte("reply"), addr)
	require.NoError(t, err)
	for _, p := range serverRaw.output {
		clientRaw.input = append(clientRaw.input, blinkTestPacket{p, blinkServerAddr})
	}
	n, _, err = client.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "reply", string(buf[:n]))
	// Replaying any completed fragment cannot recreate a reassembly object.
	serverRaw.input = []blinkTestPacket{{clientRaw.output[0], blinkClientAddr}}
	_, _, err = server.ReadFrom(buf)
	require.ErrorIs(t, err, io.EOF)
	require.Zero(t, server.BlinkStats().Assemblies)
	require.NoError(t, client.SetDeadline(time.Now()))
	require.NoError(t, client.SetReadDeadline(time.Now()))
	require.NoError(t, client.SetWriteDeadline(time.Now()))
	require.NotNil(t, client.LocalAddr())
	require.NoError(t, client.Close())
	require.NoError(t, client.Close())
	require.True(t, clientRaw.closed)
	_, err = client.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestBlinkReassemblyCapsExpirationAndConflict(t *testing.T) {
	c, _ := newBlinkTest(t, BlinkOptions{Server: true, Fragmentation: true, MaxReassemblyBytes: 2400})
	ap, source, _ := blinkAddress(blinkClientAddr)
	now := time.Now()
	h := blinkHeaderFields{session: [16]byte{1}, message: 1, total: 1200, size: 600, index: 0, count: 2}
	_, ready := c.accept(ap, source, h, make([]byte, 600), now)
	require.False(t, ready)
	h.message = 2
	c.accept(ap, source, h, make([]byte, 600), now)
	h.message = 3
	c.accept(ap, source, h, make([]byte, 600), now)
	require.Equal(t, 2400, c.assemblyBytes)
	require.Equal(t, uint64(1), c.stats.ResourceDrops)
	h.message = 1
	h.total = 1000
	h.size = 500
	c.accept(ap, source, h, make([]byte, 500), now)
	require.Equal(t, 1200, c.assemblyBytes)
	h.total = 1200
	h.size = 600
	c.accept(ap, source, h, make([]byte, 600), now)
	require.Equal(t, uint64(1), c.stats.ReplayDrops)
	c.maintain(now.Add(4*time.Second), 4096)
	require.Zero(t, c.assemblyBytes)
	require.Empty(t, c.assemblies)
	c.maintain(now.Add(3*time.Minute), 4096)
	require.Empty(t, c.peers)
	require.Empty(t, c.sources)
	_, ready = c.accept(ap, source, h, make([]byte, 600), now.Add(3*time.Minute))
	require.False(t, ready)
	require.NoError(t, c.Close())
	require.Empty(t, c.peers)
	require.Empty(t, c.assemblies)
	require.Zero(t, c.assemblyBytes)
}

func TestBlinkPerSourceAndSessionLimits(t *testing.T) {
	for _, tc := range []struct{ limit, want int }{{3, 3}, {1024, 8}} {
		c, _ := newBlinkTest(t, BlinkOptions{Server: true, MaxSessions: tc.limit})
		for i := range 10 {
			addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1000 + i}
			ap, source, _ := blinkAddress(addr)
			h := blinkHeaderFields{session: [16]byte{byte(i + 1)}, message: 1, total: 1, size: 1, count: 1}
			c.accept(ap, source, h, []byte{1}, time.Now())
		}
		require.Len(t, c.peers, tc.want)
		require.Len(t, c.sources, 1)
		require.Len(t, c.routes, tc.want)
	}
	for _, addr := range []net.Addr{nil, &net.IPAddr{}, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: -1}, &net.UDPAddr{IP: net.IPv4zero, Port: 4}, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 1), Port: 4}} {
		_, _, ok := blinkAddress(addr)
		require.False(t, ok)
	}
	_, a, ok := blinkAddress(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1})
	require.True(t, ok)
	_, b, _ := blinkAddress(&net.UDPAddr{IP: net.ParseIP("2001:db8::ffff"), Port: 2})
	require.Equal(t, a, b)
}

func TestBlinkInvalidFloodAllocatesNoPeerState(t *testing.T) {
	c, raw := newBlinkTest(t, BlinkOptions{Server: true, VerifyPacketsPerSecond: 64})
	for range 10000 {
		raw.input = append(raw.input, blinkTestPacket{make([]byte, 100), blinkClientAddr})
	}
	start := time.Now()
	_, _, err := c.ReadFrom(make([]byte, 1200))
	require.ErrorIs(t, err, io.EOF)
	s := c.BlinkStats()
	require.Zero(t, s.Sessions)
	require.Zero(t, s.Assemblies)
	require.Zero(t, s.ReassemblyBytes)
	require.Positive(t, s.AuthDrops)
	require.Positive(t, s.RateDrops)
	require.Empty(t, raw.output)
	require.LessOrEqual(t, s.AuthDrops, uint64(2049+time.Since(start).Seconds()*16))
}

func TestBlinkReplayWindowBoundaries(t *testing.T) {
	for _, step := range []uint64{1, 63, 64, 65, 255, 256, 1000} {
		p := &blinkPeer{}
		p.finish(0)
		require.True(t, p.replay(0))
		p.finish(step)
		require.True(t, p.replay(0))
		require.True(t, p.replay(step))
		require.False(t, p.replay(step+1))
		p.finish(math.MaxUint64)
		require.True(t, p.replay(0))
		require.True(t, p.replay(math.MaxUint64))
		require.False(t, p.replay(math.MaxUint64-1))
		p.finish(math.MaxUint64 - 1)
		require.True(t, p.replay(math.MaxUint64-1))
	}
}

func TestBlinkSessionsVaryAndNonceDoesNotRepeat(t *testing.T) {
	sessions := make(map[[16]byte]bool)
	for range 32 {
		c, raw := newBlinkTest(t, BlinkOptions{JunkPackets: blinkInt(0)})
		for range 2 {
			_, err := c.WriteTo(make([]byte, 1200), blinkServerAddr)
			require.NoError(t, err)
		}
		require.NotEqual(t, raw.output[0][:blinkNonce], raw.output[1][:blinkNonce])
		for _, s := range c.senders {
			require.False(t, sessions[s.session])
			sessions[s.session] = true
			require.GreaterOrEqual(t, s.paddingLimit, 16)
			require.LessOrEqual(t, s.paddingLimit, 32)
		}
	}
}

func TestBlinkShortWritesShortBuffersAndDisabledFragments(t *testing.T) {
	c, raw := newBlinkTest(t, BlinkOptions{JunkPackets: blinkInt(0)})
	raw.short = true
	_, err := c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, io.ErrShortWrite)
	raw.short = false
	raw.fail = true
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	raw.fail = false
	s := c.senders[netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 30002)]
	s.next = math.MaxUint64
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorContains(t, err, "counter exhausted")
	server, serverRaw := newBlinkTest(t, BlinkOptions{Server: true})
	h := blinkHeaderFields{session: [16]byte{1}, total: 6, size: 6, count: 1}
	serverRaw.input = []blinkTestPacket{{blinkTestFrame(c.tx, h, []byte("secret"), 0), blinkClientAddr}}
	_, _, err = server.ReadFrom(make([]byte, 2))
	require.ErrorIs(t, err, io.ErrShortBuffer)
	h.total = 6
	h.size = 3
	h.count = 2
	serverRaw.input = []blinkTestPacket{{blinkTestFrame(c.tx, h, []byte("sec"), 0), blinkClientAddr}}
	_, _, err = server.ReadFrom(make([]byte, 1200))
	require.ErrorIs(t, err, io.EOF)
	require.Zero(t, server.BlinkStats().Assemblies)
}

func FuzzBlinkDecode(f *testing.F) {
	f.Add([]byte{})
	h := blinkHeaderFields{session: [16]byte{1}, total: 1, size: 1, count: 1}
	seed := make([]byte, 33)
	h.encode(seed)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 2048 {
			in = in[:2048]
		}
		h, p, err := decodeBlinkHeader(in)
		if err == nil {
			if len(p) != int(h.size) || h.total > 1200 || h.count > 4 || h.index >= h.count {
				t.Fatal("invalid accepted header")
			}
		}
	})
}

func FuzzBlinkReceive(f *testing.F) {
	f.Add([]byte{})
	tx, _, _ := blinkCiphers(blinkTestPassword, false)
	f.Add(blinkTestFrame(tx, blinkHeaderFields{session: [16]byte{1}, total: 1, size: 1, count: 1}, []byte{1}, 0))
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 2048 {
			in = in[:2048]
		}
		c, raw := newBlinkTest(t, BlinkOptions{Server: true, Fragmentation: true, MaxSessions: 8, MaxReassemblyBytes: 2400})
		raw.input = []blinkTestPacket{{in, blinkClientAddr}, {in, blinkClientAddr}}
		_, _, err := c.ReadFrom(make([]byte, 1200))
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		s := c.BlinkStats()
		if s.Sessions > 8 || s.Assemblies > 2 || s.ReassemblyBytes > 2400 {
			t.Fatalf("unbounded state: %+v", s)
		}
	})
}
