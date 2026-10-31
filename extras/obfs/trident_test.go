// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var tridentTestPassword = []byte("trident-test-only-32-byte-secret!!")

func newTridentTest(t testing.TB, server bool) (*tridentPacketConn, *blinkTestConn) {
	t.Helper()
	raw := &blinkTestConn{}
	w, err := WrapPacketConnTrident(raw, TridentOptions{Password: tridentTestPassword, Server: server})
	require.NoError(t, err)
	return w.(*tridentPacketConn), raw
}

func tridentTestHeader() tridentHeaderFields {
	return tridentHeaderFields{session: [16]byte{1}, born: uint64(time.Now().Unix()), total: 1200, size: 400, count: 3}
}

// Independent structural walk, not the unpacker's reconstructed-byte path.
func tridentWalk(t testing.TB, isa *tridentISA, wire []byte) []byte {
	t.Helper()
	var opcodes []byte
	for pos := 0; pos < len(wire); {
		i := isa.reverse[wire[pos]]
		require.GreaterOrEqual(t, i, int16(0))
		ins := isa.code[i]
		opcodes = append(opcodes, ins.opcode)
		pos++
		pad := (-pos) & (int(ins.alignment) - 1)
		require.LessOrEqual(t, pos+pad+int(ins.operands), len(wire))
		for _, b := range wire[pos : pos+pad] {
			require.Zero(t, b)
		}
		require.Zero(t, (pos+pad)%int(ins.alignment))
		pos += pad + int(ins.operands)
	}
	return opcodes
}

func TestTridentCompilerAndPacking(t *testing.T) {
	isa, err := compileTridentISA(tridentTestPassword)
	require.NoError(t, err)
	again, err := compileTridentISA(tridentTestPassword)
	require.NoError(t, err)
	require.Equal(t, isa, again)
	var spec []byte
	for _, ins := range isa.code {
		spec = append(spec, ins.opcode, ins.operands, ins.alignment)
	}
	t.Logf("v1 ISA golden SHA256: %x", sha256.Sum256(spec))
	require.Equal(t, "91d61a59bac85019a01973d9b78e85d4574ba0f8e37b248e634ef661a2c6561b", fmt.Sprintf("%x", sha256.Sum256(spec)))
	sets := make(map[[64]tridentInstruction]bool)
	for password := range 32 {
		key := sha256.Sum256([]byte(fmt.Sprintf("trident-v1-public-test-%d", password)))
		isa, err := compileTridentISA(key[:])
		require.NoError(t, err)
		sets[isa.code] = true
		opcodes := map[byte]bool{}
		classes := map[byte]int{}
		for i, ins := range isa.code {
			require.False(t, opcodes[ins.opcode])
			opcodes[ins.opcode] = true
			classes[ins.operands]++
			require.Contains(t, []byte{1, 2, 4}, ins.alignment)
			require.LessOrEqual(t, ins.alignment, max(byte(1), ins.operands))
			require.Equal(t, int16(i), isa.reverse[ins.opcode])
		}
		require.Equal(t, map[byte]int{0: 8, 1: 8, 2: 8, 4: 16, 8: 24}, classes)
		for n := tridentOverhead + 1; n <= tridentRawMax; n++ {
			for _, fill := range []byte{0, 0xff, byte(n)} {
				raw := bytes.Repeat([]byte{fill}, n)
				wire, err := isa.pack(make([]byte, tridentWireMax), raw)
				require.NoError(t, err)
				require.LessOrEqual(t, len(wire), 1222)
				decoded, err := isa.unpack(make([]byte, tridentRawMax+12), wire)
				require.NoError(t, err)
				require.Equal(t, raw, decoded)
			}
		}
		// All legal opcodes appear with encrypted-looking uniformly random input.
		observed := map[byte]bool{}
		for range 16 {
			raw := make([]byte, tridentRawMax)
			_, err := rand.Read(raw)
			require.NoError(t, err)
			wire, err := isa.pack(make([]byte, tridentWireMax), raw)
			require.NoError(t, err)
			for _, op := range tridentWalk(t, &isa, wire) {
				observed[op] = true
			}
		}
		require.Len(t, observed, 64)
	}
	require.Len(t, sets, 32)
}

func TestTridentCanonicalProgramAndBounds(t *testing.T) {
	isa, err := compileTridentISA(tridentTestPassword)
	require.NoError(t, err)
	raw := bytes.Repeat([]byte{0x69}, 500)
	wire, err := isa.pack(make([]byte, tridentWireMax), raw)
	require.NoError(t, err)
	for n := range len(wire) {
		_, err := isa.unpack(make([]byte, tridentRawMax+12), wire[:n])
		require.Error(t, err, "truncated at %d", n)
	}
	_, err = isa.unpack(make([]byte, tridentRawMax+12), append(bytes.Clone(wire), isa.code[0].opcode))
	require.Error(t, err)
	_, err = isa.unpack(make([]byte, 1), wire)
	require.Error(t, err)
	_, err = isa.unpack(make([]byte, tridentRawMax+12), make([]byte, 1233))
	require.Error(t, err)
	for _, n := range []int{0, tridentOverhead, tridentRawMax + 1} {
		_, err := isa.pack(make([]byte, tridentWireMax), make([]byte, n))
		require.Error(t, err)
	}
	_, err = isa.pack(make([]byte, 1), raw)
	require.Error(t, err)
	// Invalid opcode, non-zero alignment, non-zero canonical tail.
	bad := bytes.Clone(wire)
	for i, idx := range isa.reverse {
		if idx < 0 {
			bad[0] = byte(i)
			break
		}
	}
	_, err = isa.unpack(make([]byte, tridentRawMax+12), bad)
	require.Error(t, err)
	paddingChecked := false
	for pos := 0; pos < len(wire); {
		ins := isa.code[isa.reverse[wire[pos]]]
		pos++
		pad := (-pos) & (int(ins.alignment) - 1)
		if pad > 0 {
			bad = bytes.Clone(wire)
			bad[pos] = 1
			_, err = isa.unpack(make([]byte, tridentRawMax+12), bad)
			require.Error(t, err)
			paddingChecked = true
			break
		}
		pos += pad + int(ins.operands)
	}
	require.True(t, paddingChecked)
	// Round-trip accepted syntax must be canonical, even after arbitrary edits.
	for i := range wire {
		bad = bytes.Clone(wire)
		bad[i] ^= 0x80
		decoded, err := isa.unpack(make([]byte, tridentRawMax+12), bad)
		if err == nil {
			repacked, err := isa.pack(make([]byte, tridentWireMax), decoded)
			require.NoError(t, err)
			require.Equal(t, bad, repacked)
		}
	}
}

func TestTridentPlanner(t *testing.T) {
	r := mathrand.New(mathrand.NewChaCha8(sha256.Sum256([]byte("trident-planner"))))
	counts := map[int]bool{}
	unequal := false
	for range 16 {
		for size := 1; size <= 1200; size++ {
			p := planTrident(size, r)
			require.GreaterOrEqual(t, p.count, 1)
			require.LessOrEqual(t, p.count, 4)
			offset := 0
			for _, part := range p.parts[:p.count] {
				require.Equal(t, offset, part.offset)
				require.Positive(t, part.size)
				require.LessOrEqual(t, part.size, tridentPartMax)
				offset += part.size
			}
			require.Equal(t, size, offset)
			if size == 1200 {
				require.GreaterOrEqual(t, p.count, 3)
				counts[p.count] = true
				unequal = unequal || p.parts[0].size != p.parts[1].size
			}
		}
	}
	require.Len(t, counts, 2)
	require.True(t, unequal)
}

func TestTridentGolden(t *testing.T) {
	// Independently generated with the slow Python bit-integer reference.
	isa, err := compileTridentISA(tridentTestPassword)
	require.NoError(t, err)
	raw := make([]byte, 500)
	for i := range raw {
		raw[i] = byte(i)
	}
	wire, err := isa.pack(make([]byte, tridentWireMax), raw)
	require.NoError(t, err)
	require.Len(t, wire, 583)
	require.Equal(t, "06533375d6426d191d7e7e0df7157236b909a47328bc7a935a46be6aeb63a5ba", fmt.Sprintf("%x", sha256.Sum256(wire)))
}

func TestTridentWireReorderAuthenticationAndIsolation(t *testing.T) {
	c, cr := newTridentTest(t, false)
	s, sr := newTridentTest(t, true)
	_, err := s.WriteTo([]byte{1}, blinkClientAddr)
	require.ErrorContains(t, err, "route")
	require.Empty(t, sr.output)
	input := bytes.Repeat([]byte{0xa3}, 1200)
	n, err := c.WriteTo(input, blinkServerAddr)
	require.NoError(t, err)
	require.Equal(t, len(input), n)
	require.Contains(t, []int{3, 4}, len(cr.output))
	sr.readErrors = []error{syscall.EMSGSIZE}
	sr.input = append(sr.input, blinkTestPacket{make([]byte, 4096), blinkClientAddr})
	for i := len(cr.output) - 1; i >= 0; i-- {
		tridentWalk(t, &c.isa, cr.output[i])
		sr.input = append(sr.input, blinkTestPacket{cr.output[i], blinkClientAddr}, blinkTestPacket{cr.output[i], blinkClientAddr})
	}
	out := make([]byte, 1200)
	n, addr, err := s.ReadFrom(out)
	require.NoError(t, err)
	require.Equal(t, input, out[:n])
	require.Equal(t, blinkClientAddr, addr)
	_, _, err = s.ReadFrom(out)
	require.ErrorIs(t, err, io.EOF)
	require.Positive(t, s.TridentStats().ReplayDrops)
	_, err = s.WriteTo(input, addr)
	require.NoError(t, err)
	for _, p := range sr.output {
		cr.input = append(cr.input, blinkTestPacket{p, blinkServerAddr})
	}
	n, _, err = c.ReadFrom(out)
	require.NoError(t, err)
	require.Equal(t, input, out[:n])
	for _, conn := range []*tridentPacketConn{c, s} {
		stats := conn.TridentStats()
		require.Equal(t, stats.SentInnerBytes+stats.SentPackets*tridentOverhead+stats.PackingBytes, stats.SentWireBytes)
		require.Equal(t, uint64(1), stats.FragmentedMessages)
	}
	// Reflect c2s bytes at the client: syntax passes, opposite AEAD rejects.
	for _, p := range cr.output {
		cr.input = append(cr.input, blinkTestPacket{p, blinkServerAddr})
	}
	_, _, err = c.ReadFrom(out)
	require.ErrorIs(t, err, io.EOF)
	require.Positive(t, c.TridentStats().AuthDrops)
	for _, mode := range []string{"wrong-password", "cipher-tamper", "presto", "blink"} {
		t.Run(mode, func(t *testing.T) {
			v, vr := newTridentTest(t, true)
			packet := cr.output[0]
			switch mode {
			case "wrong-password":
				w, err := WrapPacketConnTrident(vr, TridentOptions{Password: bytes.Repeat([]byte{2}, 32), Server: true})
				require.NoError(t, err)
				v = w.(*tridentPacketConn)
			case "cipher-tamper":
				raw, err := c.isa.unpack(make([]byte, tridentRawMax+12), packet)
				require.NoError(t, err)
				raw[len(raw)-1] ^= 1
				packet, err = c.isa.pack(make([]byte, tridentWireMax), raw)
				require.NoError(t, err)
			case "presto":
				other, or := newPrestoTest(t, false)
				_, err := other.WriteTo([]byte{1}, blinkServerAddr)
				require.NoError(t, err)
				packet = or.output[len(or.output)-1]
			case "blink":
				other, or := newBlinkTest(t, BlinkOptions{})
				_, err := other.WriteTo([]byte{1}, blinkServerAddr)
				require.NoError(t, err)
				packet = or.output[len(or.output)-1]
			}
			vr.input = []blinkTestPacket{{packet, blinkClientAddr}}
			_, _, err := v.ReadFrom(out)
			require.ErrorIs(t, err, io.EOF)
			require.Zero(t, v.TridentStats().Sessions)
			require.Empty(t, vr.output)
		})
	}
	// Same message, fresh nonce and random session each time, never fixed code.
	next, nr := newTridentTest(t, false)
	_, err = next.WriteTo(input, blinkServerAddr)
	require.NoError(t, err)
	require.NotEqual(t, cr.output, nr.output)
}

func TestTridentHeaderValidation(t *testing.T) {
	h := tridentTestHeader()
	plain := make([]byte, tridentHeader+int(h.size))
	h.encode(plain)
	got, payload, err := decodeTridentHeader(plain)
	require.NoError(t, err)
	require.Equal(t, h, got)
	require.Len(t, payload, int(h.size))
	for _, size := range []int{0, 1, 43, len(plain) - 1, len(plain) + 1} {
		_, _, err := decodeTridentHeader(make([]byte, size))
		require.Error(t, err)
	}
	for _, change := range []func([]byte){
		func(p []byte) { clear(p[:16]) }, func(p []byte) { clear(p[24:32]) },
		func(p []byte) { p[40] = 1 }, func(p []byte) { p[41] = 2 }, func(p []byte) { p[42] = 1 }, func(p []byte) { p[43] = 1 },
		func(p []byte) { p[38] = 4 }, func(p []byte) { p[39] = 0 }, func(p []byte) { p[39] = 5 },
		func(p []byte) { p[32] = 255 }, func(p []byte) { p[34] = 255 }, func(p []byte) { clear(p[36:38]) },
	} {
		bad := bytes.Clone(plain)
		change(bad)
		_, _, err := decodeTridentHeader(bad)
		require.Error(t, err)
	}
}

func TestTridentLimitsFreshnessAndExpiry(t *testing.T) {
	c, _ := newTridentTest(t, true)
	now := time.Now()
	ap, source, _ := blinkAddress(blinkClientAddr)
	h := tridentTestHeader()
	for i := range 40 {
		h.message = uint64(i)
		_, ready := c.accept(ap, source, h, make([]byte, h.size), now)
		require.False(t, ready)
	}
	require.Len(t, c.assemblies, 32)
	require.Equal(t, uint64(8), c.stats.EvictedAssemblies)
	other := netip.AddrPortFrom(ap.Addr(), ap.Port()+1)
	c.accept(other, source, h, make([]byte, h.size), now)
	require.Positive(t, c.stats.ReplayDrops)
	for i := range 8 {
		h.session = [16]byte{byte(i + 2)}
		c.accept(other, source, h, make([]byte, h.size), now)
	}
	require.Len(t, c.peers, 8)
	require.Positive(t, c.stats.ResourceDrops)
	c.maintain(now.Add(4*time.Second), 1024)
	require.Zero(t, c.assemblyBytes)
	c.maintain(now.Add(3*time.Minute), 1024)
	require.Empty(t, c.peers)
	require.Empty(t, c.sources)
	c.accept(ap, source, h, make([]byte, h.size), now.Add(3*time.Minute))
	require.Empty(t, c.peers)
	require.Positive(t, c.stats.FreshnessDrops)
	h.born = math.MaxUint64
	c.accept(ap, source, h, make([]byte, h.size), now)
	require.Empty(t, c.peers)
	c, _ = newTridentTest(t, true)
	for i := range 512 {
		h = tridentTestHeader()
		h.session = [16]byte{byte(i/32 + 1)}
		h.message = uint64(i % 32)
		ap, source, _ = blinkAddress(&net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(i/32+1)), Port: 1234})
		c.accept(ap, source, h, make([]byte, h.size), now)
	}
	require.Len(t, c.assemblies, 512)
	require.Equal(t, 600*1024, c.assemblyBytes)
	h.session = [16]byte{99}
	c.accept(ap, source, h, make([]byte, h.size), now)
	require.Len(t, c.assemblies, 512)
	require.Positive(t, c.stats.ResourceDrops)
	require.NoError(t, c.Close())
	require.Zero(t, c.TridentStats().ReassemblyBytes)
}

func TestTridentOverlapConflictAndLoss(t *testing.T) {
	for _, mode := range []string{"overlap", "gap", "total", "count", "single", "born", "expired"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := newTridentTest(t, true)
			now := time.Now()
			ap, source, _ := blinkAddress(blinkClientAddr)
			h := tridentTestHeader()
			c.accept(ap, source, h, make([]byte, h.size), now)
			h.index, h.offset = 1, 400
			switch mode {
			case "overlap":
				h.offset = 399
			case "gap":
				h.offset = 401
				h.size = 399
			case "total":
				h.total--
			case "count":
				h.count = 4
			case "single":
				h.count, h.index, h.offset, h.total, h.size = 1, 0, 0, 400, 400
			case "born":
				h.born++
			case "expired":
				now = now.Add(3 * time.Second)
			}
			_, ready := c.accept(ap, source, h, make([]byte, h.size), now)
			require.False(t, ready)
			if mode == "gap" {
				h.index, h.offset, h.size = 2, 800, 400
				_, ready := c.accept(ap, source, h, make([]byte, h.size), now)
				require.False(t, ready)
			}
			c.maintain(now.Add(4*time.Second), 1024)
			require.Empty(t, c.assemblies)
		})
	}
}

func TestTridentOptionsErrorsAndDeadline(t *testing.T) {
	_, err := WrapPacketConnTrident(nil, TridentOptions{Password: tridentTestPassword})
	require.Error(t, err)
	for _, n := range []int{0, 1, 31, 1025} {
		_, err := WrapPacketConnTrident(fakePlainConn{}, TridentOptions{Password: bytes.Repeat([]byte{1}, n)})
		require.Error(t, err)
	}
	w, err := WrapPacketConnTrident(fakeUDPLikeConn{}, TridentOptions{Password: tridentTestPassword})
	require.NoError(t, err)
	udp := w.(*tridentPacketConnUDP)
	require.Equal(t, 1200, udp.QUICPacketSizeLimit())
	_, err = udp.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, udp.SetReadBuffer(1024))
	require.NoError(t, udp.SetWriteBuffer(1024))
	require.NotNil(t, udp.LocalAddr())
	_, bypass := w.(interface {
		ReadMsgUDP([]byte, []byte) (int, int, int, *net.UDPAddr, error)
	})
	require.False(t, bypass)
	require.NoError(t, w.Close())
	require.NoError(t, w.Close())
	c, raw := newTridentTest(t, false)
	for _, data := range [][]byte{nil, make([]byte, 1201)} {
		_, err := c.WriteTo(data, blinkServerAddr)
		require.ErrorIs(t, err, ErrTridentPacketSize)
	}
	_, err = c.WriteTo([]byte{1}, nil)
	require.Error(t, err)
	raw.short = true
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, io.ErrShortWrite)
	raw.short, raw.fail = false, true
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	raw.fail = false
	_, err = c.WriteTo([]byte{1}, blinkClientAddr)
	require.ErrorContains(t, err, "one UDP endpoint")
	ap, _, _ := blinkAddress(blinkServerAddr)
	require.Equal(t, uint64(2), c.senders[ap].next)
	c.senders[ap].next = math.MaxUint64
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorContains(t, err, "counter exhausted")
	require.NoError(t, c.Close())
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, net.ErrClosed)
	// Actual UDP deadline and Close behavior, no timing shaper or background job.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	wrapped, err := WrapPacketConnTrident(pc, TridentOptions{Password: tridentTestPassword})
	require.NoError(t, err)
	defer wrapped.Close()
	require.NoError(t, wrapped.SetDeadline(time.Now().Add(-time.Second)))
	_, err = wrapped.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	_, _, err = wrapped.ReadFrom(make([]byte, 1200))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, wrapped.SetDeadline(time.Time{}))
	done := make(chan error, 1)
	go func() { _, _, err := wrapped.ReadFrom(make([]byte, 1200)); done <- err }()
	require.NoError(t, wrapped.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("Close did not release ReadFrom")
	}
}

func TestTridentInvalidTrafficAndShortBuffer(t *testing.T) {
	s, sr := newTridentTest(t, true)
	for range 10000 {
		sr.input = append(sr.input, blinkTestPacket{make([]byte, 100), blinkClientAddr})
	}
	_, _, err := s.ReadFrom(make([]byte, 1200))
	require.ErrorIs(t, err, io.EOF)
	require.Zero(t, s.TridentStats().Sessions)
	require.Zero(t, s.TridentStats().ReassemblyBytes)
	require.Positive(t, s.TridentStats().RateDrops)
	require.Empty(t, sr.output)
	c, _ := newTridentTest(t, false)
	h := tridentTestHeader()
	h.total, h.size, h.count = 200, 200, 1
	packet, err := c.seal(h, make([]byte, 200))
	require.NoError(t, err)
	sr.input = []blinkTestPacket{{packet, blinkClientAddr}}
	s.verify, s.verifyShards = blinkBucket{}, [256]blinkBucket{}
	_, _, err = s.ReadFrom(make([]byte, 1))
	require.ErrorIs(t, err, io.ErrShortBuffer)
}

func TestTridentRotationAndConcurrentLifecycle(t *testing.T) {
	c, _ := newTridentTest(t, false)
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
	fresh, err := c.sender(ap, now.Add(12*time.Minute))
	require.NoError(t, err)
	require.NotEqual(t, rotated.session, fresh.session)
	srv, _ := newTridentTest(t, true)
	ap, source, _ := blinkAddress(blinkClientAddr)
	h := tridentTestHeader()
	h.total, h.size, h.count = 1, 1, 1
	_, ready := srv.accept(ap, source, h, []byte{1}, now)
	require.True(t, ready)
	old, err := srv.sender(ap, now)
	require.NoError(t, err)
	h.session[0]++
	h.born = uint64(now.Add(time.Minute).Unix())
	_, ready = srv.accept(ap, source, h, []byte{1}, now.Add(time.Minute))
	require.True(t, ready)
	newSender, err := srv.sender(ap, now.Add(time.Minute))
	require.NoError(t, err)
	require.NotEqual(t, old.session, newSender.session)
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			c.TridentStats()
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

func FuzzTridentPacking(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0}, 100))
	f.Add(bytes.Repeat([]byte{0xff}, 600))
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) < tridentOverhead+1 || len(in) > tridentRawMax {
			return
		}
		key := sha256.Sum256(in)
		isa, err := compileTridentISA(key[:])
		require.NoError(t, err)
		wire, err := isa.pack(make([]byte, tridentWireMax), in)
		require.NoError(t, err)
		require.LessOrEqual(t, len(wire), 1222)
		out, err := isa.unpack(make([]byte, tridentRawMax+12), wire)
		require.NoError(t, err)
		require.Equal(t, in, out)
	})
}

func FuzzTridentDecode(f *testing.F) {
	isa, _ := compileTridentISA(tridentTestPassword)
	wire, _ := isa.pack(make([]byte, tridentWireMax), bytes.Repeat([]byte{0xa7}, 600))
	f.Add([]byte{})
	f.Add(wire)
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := isa.unpack(make([]byte, tridentRawMax+12), in)
		if err == nil {
			repacked, err := isa.pack(make([]byte, tridentWireMax), out)
			require.NoError(t, err)
			require.Equal(t, in, repacked)
		}
	})
}

func FuzzTridentReceive(f *testing.F) {
	c, _ := newTridentTest(f, false)
	wire, err := c.seal(tridentTestHeader(), make([]byte, 400))
	require.NoError(f, err)
	f.Add(bytes.Clone(wire))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 2048 {
			in = in[:2048]
		}
		s, raw := newTridentTest(t, true)
		raw.input = []blinkTestPacket{{in, blinkClientAddr}, {in, blinkClientAddr}}
		_, _, err := s.ReadFrom(make([]byte, 1200))
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		stats := s.TridentStats()
		if stats.Sessions > 8 || stats.Assemblies > 32 || stats.ReassemblyBytes > 32*1200 {
			t.Fatal(stats)
		}
	})
}

func FuzzTridentAuthenticatedState(f *testing.F) {
	f.Add([]byte{0, 2, 0, 0, 10, 20, 30, 40, 1, 2, 1, 0, 60, 80, 90, 100})
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 2048 {
			in = in[:2048]
		}
		c, _ := newTridentTest(t, false)
		s, raw := newTridentTest(t, true)
		for i := 0; i+8 <= len(in); i += 8 {
			b := in[i : i+8]
			h := tridentTestHeader()
			h.session = [16]byte{1 + b[0]%16}
			h.message = uint64(b[1])
			h.count = 1 + b[2]%4
			h.index = b[3] % h.count
			h.total = 1 + uint16(b[4])*4
			h.offset = uint16(b[5]) * 2
			h.size = 1 + uint16(b[6])*2
			if h.count == 1 {
				h.offset = 0
				h.total = h.size
			}
			if b[7]&8 != 0 {
				h.born = 1
			}
			wire, err := c.seal(h, make([]byte, h.size))
			require.NoError(t, err)
			raw.input = append(raw.input, blinkTestPacket{bytes.Clone(wire), blinkClientAddr})
		}
		for {
			_, _, err := s.ReadFrom(make([]byte, 1200))
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
		}
		stats := s.TridentStats()
		if stats.Sessions > 8 || stats.Assemblies > 256 || stats.ReassemblyBytes > 256*1200 {
			t.Fatal(stats)
		}
		s.maintain(time.Now().Add(3*time.Minute), 1024)
		require.Zero(t, s.TridentStats().ReassemblyBytes)
	})
}

func BenchmarkTridentPacking(b *testing.B) {
	isa, _ := compileTridentISA(tridentTestPassword)
	raw := make([]byte, tridentRawMax)
	_, _ = rand.Read(raw)
	buf, decoded := make([]byte, tridentWireMax), make([]byte, tridentRawMax+12)
	wire, _ := isa.pack(buf, raw)
	for _, mode := range []string{"pack", "unpack"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			for range b.N {
				var err error
				if mode == "pack" {
					_, err = isa.pack(buf, raw)
				} else {
					_, err = isa.unpack(decoded, wire)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestTridentLengthAAD(t *testing.T) {
	c, _ := newTridentTest(t, false)
	s, _ := newTridentTest(t, true)
	h := tridentTestHeader()
	wire, err := c.seal(h, make([]byte, h.size))
	require.NoError(t, err)
	raw, err := c.isa.unpack(make([]byte, tridentRawMax+12), wire)
	require.NoError(t, err)
	var aad [2]byte
	binary.BigEndian.PutUint16(aad[:], uint16(len(raw)))
	_, err = s.rx.Open(nil, raw[:24], raw[24:], aad[:])
	require.NoError(t, err)
	aad[1] ^= 1
	_, err = s.rx.Open(nil, raw[:24], raw[24:], aad[:])
	require.Error(t, err)
}
