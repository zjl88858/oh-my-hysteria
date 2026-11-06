// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var marinerTestPassword = []byte("mariner-independent-vector-password-32+")

func marinerTestFrame(n int) marinerFrame {
	f := marinerFrame{born: 1700000000, message: 1, total: uint16(n), data: bytes.Repeat([]byte{7}, n)}
	f.session[0] = 1
	return f
}

func marinerTestSeal(t testing.TB, r *marinerReceiver, f marinerFrame, delta int) []byte {
	t.Helper()
	l := r.profile.wireBase(62+len(f.data)) + delta
	var g marinerGraph
	require.NoError(t, r.profile.graph(l, &g))
	var raw, out [1232]byte
	b, e := r.cipher.seal(raw[:], &f, &r.profile, l)
	require.NoError(t, e)
	w, e := r.profile.encode(out[:], b, &g)
	require.NoError(t, e)
	return bytes.Clone(w)
}

func TestMarinerIndependentVectors(t *testing.T) {
	data, e := os.ReadFile("../../tests/vectors/mariner-v1.json")
	require.NoError(t, e)
	var v struct {
		Profiles []struct {
			Direction byte
			SHA256    string
			Graphs    []struct {
				Length int
				SHA256 string
			}
		}
		Frames []struct {
			Direction byte
			Length    int
			Raw       string `json:"raw_hex"`
			Wire      string `json:"wire_hex"`
		}
	}
	require.NoError(t, json.Unmarshal(data, &v))
	for _, want := range v.Profiles {
		p, e := compileMarinerProfile(marinerTestPassword, want.Direction)
		require.NoError(t, e)
		require.Equal(t, want.SHA256, fmt.Sprintf("%x", sha256.Sum256(p.bytes())))
		for _, gg := range want.Graphs {
			var g marinerGraph
			require.NoError(t, p.graph(gg.Length, &g))
			require.Equal(t, gg.SHA256, fmt.Sprintf("%x", sha256.Sum256(g.bytes())))
		}
	}
	for _, want := range v.Frames {
		p, e := compileMarinerProfile(marinerTestPassword, want.Direction)
		require.NoError(t, e)
		c, e := newMarinerCipher(marinerTestPassword, want.Direction)
		require.NoError(t, e)
		w, e := hex.DecodeString(want.Wire)
		require.NoError(t, e)
		raw, e := hex.DecodeString(want.Raw)
		require.NoError(t, e)
		var g marinerGraph
		require.NoError(t, p.graph(len(w), &g))
		var scratch, plain, out [1232]byte
		got, e := p.decode(scratch[:], w, &g)
		require.NoError(t, e)
		require.Equal(t, raw, got)
		f, e := c.open(plain[:], got, &p, len(w))
		require.NoError(t, e)
		again, e := c.seal(out[:], &f, &p, len(w))
		require.NoError(t, e)
		require.Equal(t, raw, again)
	}
}

func TestMarinerAllLengthsAndDensities(t *testing.T) {
	lengths, frames := 0, 0
	for dir := byte(0); dir < 2; dir++ {
		p, e := compileMarinerProfile(marinerTestPassword, dir)
		require.NoError(t, e)
		c, e := newMarinerCipher(marinerTestPassword, dir)
		require.NoError(t, e)
		for density := 16; density <= 20; density++ {
			p.density = density
			for l := p.wireBase(63); l <= 1232; l++ {
				var g marinerGraph
				require.NoError(t, p.graph(l, &g))
				require.NoError(t, g.validate())
				var raw, wire, decoded [1232]byte
				for i := range g.k {
					raw[i] = byte(i*37 + l)
				}
				before := raw
				w, e := p.encode(wire[:], raw[:g.k], &g)
				require.NoError(t, e)
				got, e := p.decode(decoded[:], w, &g)
				require.NoError(t, e)
				require.Equal(t, raw[:g.k], got)
				require.Equal(t, before, raw)
				lengths++
			}
			for n := 1; n <= p.capacity(); n++ {
				f := marinerTestFrame(n)
				for delta := 0; delta <= min(3, 1232-p.wireBase(62+n)); delta++ {
					l := p.wireBase(62+n) + delta
					var raw, plain [1232]byte
					b, e := c.seal(raw[:], &f, &p, l)
					require.NoError(t, e)
					got, e := c.open(plain[:], b, &p, l)
					require.NoError(t, e)
					require.Equal(t, f.data, got.data)
					frames++
				}
			}
		}
	}
	t.Logf("MARINER_ALL_LENGTHS=%d FRAME_LENGTH_DELTA_CASES=%d", lengths, frames)
}

func TestMarinerTamperingAndWrongDomains(t *testing.T) {
	r, e := newMarinerReceiver(marinerTestPassword, 0)
	require.NoError(t, e)
	f := marinerTestFrame(256)
	w := marinerTestSeal(t, r, f, 3)
	var g marinerGraph
	require.NoError(t, r.profile.graph(len(w), &g))
	var raw, plain [1232]byte
	for i := range w {
		bad := bytes.Clone(w)
		bad[i] ^= 1
		b, e := r.profile.decode(raw[:], bad, &g)
		if e == nil {
			_, e = r.cipher.open(plain[:], b, &r.profile, len(w))
		}
		require.Error(t, e)
	}
	for j := range g.r {
		bad := bytes.Clone(w)
		bad[g.positions[g.k+j]] ^= 1
		_, e = r.profile.decode(raw[:], bad, &g)
		require.ErrorIs(t, e, errMarinerRelation)
	}
	b, e := r.profile.decode(raw[:], w, &g)
	require.NoError(t, e)
	for _, dir := range []byte{0, 1} {
		password := marinerTestPassword
		if dir == 0 {
			password = bytes.Repeat([]byte{0x42}, 32)
		}
		c, e := newMarinerCipher(password, dir)
		require.NoError(t, e)
		_, e = c.open(plain[:], b, &r.profile, len(w))
		require.ErrorIs(t, e, errMarinerAuth)
	}
	s, e := newServoCipher(marinerTestPassword, 0)
	require.NoError(t, e)
	_, e = s.open(b, &plain)
	require.Error(t, e)
	for _, password := range [][]byte{nil, make([]byte, 31), make([]byte, 1025)} {
		_, e = compileMarinerProfile(password, 0)
		require.Error(t, e)
	}
	for i := range 16 {
		require.False(t, marinerAffine(&r.profile.tables[i]))
		var seen [256]bool
		for _, v := range r.profile.tables[i] {
			require.False(t, seen[v])
			seen[v] = true
		}
	}
	var identity [256]byte
	for i := range 256 {
		identity[i] = byte(i) ^ 0x5a
	}
	require.True(t, marinerAffine(&identity))
}

func TestMarinerCanonicalPlain(t *testing.T) {
	p, e := compileMarinerProfile(marinerTestPassword, 0)
	require.NoError(t, e)
	p.density = 16
	f := marinerTestFrame(1)
	c, e := newMarinerCipher(marinerTestPassword, 0)
	require.NoError(t, e)
	var raw, plain [1232]byte
	b, e := c.seal(raw[:], &f, &p, 82)
	require.NoError(t, e)
	opened, e := c.open(plain[:], b, &p, 82)
	require.NoError(t, e)
	require.Equal(t, f.data, opened.data)
	// p=3 but delta=4: reject even though the zero tail itself is canonical.
	bad := make([]byte, 26)
	binary.BigEndian.PutUint64(bad, 1700000000)
	bad[8] = 1
	binary.BigEndian.PutUint16(bad[10:], 11)
	binary.BigEndian.PutUint32(bad[12:], 1)
	binary.BigEndian.PutUint16(bad[16:], 1)
	binary.BigEndian.PutUint16(bad[20:], 1)
	bad[22] = 7
	_, e = decodeMarinerPlain(bad, &p, 83)
	require.Error(t, e)
	good := bytes.Clone(bad[:25])
	for _, index := range []int{8, 9, 10, 15, 16, 18, 20, 24} {
		mut := bytes.Clone(good)
		mut[index] ^= 1
		_, e = decodeMarinerPlain(mut, &p, 82)
		require.Error(t, e, "field %d", index)
	}
	f.born = math.MaxUint64
	require.Error(t, p.validateFragment(&f))
	f = marinerTestFrame(1)
	f.total = 1200
	require.Error(t, p.validateFragment(&f))
}

func TestMarinerReassemblyReplayBindingAndCache(t *testing.T) {
	r, e := newMarinerReceiver(marinerTestPassword, 0)
	require.NoError(t, e)
	now := time.Unix(1700000000, 0)
	addr := netip.MustParseAddrPort("192.0.2.1:1000")
	a := marinerTestFrame(600)
	a.total = 1200
	b := a
	b.offset = 600
	b.counter = 1
	b.data = bytes.Repeat([]byte{9}, 600)
	wb := marinerTestSeal(t, r, b, 0)
	require.NoError(t, r.receive(wb, addr, now))
	require.Equal(t, 1, r.state.assemblyOrder.Len())
	require.False(t, r.state.peers[a.session].routeReady)
	other := marinerTestFrame(1)
	other.message = 2
	other.counter = 2
	require.NoError(t, r.receive(marinerTestSeal(t, r, other, 0), addr, now))
	var out [1200]byte
	n, _, e := r.state.pop(out[:])
	require.NoError(t, e)
	require.Equal(t, 1, n)
	wa := marinerTestSeal(t, r, a, 0)
	require.NoError(t, r.receive(wa, addr, now))
	n, _, e = r.state.pop(out[:])
	require.NoError(t, e)
	require.Equal(t, 1200, n)
	require.Equal(t, append(bytes.Clone(a.data), b.data...), out[:n])
	require.ErrorIs(t, r.receive(wa, addr, now), errServoReplay)
	a.counter = 3
	require.NoError(t, r.receive(marinerTestSeal(t, r, a, 0), addr, now))
	require.Zero(t, r.state.queue.Len())
	a.counter = 4
	require.ErrorIs(t, r.receive(marinerTestSeal(t, r, a, 0), netip.MustParseAddrPort("192.0.2.1:1001"), now), errServoFresh)
	// Invalid candidates neither promote nor evict authenticated graph entries.
	before := r.cache.order.Len()
	for i := range 500 {
		l := r.profile.wireBase(63) + i%100
		_ = r.receive(make([]byte, l), addr, now)
	}
	require.Equal(t, before, r.cache.order.Len())
	require.Positive(t, r.compileDrops)
	r.state.retire(r.state.peers[a.session], now)
	require.ErrorIs(t, r.receive(wa, addr, now), errServoReplay)
}

func FuzzMarinerWire(f *testing.F) {
	r, _ := newMarinerReceiver(marinerTestPassword, 0)
	p := marinerTestFrame(1)
	l := r.profile.wireBase(63)
	var raw, wire [1232]byte
	var g marinerGraph
	_ = r.profile.graph(l, &g)
	b, _ := r.cipher.seal(raw[:], &p, &r.profile, l)
	w, _ := r.profile.encode(wire[:], b, &g)
	f.Add(w)
	f.Fuzz(func(t *testing.T, w []byte) {
		var graph marinerGraph
		if e := r.profile.graph(len(w), &graph); e != nil {
			return
		}
		var raw, plain [1232]byte
		b, e := r.profile.decode(raw[:], w, &graph)
		if e == nil {
			_, _ = r.cipher.open(plain[:], b, &r.profile, len(w))
		}
	})
}

func FuzzMarinerPlain(f *testing.F) {
	p, _ := compileMarinerProfile(marinerTestPassword, 0)
	f.Add([]byte{0}, uint16(83))
	f.Fuzz(func(t *testing.T, b []byte, l uint16) { _, _ = decodeMarinerPlain(b, &p, int(l)) })
}

func BenchmarkMariner(b *testing.B) {
	p, _ := compileMarinerProfile(marinerTestPassword, 0)
	var g marinerGraph
	_ = p.graph(900, &g)
	raw := make([]byte, g.k)
	wire := make([]byte, 900)
	_, _ = p.encode(wire, raw, &g)
	b.Run("graph-cold900", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = p.graph(900, &g)
		}
	})
	b.Run("encode-hot900", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(900)
		for b.Loop() {
			_, _ = p.encode(wire, raw, &g)
		}
	})
	b.Run("decode-hot900", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(900)
		for b.Loop() {
			_, _ = p.decode(raw, wire, &g)
		}
	})
}

func TestMarinerTopologyPoolsAndCacheBounds(t *testing.T) {
	p, e := compileMarinerProfile(marinerTestPassword, 0)
	require.NoError(t, e)
	for _, pool := range []int{16, 32, 64, 128, 0} {
		p.pool = pool
		for _, l := range []int{p.wireBase(63), 512, 1232} {
			var g marinerGraph
			require.NoError(t, p.graph(l, &g))
			require.NoError(t, g.validate())
			g.positions[1] = g.positions[0]
			require.Error(t, g.validate())
		}
	}
	other, e := compileMarinerProfile(bytes.Repeat([]byte{0x42}, 32), 0)
	require.NoError(t, e)
	require.NotEqual(t, p.bytes(), other.bytes())
	r, e := newMarinerReceiver(marinerTestPassword, 0)
	require.NoError(t, e)
	now := time.Unix(1700000000, 0)
	for i := range 80 {
		f := marinerTestFrame(1 + i)
		f.counter = uint64(i)
		f.message = uint32(i + 1)
		require.NoError(t, r.receive(marinerTestSeal(t, r, f, 0), tasmanTestAddr, now))
		_, _, e = r.state.pop(make([]byte, 1200))
		require.NoError(t, e)
	}
	require.Equal(t, 32, r.cache.order.Len())
	require.Equal(t, 32, len(r.cache.entries))
	require.Equal(t, uint64(80), r.cache.promotions)
	// An expired partial message cannot be revived by its second half.
	f := marinerTestFrame(600)
	f.total = 1200
	f.message = 999
	f.counter = 81
	require.NoError(t, r.receive(marinerTestSeal(t, r, f, 0), tasmanTestAddr, now))
	f.offset = 600
	f.counter = 82
	require.NoError(t, r.receive(marinerTestSeal(t, r, f, 0), tasmanTestAddr, now.Add(4*time.Second)))
	require.Zero(t, r.state.queue.Len())
	require.Positive(t, r.state.stats.ExpiredAssemblies)
}

func FuzzMarinerAuthenticatedTrace(f *testing.F) {
	p, _ := compileMarinerProfile(marinerTestPassword, 0)
	c, _ := newMarinerCipher(marinerTestPassword, 0)
	var g marinerGraph
	length := p.wireBase(662)
	_ = p.graph(length, &g)
	f.Add([]byte{0, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, input []byte) {
		r, e := newMarinerReceiver(marinerTestPassword, 0)
		require.NoError(t, e)
		for i, x := range input[:min(32, len(input))] {
			frame := marinerTestFrame(600)
			frame.total = 1200
			frame.offset = uint16(x%2) * 600
			frame.message = uint32(x/2 + 1)
			frame.counter = uint64(i)
			var raw, wire [1232]byte
			b, e := c.seal(raw[:], &frame, &p, length)
			require.NoError(t, e)
			w, e := p.encode(wire[:], b, &g)
			require.NoError(t, e)
			_ = r.receive(w, tasmanTestAddr, time.Unix(1700000000, 0))
		}
		require.LessOrEqual(t, r.state.assemblyBytes, servoMaxAssemblyBytes)
		require.LessOrEqual(t, r.cache.order.Len(), 32)
	})
}
