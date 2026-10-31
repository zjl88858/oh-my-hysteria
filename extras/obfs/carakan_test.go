// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
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

var carakanTestPassword = []byte("carakan-test-only-32-byte-secret!!")

func carakanTestTarget(h float64) *float64 { return &h }

func newCarakanTest(t testing.TB, server bool, entropy float64) (*carakanPacketConn, *blinkTestConn) {
	t.Helper()
	raw := &blinkTestConn{}
	w, err := WrapPacketConnCarakan(raw, CarakanOptions{Password: carakanTestPassword, Server: server, TargetEntropy: &entropy})
	require.NoError(t, err)
	return w.(*carakanPacketConn), raw
}

func carakanTestHeader() carakanHeaderFields {
	return carakanHeaderFields{session: [16]byte{1}, born: uint64(time.Now().Unix()), total: 1200, width: 400, size: 400, count: 3}
}

func TestCarakanTablesAndPacking(t *testing.T) {
	for _, target := range []float64{1, 1.01, 1.5, 2.5, 3.99, 4, 4.5, 6.99, 7.5} {
		t.Run(fmt.Sprint(target), func(t *testing.T) {
			table, err := compileCarakanTANS(carakanTestPassword, &target)
			require.NoError(t, err)
			again, err := compileCarakanTANS(carakanTestPassword, &target)
			require.NoError(t, err)
			require.Equal(t, table, again)
			sum := 0
			for _, f := range table.freq {
				sum += int(f)
			}
			require.Equal(t, carakanStates, sum)
			require.InDelta(t, target, table.entropy, .04)
			for i, row := range table.rows {
				require.GreaterOrEqual(t, int(row.bits), table.minBits)
				require.Less(t, int(row.base)+(1<<row.bits)-1, carakanStates)
				for _, y := range []uint16{row.base, row.base + (1 << row.bits) - 1} {
					x, b, n := table.inverse(row.symbol, y)
					require.Equal(t, uint16(i), x)
					require.Equal(t, row.bits, n)
					require.Equal(t, y-row.base, b)
				}
				if i != 0 {
					require.Less(t, table.distance[table.finish[i]], table.distance[i])
				}
			}
			r := mathrand.New(mathrand.NewChaCha8(sha256.Sum256([]byte(fmt.Sprint(target)))))
			for size := carakanOverhead + 1; size <= table.rawMax; size++ {
				for _, fill := range []int{0, 255, -1} {
					raw := make([]byte, size)
					for i := range raw {
						if fill < 0 {
							raw[i] = byte(r.Uint32())
						} else {
							raw[i] = byte(fill)
						}
					}
					wire, err := table.pack(make([]byte, carakanWireMax), raw)
					require.NoError(t, err)
					require.LessOrEqual(t, len(wire), carakanWireMax)
					out, err := table.unpack(make([]byte, carakanRawMax+2), wire)
					require.NoError(t, err)
					require.Equal(t, raw, out)
				}
			}
			for size := 1; size <= 1200; size++ {
				p := table.plan(size, r)
				offset := 0
				require.LessOrEqual(t, p.count, carakanMaxParts)
				for _, part := range p.parts[:p.count] {
					require.Equal(t, offset, part.offset)
					require.Positive(t, part.size)
					require.LessOrEqual(t, part.size, table.partMax)
					offset += part.size
				}
				require.Equal(t, size, offset)
				if size == 1200 {
					require.GreaterOrEqual(t, p.count, 2)
				}
			}
		})
	}
}

func TestCarakanTargetRange(t *testing.T) {
	for code := 100; code <= 750; code++ {
		key := sha256.Sum256([]byte(fmt.Sprintf("carakan-range-%d", code)))
		h := float64(code) / 100
		table, err := compileCarakanTANS(key[:], &h)
		require.NoError(t, err, "code=%d", code)
		require.InDelta(t, h, table.entropy, .04)
		require.GreaterOrEqual(t, table.partMax, 96)
		require.LessOrEqual(t, table.partMax, 632)
		require.LessOrEqual(t, table.maxTail, 32)
	}
}

func TestCarakanIndependentGolden(t *testing.T) {
	for _, v := range []struct {
		code, rawMax, wireLength int
		spectrum, wire           string
	}{
		{100, 149, 1206, "7f19fb34904440526b046570b256663348a86f112212cb734a2962784db33642", "56d28b0fa3d719b25fc4123ac9732e22e7cc5858434d3bebc37e88d16abb1806"},
		{450, 612, 1102, "5253cfa9b64fab2930804d61f8d913eb78a19d7731758d64a58bedbbe3736cf3", "d6e9db75c57a7f95566892f0c3063982997159c8e9948663f0dd2283bd643c2c"},
		{750, 684, 737, "2eea1638a72e89bc32f11debbc2cf8f96c38da6e3a9b95994ad21ff6322dbc64", "e7e32eef391179566bf2db96f370c87072c8a2f2a5bef4e58ca54ab49804c2b3"},
	} {
		table, err := compileCarakanTANS(carakanTestPassword, carakanTestTarget(float64(v.code)/100))
		require.NoError(t, err)
		var spec []byte
		for _, f := range table.freq {
			spec = binary.LittleEndian.AppendUint16(spec, f)
		}
		for _, row := range table.rows {
			spec = binary.LittleEndian.AppendUint16(spec, row.base)
			spec = append(spec, row.symbol, row.bits)
		}
		for _, y := range table.finish {
			spec = binary.LittleEndian.AppendUint16(spec, y)
		}
		require.Equal(t, v.spectrum, fmt.Sprintf("%x", sha256.Sum256(spec)))
		require.Equal(t, v.rawMax, table.rawMax)
		raw := make([]byte, table.rawMax)
		for i := range raw {
			raw[i] = byte(i)
		}
		wire, err := table.pack(make([]byte, 1232), raw)
		require.NoError(t, err)
		require.Len(t, wire, v.wireLength)
		require.Equal(t, v.wire, fmt.Sprintf("%x", sha256.Sum256(wire)))
	}
}

func TestCarakanCanonicalAndOptions(t *testing.T) {
	for _, h := range []float64{0, .5, 7.51, 8, 4.001, math.NaN(), math.Inf(1)} {
		_, err := compileCarakanTANS(carakanTestPassword, &h)
		require.Error(t, err)
	}
	for _, n := range []int{0, 1, 31, 1025} {
		_, err := compileCarakanTANS(make([]byte, n), nil)
		require.Error(t, err)
	}
	_, err := WrapPacketConnCarakan(nil, CarakanOptions{})
	require.Error(t, err)
	table, err := compileCarakanTANS(carakanTestPassword, nil)
	require.NoError(t, err)
	require.Equal(t, 4.0, table.target)
	raw := make([]byte, table.rawMax)
	_, err = rand.Read(raw)
	require.NoError(t, err)
	wire, err := table.pack(make([]byte, carakanWireMax), raw)
	require.NoError(t, err)
	for n := range len(wire) {
		out, err := table.unpack(make([]byte, carakanRawMax+2), wire[:n])
		if err == nil {
			// A truncation can be another canonical source, never the same one.
			// Integrity is the AEAD's job, not syntax's.
			require.NotEqual(t, raw, out)
			repacked, err := table.pack(make([]byte, carakanWireMax), out)
			require.NoError(t, err)
			require.Equal(t, wire[:n], repacked)
		}
	}
	for i := range wire {
		bad := bytes.Clone(wire)
		bad[i] ^= 128
		out, err := table.unpack(make([]byte, carakanRawMax+2), bad)
		if err == nil {
			repacked, err := table.pack(make([]byte, carakanWireMax), out)
			require.NoError(t, err)
			require.Equal(t, bad, repacked)
		}
	}
	for _, in := range [][]byte{nil, make([]byte, carakanWireMax+1)} {
		_, err := table.unpack(make([]byte, carakanRawMax+2), in)
		require.Error(t, err)
	}
	_, err = table.unpack(make([]byte, 1), wire)
	require.Error(t, err)
	for _, size := range []int{0, carakanOverhead, table.rawMax + 1} {
		_, err := table.pack(make([]byte, 1232), make([]byte, size))
		require.Error(t, err)
	}
	_, err = table.pack(make([]byte, 1), raw)
	require.Error(t, err)
}

func TestCarakanV3NonceAndInterleave(t *testing.T) {
	c, _ := newCarakanTest(t, false, 4.5)
	s, _ := newCarakanTest(t, true, 4.5)
	seen := make(map[[24]byte]bool)
	for _, message := range []uint64{0, 1, carakanMessageLimit - 1} {
		for _, index := range []uint8{0, 1, 31} {
			h := carakanTestHeader()
			h.message = message
			h.index = index
			h.count = 28
			h.total = 28
			h.size = 1
			h.width = 1
			wire, err := c.seal(h, []byte{0x93})
			require.NoError(t, err)
			raw, err := c.table.unpack(make([]byte, carakanRawMax+2), wire)
			require.NoError(t, err)
			var nonce [24]byte
			copy(nonce[:], raw[:24])
			require.False(t, seen[nonce])
			seen[nonce] = true
			require.Equal(t, h.session[:], nonce[:16])
			require.Equal(t, message<<5|uint64(index), binary.BigEndian.Uint64(nonce[16:]))
			var aad [2]byte
			binary.BigEndian.PutUint16(aad[:], uint16(len(raw)))
			plain, err := s.rx.Open(nil, nonce[:], raw[24:], aad[:])
			require.NoError(t, err)
			got, payload, err := s.table.decodeHeader(plain, nonce[:])
			require.NoError(t, err)
			require.Equal(t, h, got)
			require.Equal(t, []byte{0x93}, payload)
			// Cross-check allocation-free HMAC and rotation invariance independently
			// with the standard library; the offset does not consume wire bytes.
			var hist [256]uint16
			for _, b := range wire {
				hist[b]++
			}
			var spec []byte
			spec = binary.BigEndian.AppendUint16(spec, uint16(len(wire)))
			for _, n := range hist {
				spec = binary.BigEndian.AppendUint16(spec, n)
			}
			key, err := carakanDerive(carakanTestPassword, "interleave/450", 32)
			require.NoError(t, err)
			mac := hmac.New(sha256.New, key)
			mac.Write(spec)
			want := int(binary.BigEndian.Uint64(mac.Sum(nil)[:8]) % uint64(len(wire)))
			require.Equal(t, want, c.table.rotation(wire))
			for _, shift := range []int{0, 1, len(wire) / 2, len(wire) - 1} {
				other := append(bytes.Clone(wire[shift:]), wire[:shift]...)
				require.Equal(t, want, c.table.rotation(other))
			}
		}
	}
	for _, change := range []func(*carakanHeaderFields){
		func(h *carakanHeaderFields) { h.message = carakanMessageLimit }, func(h *carakanHeaderFields) { h.index = 32 }, func(h *carakanHeaderFields) { h.count = 0 }, func(h *carakanHeaderFields) { h.count = 33 }, func(h *carakanHeaderFields) { h.total = 2048 }, func(h *carakanHeaderFields) { h.size-- },
	} {
		h := carakanTestHeader()
		change(&h)
		_, err := c.seal(h, make([]byte, 400))
		require.Error(t, err)
	}
	_, err := c.WriteTo([]byte{1}, blinkServerAddr)
	require.NoError(t, err)
	ap, _, _ := blinkAddress(blinkServerAddr)
	c.senders[ap].next = carakanMessageLimit - 1
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.NoError(t, err)
	require.Equal(t, carakanMessageLimit, c.senders[ap].next)
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorContains(t, err, "counter exhausted")
}

func TestCarakanWireAuthenticationAndFragmentation(t *testing.T) {
	for _, entropy := range []float64{1, 2.5, 4.5, 7.5} {
		t.Run(fmt.Sprint(entropy), func(t *testing.T) {
			c, cr := newCarakanTest(t, false, entropy)
			s, sr := newCarakanTest(t, true, entropy)
			_, err := s.WriteTo([]byte{1}, blinkClientAddr)
			require.ErrorContains(t, err, "route")
			input := bytes.Repeat([]byte{0xa3}, 1200)
			_, err = c.WriteTo(input, blinkServerAddr)
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(cr.output), 2)
			sr.readErrors = []error{syscall.EMSGSIZE}
			sr.input = append(sr.input, blinkTestPacket{make([]byte, 4096), blinkClientAddr})
			for i := len(cr.output) - 1; i >= 0; i-- {
				require.LessOrEqual(t, len(cr.output[i]), 1232)
				for _, b := range cr.output[i] {
					require.NotZero(t, c.table.freq[b])
				}
				sr.input = append(sr.input, blinkTestPacket{cr.output[i], blinkClientAddr}, blinkTestPacket{cr.output[i], blinkClientAddr})
			}
			for cut := range len(cr.output[0]) {
				raw, err := c.table.unpack(make([]byte, carakanRawMax+2), cr.output[0][:cut])
				if err == nil {
					var aad [2]byte
					binary.BigEndian.PutUint16(aad[:], uint16(len(raw)))
					_, err = s.rx.Open(nil, raw[:24], raw[24:], aad[:])
					require.Error(t, err, "truncated authenticated packet at %d", cut)
				}
			}
			out := make([]byte, 1200)
			n, addr, err := s.ReadFrom(out)
			require.NoError(t, err)
			require.Equal(t, input, out[:n])
			require.Equal(t, blinkClientAddr, addr)
			_, _, err = s.ReadFrom(out)
			require.ErrorIs(t, err, io.EOF)
			require.Positive(t, s.CarakanStats().ReplayDrops)
			_, err = s.WriteTo(input, addr)
			require.NoError(t, err)
			for _, p := range sr.output {
				cr.input = append(cr.input, blinkTestPacket{p, blinkServerAddr})
			}
			n, _, err = c.ReadFrom(out)
			require.NoError(t, err)
			require.Equal(t, input, out[:n])
			for _, conn := range []*carakanPacketConn{c, s} {
				stats := conn.CarakanStats()
				require.Equal(t, int64(stats.SentInnerBytes+stats.SentRepairBytes+stats.SentPackets*carakanOverhead)+stats.ShapingBytes, int64(stats.SentWireBytes))
				require.Equal(t, uint64(1), stats.FragmentedMessages)
			}
			for _, p := range cr.output {
				cr.input = append(cr.input, blinkTestPacket{p, blinkServerAddr})
			}
			_, _, err = c.ReadFrom(out)
			require.ErrorIs(t, err, io.EOF)
			require.Positive(t, c.CarakanStats().AuthDrops)
			// Keep syntax canonical but corrupt the authenticated ciphertext.
			raw, err := c.table.unpack(make([]byte, carakanRawMax+2), cr.output[0])
			require.NoError(t, err)
			raw[len(raw)-1] ^= 1
			bad, err := c.table.pack(make([]byte, 1232), raw)
			require.NoError(t, err)
			for _, mode := range []string{"tamper", "wrong-password", "wrong-entropy", "trident"} {
				v, vr := newCarakanTest(t, true, entropy)
				packet := bad
				switch mode {
				case "wrong-password":
					w, err := WrapPacketConnCarakan(vr, CarakanOptions{Password: bytes.Repeat([]byte{1}, 32), Server: true, TargetEntropy: &entropy})
					require.NoError(t, err)
					v = w.(*carakanPacketConn)
					packet = cr.output[0]
				case "wrong-entropy":
					v, vr = newCarakanTest(t, true, 3.5)
					packet = cr.output[0]
				case "trident":
					other, or := newTridentTest(t, false)
					_, err := other.WriteTo([]byte{1}, blinkServerAddr)
					require.NoError(t, err)
					packet = or.output[0]
				}
				vr.input = []blinkTestPacket{{packet, blinkClientAddr}}
				_, _, err := v.ReadFrom(out)
				require.ErrorIs(t, err, io.EOF)
				require.Zero(t, v.CarakanStats().Sessions)
				require.Empty(t, vr.output)
			}
		})
	}
}

func TestCarakanResourcesAndLifecycle(t *testing.T) {
	c, _ := newCarakanTest(t, true, 4.5)
	now := time.Now()
	ap, source, _ := blinkAddress(blinkClientAddr)
	h := carakanTestHeader()
	for i := range 40 {
		h.message = uint64(i)
		_, ready := c.accept(ap, source, h, make([]byte, h.size), now)
		require.False(t, ready)
	}
	require.Len(t, c.assemblies, 32)
	require.Equal(t, uint64(8), c.stats.EvictedAssemblies)
	for i := range 8 {
		h.session[0] = byte(i + 2)
		c.accept(ap, source, h, make([]byte, h.size), now)
	}
	require.Len(t, c.peers, 8)
	require.Positive(t, c.stats.ResourceDrops)
	c.maintain(now.Add(4*time.Second), 1024)
	require.Zero(t, c.assemblyBytes)
	c.maintain(now.Add(3*time.Minute), 1024)
	require.Empty(t, c.peers)
	c.accept(ap, source, h, make([]byte, h.size), now.Add(3*time.Minute))
	require.Positive(t, c.stats.FreshnessDrops)
	c, _ = newCarakanTest(t, true, 4.5)
	for i := range 512 {
		h = carakanTestHeader()
		h.session[0] = byte(i/32 + 1)
		h.message = uint64(i % 32)
		ap, source, _ = blinkAddress(&net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(i/32+1)), Port: 1234})
		c.accept(ap, source, h, make([]byte, h.size), now)
	}
	require.Len(t, c.assemblies, 384)
	require.Equal(t, 600*1024, c.assemblyBytes)
	h.session[0] = 99
	c.accept(ap, source, h, make([]byte, h.size), now)
	require.Positive(t, c.stats.ResourceDrops)
	require.NoError(t, c.Close())
	require.Zero(t, c.CarakanStats().ReassemblyBytes)
	// The 32nd fragment uses bit 31, not a truncated 8/16-bit mask.
	c, _ = newCarakanTest(t, true, 4.5)
	ap, source, _ = blinkAddress(blinkClientAddr)
	data := make([]byte, 28)
	for i := range data {
		data[i] = byte(i)
	}
	var parity [1]byte
	carakanRepair(parity[:], data, 1, 28, 3)
	h = carakanTestHeader()
	h.count, h.index, h.total, h.size, h.width = 28, 31, 28, 1, 1
	_, ready := c.accept(ap, source, h, parity[:], now)
	require.False(t, ready)
	for i := range 27 {
		h = carakanTestHeader()
		h.count, h.index, h.total, h.size, h.width = 28, uint8(i), 28, 1, 1
		out, ready := c.accept(ap, source, h, []byte{byte(i)}, now)
		require.Equal(t, i == 26, ready)
		if ready {
			require.Equal(t, data, out)
		}
	}
	require.Empty(t, c.assemblies)
	c, raw := newCarakanTest(t, false, 4.5)
	for _, in := range [][]byte{nil, make([]byte, 1201)} {
		_, err := c.WriteTo(in, blinkServerAddr)
		require.ErrorIs(t, err, ErrCarakanPacketSize)
	}
	_, err := c.WriteTo([]byte{1}, nil)
	require.Error(t, err)
	raw.short = true
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, io.ErrShortWrite)
	raw.short, raw.fail = false, true
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	_, err = c.WriteTo([]byte{1}, blinkClientAddr)
	require.ErrorContains(t, err, "one UDP endpoint")
	serverAP, _, _ := blinkAddress(blinkServerAddr)
	require.Equal(t, uint64(2), c.senders[serverAP].next)
	c.senders[serverAP].next = math.MaxUint64
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorContains(t, err, "counter exhausted")
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			c.CarakanStats()
		}
	})
	wg.Go(func() { _ = c.Close() })
	wg.Wait()
	_, err = c.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, net.ErrClosed)
	w, err := WrapPacketConnCarakan(fakeUDPLikeConn{}, CarakanOptions{Password: carakanTestPassword})
	require.NoError(t, err)
	udp := w.(*carakanPacketConnUDP)
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
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	w, err = WrapPacketConnCarakan(pc, CarakanOptions{Password: carakanTestPassword})
	require.NoError(t, err)
	defer w.Close()
	require.NoError(t, w.SetDeadline(time.Now().Add(-time.Second)))
	_, err = w.WriteTo([]byte{1}, blinkServerAddr)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	_, _, err = w.ReadFrom(make([]byte, 1200))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, w.SetDeadline(time.Time{}))
	done := make(chan error, 1)
	go func() { _, _, err := w.ReadFrom(make([]byte, 1200)); done <- err }()
	require.NoError(t, w.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("Close blocked")
	}
}

func TestCarakanMalformedHeadersAndAssembly(t *testing.T) {
	c, _ := newCarakanTest(t, true, 4.5)
	h := carakanTestHeader()
	plain := make([]byte, carakanHeader+int(h.size))
	h.encode(plain)
	var nonce [24]byte
	copy(nonce[:16], h.session[:])
	binary.BigEndian.PutUint64(nonce[16:], h.message<<5|uint64(h.index))
	got, payload, err := c.table.decodeHeader(plain, nonce[:])
	require.NoError(t, err)
	require.Equal(t, h, got)
	require.Len(t, payload, int(h.size))
	for _, change := range []func([]byte){
		func(p []byte) { clear(p[:8]) },
		func(p []byte) { binary.BigEndian.PutUint16(p[8:10], 2<<11) },
		func(p []byte) { binary.BigEndian.PutUint16(p[8:10], 2<<11|2047) },
		func(p []byte) { binary.BigEndian.PutUint16(p[8:10], 1200) },
		func(p []byte) { binary.BigEndian.PutUint16(p[10:12], 65535) },
	} {
		bad := bytes.Clone(plain)
		change(bad)
		_, _, err := c.table.decodeHeader(bad, nonce[:])
		require.Error(t, err)
	}
	for _, size := range []int{0, 1, 11, 12} {
		_, _, err := c.table.decodeHeader(make([]byte, size), nonce[:])
		require.Error(t, err)
	}
	for _, size := range []int{0, 23, 25} {
		_, _, err := c.table.decodeHeader(plain, make([]byte, size))
		require.Error(t, err)
	}
	for _, change := range []func([]byte){func(p []byte) { clear(p[:16]) }, func(p []byte) { p[23] = 4 }} {
		bad := bytes.Clone(nonce[:])
		change(bad)
		_, _, err := c.table.decodeHeader(plain, bad)
		require.Error(t, err)
	}
	for _, mode := range []string{"width", "total", "count", "single", "born", "expired", "size"} {
		v, _ := newCarakanTest(t, true, 4.5)
		now := time.Now()
		ap, source, _ := blinkAddress(blinkClientAddr)
		h := carakanTestHeader()
		v.accept(ap, source, h, make([]byte, h.size), now)
		h.index = 1
		switch mode {
		case "width":
			h.width = 399
		case "total":
			h.total--
		case "count":
			h.count = 4
		case "single":
			h.count, h.index, h.width, h.total, h.size = 1, 0, 400, 400, 400
		case "born":
			h.born++
		case "expired":
			now = now.Add(3 * time.Second)
		case "size":
			h.size = 399
		}
		_, ready := v.accept(ap, source, h, make([]byte, h.size), now)
		require.False(t, ready)
		v.maintain(now.Add(4*time.Second), 1024)
		require.Empty(t, v.assemblies)
	}
	// Invalid traffic does not create sessions or responses, and is budgeted.
	s, sr := newCarakanTest(t, true, 4.5)
	for range 6000 {
		sr.input = append(sr.input, blinkTestPacket{make([]byte, 100), blinkClientAddr})
	}
	_, _, err = s.ReadFrom(make([]byte, 1200))
	require.ErrorIs(t, err, io.EOF)
	require.Zero(t, s.CarakanStats().Sessions)
	require.Positive(t, s.CarakanStats().RateDrops)
	require.Empty(t, sr.output)
	tx, _ := newCarakanTest(t, false, 4.5)
	h = carakanTestHeader()
	h.total, h.size, h.count, h.width = 200, 200, 1, 200
	packet, err := tx.seal(h, make([]byte, 200))
	require.NoError(t, err)
	s.verify, s.verifyShards = blinkBucket{}, [256]blinkBucket{}
	sr.input = []blinkTestPacket{{packet, blinkClientAddr}}
	_, _, err = s.ReadFrom(make([]byte, 1))
	require.ErrorIs(t, err, io.ErrShortBuffer)
	raw, err := tx.table.unpack(make([]byte, carakanRawMax+2), packet)
	require.NoError(t, err)
	var aad [2]byte
	binary.BigEndian.PutUint16(aad[:], uint16(len(raw)))
	_, err = s.rx.Open(nil, raw[:24], raw[24:], aad[:])
	require.NoError(t, err)
	aad[1] ^= 1
	_, err = s.rx.Open(nil, raw[:24], raw[24:], aad[:])
	require.Error(t, err)
}

func FuzzCarakanPacking(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0}, 100), uint8(0))
	f.Add(bytes.Repeat([]byte{255}, 600), uint8(3))
	tables := make([]*carakanTANS, 0, 4)
	for _, h := range []float64{1, 2.5, 4.5, 7.5} {
		t, err := compileCarakanTANS(carakanTestPassword, &h)
		require.NoError(f, err)
		tables = append(tables, t)
	}
	f.Fuzz(func(t *testing.T, in []byte, choice uint8) {
		table := tables[int(choice)%len(tables)]
		if len(in) < carakanOverhead+1 || len(in) > table.rawMax {
			return
		}
		wire, err := table.pack(make([]byte, 1232), in)
		require.NoError(t, err)
		out, err := table.unpack(make([]byte, carakanRawMax+2), wire)
		require.NoError(t, err)
		require.Equal(t, in, out)
	})
}

func FuzzCarakanDecode(f *testing.F) {
	table, err := compileCarakanTANS(carakanTestPassword, carakanTestTarget(4.5))
	require.NoError(f, err)
	wire, err := table.pack(make([]byte, 1232), bytes.Repeat([]byte{0xa7}, table.rawMax))
	require.NoError(f, err)
	f.Add([]byte{})
	f.Add(wire)
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := table.unpack(make([]byte, carakanRawMax+2), in)
		if err == nil {
			repacked, err := table.pack(make([]byte, 1232), out)
			require.NoError(t, err)
			require.Equal(t, in, repacked)
		}
	})
}

func FuzzCarakanReceive(f *testing.F) {
	c, _ := newCarakanTest(f, false, 4.5)
	wire, err := c.seal(carakanTestHeader(), make([]byte, 400))
	require.NoError(f, err)
	f.Add(bytes.Clone(wire))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 2048 {
			in = in[:2048]
		}
		// Immutable table/AEAD are safe to reuse; each receiver has fresh state.
		raw := &blinkTestConn{}
		s := carakanFuzzReceiver(c, raw)
		raw.input = []blinkTestPacket{{in, blinkClientAddr}, {in, blinkClientAddr}}
		_, _, err := s.ReadFrom(make([]byte, 1200))
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		stats := s.CarakanStats()
		if stats.Sessions > 8 || stats.Assemblies > 32 || stats.ReassemblyBytes > 32*(1200+632) {
			t.Fatal(stats)
		}
	})
}

// Shared tables avoid making each fuzz iteration a key compiler benchmark.
func carakanFuzzReceiver(tx *carakanPacketConn, raw *blinkTestConn) *carakanPacketConn {
	return &carakanPacketConn{
		inner: raw, server: true, table: tx.table, rx: tx.tx,
		readBuf: make([]byte, 1233), decodeBuf: make([]byte, carakanRawMax+2), plainBuf: make([]byte, 0, carakanRawMax),
		peers: make(map[[16]byte]*carakanPeer), sources: make(map[netip.Prefix]int), routes: make(map[netip.AddrPort]*carakanPeer), senders: make(map[netip.AddrPort]*carakanSender),
		peerOrder: list.New(), assemblyOrder: list.New(), assemblies: make(map[carakanAssemblyKey]*carakanAssembly), hashSeed: maphash.MakeSeed(),
	}
}

func FuzzCarakanAuthenticatedState(f *testing.F) {
	c, _ := newCarakanTest(f, false, 4.5)
	f.Add([]byte{0, 2, 0, 0, 10, 20, 30, 40, 1, 2, 1, 0, 60, 80, 90, 100})
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 2048 {
			in = in[:2048]
		}
		raw := &blinkTestConn{}
		s := carakanFuzzReceiver(c, raw)
		for i := 0; i+8 <= len(in); i += 8 {
			b := in[i : i+8]
			h := carakanTestHeader()
			h.session[0] = 1 + b[0]%16
			h.message = uint64(b[1])
			h.count = 1 + b[2]%28
			h.index = b[3] % uint8(int(h.count)+carakanRepairCount(int(h.count)))
			h.total = 1 + uint16(b[4])*4
			h.width = 1 + uint16(b[5])*2
			h.size = 1 + uint16(b[6])*2
			if h.count == 1 {
				h.width = h.size
				h.total = h.size
			}
			if b[7]&4 != 0 {
				h.count = uint8((int(h.total) + c.table.partMax - 1) / c.table.partMax)
				h.width = uint16((int(h.total) + int(h.count) - 1) / int(h.count))
				h.index %= uint8(int(h.count) + carakanRepairCount(int(h.count)))
				h.size = h.width
				if h.index == h.count-1 {
					h.size = h.total - uint16(h.count-1)*h.width
				}
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
		stats := s.CarakanStats()
		if stats.Sessions > 8 || stats.Assemblies > 256 || stats.ReassemblyBytes > carakanReassemblyBudget {
			t.Fatal(stats)
		}
		s.maintain(time.Now().Add(3*time.Minute), 1024)
		require.Zero(t, s.CarakanStats().ReassemblyBytes)
	})
}

func BenchmarkCarakanShaping(b *testing.B) {
	for _, h := range []float64{1, 4.5, 7.5} {
		table, err := compileCarakanTANS(carakanTestPassword, &h)
		if err != nil {
			b.Fatal(err)
		}
		raw := make([]byte, table.rawMax)
		_, _ = rand.Read(raw)
		buf, decoded := make([]byte, 1232), make([]byte, carakanRawMax+2)
		wire, err := table.pack(buf, raw)
		if err != nil {
			b.Fatal(err)
		}
		for _, mode := range []string{"pack", "unpack"} {
			b.Run(fmt.Sprintf("%.2f/%s", h, mode), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				for range b.N {
					var err error
					if mode == "pack" {
						_, err = table.pack(buf, raw)
					} else {
						_, err = table.unpack(decoded, wire)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
