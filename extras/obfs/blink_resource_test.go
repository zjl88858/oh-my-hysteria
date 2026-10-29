// SPDX-License-Identifier: MIT-0

package obfs

import (
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBlinkOversizeUDPErrorIsNotFatal(t *testing.T) {
	c, raw := newBlinkTest(t, BlinkOptions{Server: true})
	tx, _, err := blinkCiphers(blinkTestPassword, false)
	require.NoError(t, err)
	raw.readErrors = []error{&net.OpError{Op: "read", Net: "udp", Err: syscall.EMSGSIZE}}
	raw.input = []blinkTestPacket{{blinkTestFrame(tx, blinkHeaderFields{session: [16]byte{1}, total: 1, size: 1, count: 1}, []byte{1}, 0), blinkClientAddr}}
	n, _, err := c.ReadFrom(make([]byte, 1200))
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, uint64(1), c.BlinkStats().MalformedDrops)
}

func TestBlinkGlobalAndPerSessionAssemblyCountCaps(t *testing.T) {
	c, _ := newBlinkTest(t, BlinkOptions{Server: true, Fragmentation: true})
	now := time.Now()
	for i := range 17 {
		ap, source, _ := blinkAddress(&net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(i+1)), Port: 1000})
		for j := range 33 {
			h := blinkHeaderFields{session: [16]byte{byte(i + 1)}, message: uint64(j), total: 1200, size: 600, count: 2}
			c.accept(ap, source, h, make([]byte, 600), now)
		}
	}
	require.Len(t, c.assemblies, 512)
	require.Equal(t, uint64(16), c.stats.EvictedAssemblies)
	require.Equal(t, 512*1200, c.assemblyBytes)
	for _, p := range c.peers {
		require.LessOrEqual(t, p.active, 32)
	}
	c.maintain(now.Add(4*time.Second), 4096)
	require.Empty(t, c.assemblies)
	require.Zero(t, c.assemblyBytes)
	c.maintain(now.Add(3*time.Minute), 4096)
	require.Empty(t, c.peers)
	require.Empty(t, c.routes)
}

func TestBlinkExpiredTargetCannotBypassBoundedCleanup(t *testing.T) {
	c, _ := newBlinkTest(t, BlinkOptions{Server: true, Fragmentation: true})
	ap, source, _ := blinkAddress(blinkClientAddr)
	now := time.Now()
	h := blinkHeaderFields{session: [16]byte{1}, total: 1200, size: 600, count: 2}
	for i := range 32 {
		h.message = uint64(i)
		c.accept(ap, source, h, make([]byte, 600), now)
	}
	h.index = 1
	_, ready := c.accept(ap, source, h, make([]byte, 600), now.Add(4*time.Second))
	require.False(t, ready, "an expired target behind the eight-entry GC budget cannot complete")
	require.Equal(t, uint64(9), c.stats.ExpiredAssemblies)
}

func FuzzBlinkAuthenticatedState(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 512 {
			input = input[:512]
		}
		c, _ := newBlinkTest(t, BlinkOptions{Server: true, Fragmentation: true, MaxSessions: 8, MaxReassemblyBytes: 2400})
		now := time.Unix(1000000, 0)
		for i, b := range input {
			total := 1 + int(b)*4
			count := 1 + int(b%4)
			span := (total + count - 1) / count
			idx := int(b>>2) % count
			if (count-1)*span >= total {
				continue
			}
			h := blinkHeaderFields{session: [16]byte{1 + byte(i%4)}, message: uint64(b / 4), total: uint16(total), size: uint16(min(span, total-idx*span)), index: uint8(idx), count: uint8(count)}
			wire := make([]byte, blinkHeader+int(h.size))
			h.encode(wire)
			parsed, payload, err := decodeBlinkHeader(wire)
			if err != nil {
				t.Fatal(err)
			}
			ap, source, _ := blinkAddress(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1+b%8), Port: 1000 + int(b%16)})
			now = now.Add(time.Duration(b) * time.Millisecond)
			c.accept(ap, source, parsed, payload, now)
			bytes, count := 0, 0
			for _, a := range c.assemblies {
				bytes += len(a.data)
				count++
			}
			active := 0
			for _, p := range c.peers {
				active += p.active
				if p.active > 32 {
					t.Fatal("per-session cap")
				}
			}
			if bytes != c.assemblyBytes || bytes > 2400 || count != active || count > 512 || len(c.peers) > 8 || len(c.sources) > len(c.peers) {
				t.Fatalf("unbounded/inconsistent state: %+v", c.BlinkStats())
			}
		}
	})
}

type blinkSink struct{ fakePlainConn }

func (blinkSink) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (blinkSink) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, io.EOF }
func BenchmarkBlinkWrite(b *testing.B) {
	for _, tc := range []struct {
		name     string
		wire     int
		fragment bool
		pad      int
	}{
		{"envelope-only", 1400, false, 0}, {"default-padding", 1400, false, 32}, {"fragment-1232", 1232, true, 32}, {"fragment-512", 512, true, 32},
	} {
		b.Run(tc.name, func(b *testing.B) {
			conn, err := WrapPacketConnBlink(blinkSink{}, BlinkOptions{Password: blinkTestPassword, MaxPacketSize: tc.wire, Fragmentation: tc.fragment, PaddingMax: blinkInt(tc.pad), JunkPackets: blinkInt(0)})
			if err != nil {
				b.Fatal(err)
			}
			defer conn.Close()
			payload := make([]byte, 1200)
			b.ReportAllocs()
			b.SetBytes(1200)
			b.ResetTimer()
			for range b.N {
				if _, err := conn.WriteTo(payload, blinkServerAddr); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			s := conn.(interface{ BlinkStats() BlinkStats }).BlinkStats()
			b.ReportMetric(float64(s.SentWireBytes)/float64(s.SentInnerBytes), "wire/inner")
			b.ReportMetric(float64(s.SentPackets)/float64(b.N), "datagrams/op")
		})
	}
}
