// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	tasmanTestPassword = []byte("tasman-independent-vector-password-32+")
	tasmanTestNow      = time.Unix(1700000000, 0)
	tasmanTestAddr     = netip.MustParseAddrPort("192.0.2.1:1234")
)

func tasmanTestSymbol(id uint32, width, n int) []byte {
	b := make([]byte, width)
	l := encodeTasmanRecord(b[2:], tasmanRecord{message: id, total: uint16(n), data: bytes.Repeat([]byte{byte(id)}, n)})
	b[0], b[1] = byte(l>>8), byte(l)
	return b
}

func tasmanTestFrame(kind byte) tasmanFrame {
	f := tasmanFrame{born: 1700000000, kind: kind, generation: 1, width: 500}
	f.session[0] = 1
	switch kind {
	case tasmanSource:
		f.body = tasmanTestSymbol(1, 500, 488)
	case tasmanRepair:
		f.index = 128
		f.finalK = 2
		f.body = make([]byte, 500)
	case tasmanCover:
		f.generation = 0
		f.width = 0
		f.padding = make([]byte, 12)
	case tasmanShort:
		f.generation = 0
		f.width = 0
		f.body = make([]byte, 11)
		encodeTasmanRecord(f.body, tasmanRecord{message: 1, total: 1, data: []byte{7}})
	}
	return f
}

func TestTasmanIndependentVectors(t *testing.T) {
	data, err := os.ReadFile("../../tests/vectors/tasman-v1.json")
	require.NoError(t, err)
	var v struct {
		Profiles []string
		Frames   []struct {
			Dir, Kind byte
			Wire      string `json:"wire_hex"`
		}
		FEC []struct {
			K      int
			Hashes []string `json:"repair_sha256"`
		}
	}
	require.NoError(t, json.Unmarshal(data, &v))
	var src [][]byte
	for i := range 8 {
		b := make([]byte, 500)
		d := make([]byte, 488)
		for j := range d {
			d[j] = byte(i + j)
		}
		n := encodeTasmanRecord(b[2:], tasmanRecord{message: uint32(i + 1), total: 488, data: d})
		b[0], b[1] = byte(n>>8), byte(n)
		src = append(src, b)
	}
	for d := range 2 {
		p, e := compileTasmanProfile(tasmanTestPassword, byte(d))
		require.NoError(t, e)
		require.Equal(t, v.Profiles[d], hex.EncodeToString(p.bytes()))
	}
	for _, f := range v.Frames {
		wire, e := hex.DecodeString(f.Wire)
		require.NoError(t, e)
		c, e := newTasmanCipher(tasmanTestPassword, f.Dir)
		require.NoError(t, e)
		var scratch [1232]byte
		parsed, e := c.open(wire, &scratch)
		require.NoError(t, e)
		require.Equal(t, f.Kind, parsed.kind)
		again, e := c.seal(&parsed)
		require.NoError(t, e)
		require.Equal(t, wire, again)
	}
	for _, f := range v.FEC {
		for row := range 2 {
			r := tasmanEncode(src[:f.K], row)
			require.Equal(t, f.Hashes[row], fmt.Sprintf("%x", sha256.Sum256(r)))
		}
	}
}

func TestTasmanAllNominalErasures(t *testing.T) {
	for k := 2; k <= 8; k++ {
		for _, width := range []int{416, 500, 616, 700} {
			var sources [8][]byte
			for i := range k {
				sources[i] = tasmanTestSymbol(uint32(i+1), width, width-12)
			}
			var repairs [2][]byte
			for j := range 2 {
				repairs[j] = tasmanEncode(sources[:k], j)
			}
			for a := range k + 2 {
				for b := a; b < k+2; b++ {
					src, rep := sources, repairs
					for _, loss := range []int{a, b} {
						if loss < k {
							src[loss] = nil
						} else {
							rep[loss-k] = nil
						}
					}
					recovered, err := tasmanRecover(src, rep, k, width)
					require.NoError(t, err)
					for i := range k {
						if src[i] == nil {
							require.Equal(t, sources[i], recovered[i])
						}
					}
				}
			}
		}
	}
}

func TestTasmanCodecRejectsAndBounds(t *testing.T) {
	c, err := newTasmanCipher(tasmanTestPassword, 0)
	require.NoError(t, err)
	for kind := byte(0); kind < 4; kind++ {
		f := tasmanTestFrame(kind)
		w, e := c.seal(&f)
		require.NoError(t, e)
		var scratch [1232]byte
		for i := range len(w) {
			bad := bytes.Clone(w)
			bad[i] ^= 1
			_, e = c.open(bad, &scratch)
			require.Error(t, e)
		}
		wrong, e := newTasmanCipher(tasmanTestPassword, 1)
		require.NoError(t, e)
		_, e = wrong.open(w, &scratch)
		require.Error(t, e)
		wrongKey, e := newTasmanCipher(bytes.Repeat([]byte{0x42}, 32), 0)
		require.NoError(t, e)
		_, e = wrongKey.open(w, &scratch)
		require.ErrorIs(t, e, errTasmanAuth)
		servo, e := newServoCipher(tasmanTestPassword, 0)
		require.NoError(t, e)
		_, e = servo.open(w, &scratch)
		require.Error(t, e)
		for _, n := range []int{0, 1, 59, 1233} {
			_, e = c.open(make([]byte, n), &scratch)
			require.Error(t, e)
		}
	}
	f := tasmanTestFrame(tasmanSource)
	f.body[len(f.body)-1] = 1
	_, err = c.seal(&f)
	require.NoError(t, err) // full symbol, no zero tail
	f.body = tasmanTestSymbol(1, 500, 1)
	f.body[499] = 1
	_, err = c.seal(&f)
	require.Error(t, err)
	f = tasmanTestFrame(tasmanShort)
	f.body = make([]byte, 1181)
	encodeTasmanRecord(f.body, tasmanRecord{message: 1, total: 1171, data: make([]byte, 1171)})
	_, err = c.seal(&f)
	require.Error(t, err)
	for _, password := range [][]byte{nil, make([]byte, 31), make([]byte, 1025)} {
		_, err = compileTasmanProfile(password, 0)
		require.Error(t, err)
	}
}

func TestTasmanReceiveRecoveryReplayConflictsAndNoHOL(t *testing.T) {
	c, err := newTasmanCipher(tasmanTestPassword, 0)
	require.NoError(t, err)
	r, err := newTasmanReceiver(tasmanTestPassword, 0)
	require.NoError(t, err)
	var src [][]byte
	for i := range 4 {
		src = append(src, tasmanTestSymbol(uint32(i+1), 500, 488))
	}
	frames := []tasmanFrame{}
	for i := range 4 {
		f := tasmanTestFrame(tasmanSource)
		f.index = byte(i)
		f.counter = uint64(i)
		f.body = src[i]
		frames = append(frames, f)
	}
	for j := range 2 {
		f := tasmanTestFrame(tasmanRepair)
		f.index = byte(128 + j)
		f.counter = uint64(4 + j)
		f.finalK = 4
		f.body = tasmanEncode(src, j)
		frames = append(frames, f)
	}
	for _, i := range []int{5, 1, 4, 3} {
		w, e := c.seal(&frames[i])
		require.NoError(t, e)
		require.NoError(t, r.receive(w, tasmanTestAddr, tasmanTestNow))
	}
	require.Equal(t, 4, r.queue.Len())
	require.Equal(t, uint64(2), r.stats.RecoveredSymbols)
	for _, i := range []int{0, 2} {
		w, e := c.seal(&frames[i])
		require.NoError(t, e)
		require.ErrorIs(t, r.receive(w, tasmanTestAddr, tasmanTestNow), errTasmanConflict) // retired generation, never duplicate-delivered
	}
	require.Equal(t, 4, r.queue.Len())
	f := frames[0]
	f.counter = 99
	f.body = bytes.Clone(f.body)
	f.body[12] ^= 1
	w, e := c.seal(&f)
	require.NoError(t, e)
	require.ErrorIs(t, r.receive(w, tasmanTestAddr, tasmanTestNow), errTasmanConflict)
	f = frames[4]
	f.counter = 100
	f.finalK = 3
	w, e = c.seal(&f)
	require.NoError(t, e)
	require.Error(t, r.receive(w, tasmanTestAddr, tasmanTestNow))
	r.maintain(tasmanTestNow.Add(4 * time.Second))
	require.Zero(t, r.genOrder.Len())
	require.Zero(t, r.symbolBytes)
	f = tasmanTestFrame(tasmanCover)
	f.counter = 101
	f.session[0] = 9
	w, e = c.seal(&f)
	require.NoError(t, e)
	before := len(r.peers)
	require.NoError(t, r.receive(w, tasmanTestAddr, tasmanTestNow))
	require.Equal(t, before, len(r.peers))
}

func FuzzTasmanWire(f *testing.F) {
	c, _ := newTasmanCipher(tasmanTestPassword, 0)
	frame := tasmanTestFrame(tasmanSource)
	w, _ := c.seal(&frame)
	f.Add(w)
	f.Fuzz(func(t *testing.T, w []byte) {
		var scratch [1232]byte
		p, e := c.open(w, &scratch)
		if e == nil {
			again, e := c.seal(&p)
			require.NoError(t, e)
			require.Equal(t, w, again)
		}
	})
}

func FuzzTasmanPlain(f *testing.F) {
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, p []byte) { _, _ = decodeTasmanPlain(p) })
}

func BenchmarkTasmanCodec(b *testing.B) {
	c, _ := newTasmanCipher(tasmanTestPassword, 0)
	f := tasmanTestFrame(tasmanSource)
	w, _ := c.seal(&f)
	b.Run("seal500", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = c.seal(&f)
		}
	})
	b.Run("open560", func(b *testing.B) {
		var scratch [1232]byte
		b.ReportAllocs()
		for b.Loop() {
			_, _ = c.open(w, &scratch)
		}
	})
}
