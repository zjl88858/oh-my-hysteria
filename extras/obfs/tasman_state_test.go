// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTasmanReceiveAllErasuresAndRepairFirst(t *testing.T) {
	for k := 2; k <= 8; k++ {
		for a := range k + 2 {
			for b := a; b < k+2; b++ {
				r, err := newTasmanReceiver(tasmanTestPassword, 0)
				require.NoError(t, err)
				var sources [][]byte
				for i := range k {
					sources = append(sources, tasmanTestSymbol(uint32(i+1), 500, 488))
				}
				var frames []tasmanFrame
				for j := range 2 {
					f := tasmanTestFrame(tasmanRepair)
					f.index = byte(128 + j)
					f.finalK = byte(k)
					f.body = tasmanEncode(sources, j)
					f.counter = uint64(k + j)
					frames = append(frames, f)
				}
				for i := k - 1; i >= 0; i-- {
					f := tasmanTestFrame(tasmanSource)
					f.index = byte(i)
					f.body = sources[i]
					f.counter = uint64(i)
					frames = append(frames, f)
				}
				for _, f := range frames {
					index := int(f.index)
					if f.kind == tasmanRepair {
						index = int(f.index) - 128 + k
					}
					if index == a || index == b {
						continue
					}
					wire, err := r.cipher.seal(&f)
					require.NoError(t, err)
					err = r.receive(wire, tasmanTestAddr, tasmanTestNow)
					if err != nil {
						require.ErrorIs(t, err, errTasmanConflict)
					}
				}
				require.Equal(t, k, r.queue.Len(), "k=%d erased=%d,%d", k, a, b)
				for range k {
					var p [1200]byte
					n, _, err := r.pop(p[:])
					require.NoError(t, err)
					require.Equal(t, 488, n)
				}
			}
		}
	}
}

func TestTasmanCrossGenerationNoHOLOverlapTTLAndShortDedup(t *testing.T) {
	r, err := newTasmanReceiver(tasmanTestPassword, 0)
	require.NoError(t, err)
	counter := uint64(0)
	send := func(generation uint32, rec tasmanRecord) error {
		f := tasmanTestFrame(tasmanSource)
		f.counter = counter
		counter++
		f.generation = generation
		f.body = make([]byte, 500)
		n := encodeTasmanRecord(f.body[2:], rec)
		binary.BigEndian.PutUint16(f.body, uint16(n))
		w, err := r.cipher.seal(&f)
		require.NoError(t, err)
		return r.receive(w, tasmanTestAddr, tasmanTestNow)
	}
	rec := tasmanRecord{message: 1, total: 1200, data: bytes.Repeat([]byte{3}, 400)}
	require.NoError(t, send(1, rec))
	require.NoError(t, send(2, rec))
	bad := rec
	bad.offset = 1
	require.ErrorIs(t, send(3, bad), errTasmanConflict)
	other := tasmanRecord{message: 2, total: 1, data: []byte{9}}
	require.NoError(t, send(4, other))
	var out [1200]byte
	n, _, err := r.pop(out[:])
	require.NoError(t, err)
	require.Equal(t, []byte{9}, out[:n])
	rec.offset = 800
	require.NoError(t, send(5, rec))
	rec.offset = 400
	require.NoError(t, send(6, rec))
	n, _, err = r.pop(out[:])
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{3}, 1200), out[:n])
	f := tasmanTestFrame(tasmanShort)
	f.counter = counter
	counter++
	f.body = make([]byte, 11)
	encodeTasmanRecord(f.body, other)
	wire, err := r.cipher.seal(&f)
	require.NoError(t, err)
	require.NoError(t, r.receive(wire, tasmanTestAddr, tasmanTestNow))
	require.Zero(t, r.queue.Len())
	rec.message = 3
	rec.offset = 0
	require.NoError(t, send(7, rec))
	r.maintain(tasmanTestNow.Add(4 * time.Second))
	require.Zero(t, r.assemblyOrder.Len())
	require.Zero(t, r.genOrder.Len())
	require.Positive(t, r.stats.ExpiredMessages)
	for _, p := range r.peers {
		r.retire(p, tasmanTestNow.Add(5*time.Second))
	}
	require.Error(t, r.receive(wire, tasmanTestAddr, tasmanTestNow.Add(6*time.Second)))
}

func TestTasmanResourceBoundsSourceBindingAndCanonicalTail(t *testing.T) {
	r, err := newTasmanReceiver(tasmanTestPassword, 0)
	require.NoError(t, err)
	for i := range 130 {
		f := tasmanTestFrame(tasmanSource)
		f.counter = uint64(i)
		f.generation = uint32(i + 1)
		f.body = make([]byte, 500)
		rec := tasmanRecord{message: uint32(i + 1), total: 1200, data: make([]byte, 1)}
		n := encodeTasmanRecord(f.body[2:], rec)
		binary.BigEndian.PutUint16(f.body, uint16(n))
		wire, err := r.cipher.seal(&f)
		require.NoError(t, err)
		require.NoError(t, r.receive(wire, tasmanTestAddr, tasmanTestNow))
	}
	require.Equal(t, 128, r.assemblyOrder.Len())
	require.Positive(t, r.stats.ResourceDrops)
	require.LessOrEqual(t, r.assemblyBytes, 2457600)
	require.LessOrEqual(t, r.symbolBytes, tasmanSymbolBytes)
	f := tasmanTestFrame(tasmanShort)
	f.counter = 200
	wire, err := r.cipher.seal(&f)
	require.NoError(t, err)
	require.Error(t, r.receive(wire, netip.MustParseAddrPort("192.0.2.1:4321"), tasmanTestNow))
	for range 5 {
		r.maintain(tasmanTestNow.Add(4 * time.Second))
	} // bounded 32-object maintenance turns
	require.Zero(t, r.symbolBytes)
	require.Zero(t, r.assemblyBytes)
	f.counter = 201
	encodeTasmanRecord(f.body, tasmanRecord{message: 999, total: 1, data: []byte{1}})
	wire, err = r.cipher.seal(&f)
	require.NoError(t, err)
	require.NoError(t, r.receive(wire, tasmanTestAddr, tasmanTestNow))
	_, _, err = r.pop(nil)
	require.ErrorIs(t, err, io.ErrShortBuffer)
	require.Zero(t, r.queue.Len())
}

func FuzzTasmanAuthenticatedTrace(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := newTasmanReceiver(tasmanTestPassword, 0)
		require.NoError(t, err)
		for i, b := range data[:min(64, len(data))] {
			frame := tasmanTestFrame(tasmanSource)
			frame.counter = uint64(i)
			frame.generation = uint32(b%8 + 1)
			frame.index = b % 8
			frame.body = tasmanTestSymbol(uint32(b%16+1), 500, int(b)+1)
			wire, e := r.cipher.seal(&frame)
			require.NoError(t, e)
			_ = r.receive(wire, tasmanTestAddr, tasmanTestNow.Add(time.Duration(i)*time.Millisecond))
		}
		require.LessOrEqual(t, r.genOrder.Len(), tasmanGenerationLimit)
		require.LessOrEqual(t, r.symbolBytes, tasmanSymbolBytes)
		require.LessOrEqual(t, r.assemblyBytes, 2457600)
	})
}
