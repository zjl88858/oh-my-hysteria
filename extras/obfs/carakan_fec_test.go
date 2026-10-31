// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"io"
	"math/bits"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestCarakanFECReferenceAndAllFourErasures(t *testing.T) {
	for a := 1; a < 256; a++ {
		require.Equal(t, byte(1), carakanField.mul[a][carakanField.inv[a]])
	}
	data := make([]byte, 1200)
	for i := range data {
		data[i] = byte(i)
	}
	const k, width, r = 13, 96, 4
	var parity [r][width]byte
	var joined []byte
	for row := range r {
		carakanRepair(parity[row][:], data, width, k, row)
		joined = append(joined, parity[row][:]...)
	}
	require.Equal(t, "bee022adeeba3056ed3b33383feee515bc1a56aa6ee3f9373e270a4b1c667c22", fmt.Sprintf("%x", sha256.Sum256(joined)))
	cases := 0
	for erased := uint32(0); erased < 1<<(k+r); erased++ {
		if bits.OnesCount32(erased) > r {
			continue
		}
		a := carakanAssembly{count: k, width: width, data: make([]byte, len(data)), parity: make([]byte, r*width)}
		for i := range k + r {
			if erased&(1<<i) != 0 {
				continue
			}
			a.mask |= 1 << i
			if i < k {
				copy(a.data[i*width:], data[i*width:min((i+1)*width, len(data))])
			} else {
				copy(a.parity[(i-k)*width:], parity[i-k][:])
			}
		}
		recovered, ok := a.recover()
		require.True(t, ok, "mask=%x", erased)
		require.Equal(t, bits.OnesCount32(erased&((1<<k)-1)), recovered)
		require.Equal(t, data, a.data, "mask=%x", erased)
		cases++
	}
	t.Logf("all %d subsets of up to four erasures in 17 shards recovered", cases)
}

func TestCarakanFECWireLossAndLateRepairs(t *testing.T) {
	for _, h := range []float64{1, 1.5, 1.99, 2, 4, 7.5} {
		t.Run(fmt.Sprint(h), func(t *testing.T) {
			tx, wire := newCarakanTest(t, false, h)
			data := bytes.Repeat([]byte{0xa7}, 1200)
			_, err := tx.WriteTo(data, blinkServerAddr)
			require.NoError(t, err)
			k := (len(data) + tx.table.partMax - 1) / tx.table.partMax
			r := carakanRepairCount(k)
			require.Len(t, wire.output, k+r)
			for _, lost := range []int{0, 1, r, r + 1} {
				raw := &blinkTestConn{}
				rx := carakanFuzzReceiver(tx, raw)
				for index, p := range wire.output {
					if index >= lost {
						raw.input = append(raw.input, blinkTestPacket{p, blinkClientAddr})
					}
				}
				out := make([]byte, 1200)
				n, _, err := rx.ReadFrom(out)
				if lost <= r {
					require.NoError(t, err)
					require.Equal(t, data, out[:n])
					require.Equal(t, uint64(lost), rx.stats.FECRecoveredShards)
					_, _, err = rx.ReadFrom(out)
					require.ErrorIs(t, err, io.EOF)
					require.Empty(t, rx.assemblies)
					if lost == 0 {
						require.Equal(t, uint64(r), rx.stats.RedundantRepairPackets)
					}
				} else {
					require.ErrorIs(t, err, io.EOF)
					require.Zero(t, rx.stats.DeliveredBytes)
					require.Empty(t, rx.routes)
					rx.maintain(time.Now().Add(4*time.Second), 1024)
					require.Zero(t, rx.assemblyBytes)
				}
				require.Zero(t, rx.stats.AuthDrops+rx.stats.RateDrops+rx.stats.MalformedDrops)
			}
		})
	}
}

func TestCarakanFECTailPaddingAndBudget(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	parity := make([]byte, 3)
	carakanRepair(parity, data, 3, 2, 0)
	parity[2] ^= 1
	a := carakanAssembly{count: 2, width: 3, mask: 1 | 4, data: []byte{1, 2, 3, 0, 0}, parity: parity}
	_, ok := a.recover()
	require.False(t, ok, "nonzero reconstructed padding must be rejected")
	for k := 1; k <= carakanMaxData; k++ {
		require.LessOrEqual(t, k+carakanRepairCount(k), carakanMaxParts)
	}
	for _, h := range []float64{1, 1.5, 2, 4, 7.5} {
		table, err := compileCarakanTANS(carakanTestPassword, &h)
		require.NoError(t, err)
		for size := 1; size <= 1200; size++ {
			k := (size + table.partMax - 1) / table.partMax
			require.LessOrEqual(t, size+carakanRepairCount(k)*table.partMax, 1200+632)
		}
	}
}

func TestCarakanV2KeyDomainRejected(t *testing.T) {
	key, err := hkdf.Key(sha256.New, carakanTestPassword, []byte("oh-my-hysteria/carakan/v2"), "aead/client-to-server/450", 32)
	require.NoError(t, err)
	legacy, err := chacha20poly1305.NewX(key)
	require.NoError(t, err)
	rx, _ := newCarakanTest(t, true, 4.5)
	nonce := make([]byte, 24)
	sealed := legacy.Seal(nil, nonce, []byte("public legacy-domain fixture"), nil)
	_, err = rx.rx.Open(nil, nonce, sealed, nil)
	require.Error(t, err)
}

func TestCarakanUnauthenticatedRepairCannotRecover(t *testing.T) {
	tx, wire := newCarakanTest(t, false, 1.5)
	_, err := tx.WriteTo(bytes.Repeat([]byte{1}, 1200), blinkServerAddr)
	require.NoError(t, err)
	k := (1200 + tx.table.partMax - 1) / tx.table.partMax
	raw, err := tx.table.unpack(make([]byte, carakanRawMax+2), wire.output[k])
	require.NoError(t, err)
	raw[len(raw)-1] ^= 1
	bad, err := tx.table.pack(make([]byte, 1232), raw)
	require.NoError(t, err)
	input := &blinkTestConn{}
	for _, p := range wire.output[1:k] {
		input.input = append(input.input, blinkTestPacket{p, blinkClientAddr})
	}
	input.input = append(input.input, blinkTestPacket{bad, blinkClientAddr})
	rx := carakanFuzzReceiver(tx, input)
	_, _, err = rx.ReadFrom(make([]byte, 1200))
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, uint64(1), rx.stats.AuthDrops)
	require.Zero(t, rx.stats.DeliveredBytes+rx.stats.FECRecoveredMessages+rx.stats.ReceivedRepairPackets)
	require.Empty(t, rx.routes)
}

func BenchmarkCarakanRepairAndRecover(b *testing.B) {
	data := make([]byte, 1200)
	for i := range data {
		data[i] = byte(i)
	}
	var parity [4][96]byte
	for row := range 4 {
		carakanRepair(parity[row][:], data, 96, 13, row)
	}
	b.Run("encode-four", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(1200)
		for range b.N {
			for row := range 4 {
				carakanRepair(parity[row][:], data, 96, 13, row)
			}
		}
	})
	b.Run("recover-four", func(b *testing.B) {
		a := carakanAssembly{count: 13, width: 96, data: make([]byte, 1200), parity: make([]byte, 4*96), mask: ((1 << 17) - 1) &^ 15}
		b.ReportAllocs()
		b.SetBytes(1200)
		b.ResetTimer()
		for range b.N {
			copy(a.data, data)
			for row := range 4 {
				copy(a.parity[row*96:], parity[row][:])
			}
			if _, ok := a.recover(); !ok {
				b.Fatal("recovery failed")
			}
		}
	})
}
