// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type carakanWireRecord struct {
	Packets, Bytes         int
	Lengths                []int
	Histogram, First, Last [256]int
	SequenceHash           string
	UnrotatedLast          [256]int
	PositionBins           [16][256]int
	Prefix, Suffix         [8][256]int
	Transitions            [16][16]int
}

type carakanRecordingConn struct {
	net.PacketConn
	record carakanWireRecord
	digest hash.Hash
	table  *carakanTANS
}

func (c *carakanRecordingConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}
	c.record.Packets++
	c.record.Bytes += n
	c.record.Lengths = append(c.record.Lengths, n)
	if n > 0 {
		c.record.First[p[0]]++
		c.record.Last[p[n-1]]++
		shift := c.table.rotation(p[:n])
		c.record.UnrotatedLast[p[(n-1+n-shift)%n]]++
	}
	for i, b := range p[:n] {
		c.record.Histogram[b]++
		c.record.PositionBins[i*16/n][b]++
		if i < 8 {
			c.record.Prefix[i][b]++
		}
		if n-1-i < 8 {
			c.record.Suffix[n-1-i][b]++
		}
		if i > 0 {
			c.record.Transitions[p[i-1]>>4][b>>4]++
		}
	}
	c.digest.Write(p[:n])
	return n, addr, nil
}

func TestCarakanSpectrumExperiment(t *testing.T) {
	out := os.Getenv("OMHY_CARAKAN_TRACE_DIR")
	if out == "" {
		t.Skip("explicit opt-in loopback spectral experiment; no public listener")
	}
	require.NoError(t, os.Mkdir(out, 0o700), "refuse overwriting a prior experiment")
	type testCase struct {
		key, session int
		entropy      float64
	}
	var cases []testCase
	keyOffset := 0
	if value := os.Getenv("OMHY_CARAKAN_TRACE_KEY_OFFSET"); value != "" {
		var err error
		keyOffset, err = strconv.Atoi(value)
		require.NoError(t, err)
		require.GreaterOrEqual(t, keyOffset, 0)
	}
	for key := range 8 {
		for session := range 2 {
			for _, h := range []float64{1, 2.5, 4, 4.5, 7.5} {
				cases = append(cases, testCase{key + keyOffset, session, h})
			}
		}
	}
	order := rand.New(rand.NewPCG(0x636172616b616e, 1))
	order.Shuffle(len(cases), func(i, j int) { cases[i], cases[j] = cases[j], cases[i] })
	for _, tc := range cases {
		name := fmt.Sprintf("h-%03d-key-%02d-session-%02d.json", int(tc.entropy*100), tc.key, tc.session)
		t.Run(name, func(t *testing.T) {
			key := sha256.Sum256([]byte(fmt.Sprintf("oh-my-hysteria/carakan/experiment/password/%02d", tc.key)))
			password := []byte(hex.EncodeToString(key[:])) // Public test corpus only.
			su, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer su.Close()
			cu, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer cu.Close()
			for _, pc := range []net.PacketConn{su, cu} {
				require.NoError(t, pc.SetDeadline(time.Now().Add(20*time.Second)))
			}
			sraw := &carakanRecordingConn{PacketConn: su, digest: sha256.New()}
			craw := &carakanRecordingConn{PacketConn: cu, digest: sha256.New()}
			sw, err := WrapPacketConnCarakan(sraw, CarakanOptions{Password: password, Server: true, TargetEntropy: &tc.entropy})
			require.NoError(t, err)
			defer sw.Close()
			cw, err := WrapPacketConnCarakan(craw, CarakanOptions{Password: password, TargetEntropy: &tc.entropy})
			require.NoError(t, err)
			defer cw.Close()
			sraw.table, craw.table = cw.(*carakanPacketConn).table, sw.(*carakanPacketConn).table
			done := make(chan error, 1)
			var counts []int
			go func() {
				buf := make([]byte, 1200)
				for range 64 {
					n, addr, err := sw.ReadFrom(buf)
					if err == nil {
						_, err = sw.WriteTo(buf[:n], addr)
					}
					if err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			buf := make([]byte, 1200)
			application := 0
			for message := range 64 {
				size := []int{1200, 64, 256, 512, 900, 1200, 1200, 1200}[message%8]
				payload := bytes.Repeat([]byte{byte(message)}, size)
				before := cw.(interface{ CarakanStats() CarakanStats }).CarakanStats().SentPackets
				_, err := cw.WriteTo(payload, su.LocalAddr())
				require.NoError(t, err)
				after := cw.(interface{ CarakanStats() CarakanStats }).CarakanStats().SentPackets
				counts = append(counts, int(after-before))
				n, _, err := cw.ReadFrom(buf)
				require.NoError(t, err)
				require.Equal(t, payload, buf[:n])
				application += size
			}
			require.NoError(t, <-done)
			// Receive the final unneeded repairs too; otherwise the last codeword
			// would be truncated in the wire histogram merely by early delivery.
			for _, pc := range []net.PacketConn{cw, sw} {
				require.NoError(t, pc.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
				_, _, err := pc.ReadFrom(make([]byte, 1200))
				require.Error(t, err)
				var timeout net.Error
				require.ErrorAs(t, err, &timeout)
				require.True(t, timeout.Timeout())
			}
			cs := cw.(interface{ CarakanStats() CarakanStats }).CarakanStats()
			ss := sw.(interface{ CarakanStats() CarakanStats }).CarakanStats()
			for _, stats := range []CarakanStats{cs, ss} {
				require.Zero(t, stats.AuthDrops+stats.MalformedDrops+stats.RateDrops+stats.ResourceDrops+stats.ReplayDrops+stats.FreshnessDrops)
				require.Equal(t, int64(stats.SentInnerBytes+stats.SentRepairBytes+stats.SentPackets*carakanOverhead)+stats.ShapingBytes, int64(stats.SentWireBytes))
			}
			for i, n := range counts {
				if i%8 == 0 || i%8 >= 5 {
					require.GreaterOrEqual(t, n, 2)
				}
			}
			for _, raw := range []*carakanRecordingConn{sraw, craw} {
				raw.record.SequenceHash = hex.EncodeToString(raw.digest.Sum(nil))
				observed, tv := 0.0, 0.0
				for i, n := range raw.record.Histogram {
					p := float64(n) / float64(raw.record.Bytes)
					if n > 0 {
						observed -= p * math.Log2(p)
					}
					tv += math.Abs(p - float64(cs.Spectrum[i])/carakanStates)
				}
				require.InDelta(t, cs.SpectrumEntropy, observed, .08)
				require.Less(t, tv/2, .06)
				for _, n := range raw.record.Lengths {
					require.LessOrEqual(t, n, 1232)
				}
			}
			record := struct {
				KeyIndex, Session        int
				TargetEntropy            float64
				C2S, S2C                 carakanWireRecord
				MessagePackets           []int
				ApplicationPerDirection  int
				ClientStats, ServerStats CarakanStats
				Runtime                  string
			}{tc.key, tc.session, tc.entropy, sraw.record, craw.record, counts, application, cs, ss, runtime.Version() + "/" + runtime.GOOS + "/" + runtime.GOARCH}
			data, err := json.Marshal(record)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(out, name), data, 0o600))
		})
	}
}
