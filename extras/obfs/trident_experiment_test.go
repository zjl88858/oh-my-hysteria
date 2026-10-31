// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type tridentWireRecord struct {
	Lengths      []int
	OpcodeCounts [256]int
	Programs     int
	Bytes        int
	SequenceHash string
}

type tridentRecordingConn struct {
	net.PacketConn
	isa    tridentISA
	buffer [tridentRawMax + 12]byte
	record tridentWireRecord
	digest hash.Hash
}

func (c *tridentRecordingConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}
	if _, err := c.isa.unpack(c.buffer[:], p[:n]); err != nil {
		return 0, addr, fmt.Errorf("captured non-canonical bytecode: %w", err)
	}
	c.record.Programs++
	c.record.Bytes += n
	c.record.Lengths = append(c.record.Lengths, n)
	c.digest.Write(p[:n]) // Only the final sequence hash is retained, no payload.
	for pos := 0; pos < n; {
		ins := c.isa.code[c.isa.reverse[p[pos]]]
		c.record.OpcodeCounts[ins.opcode]++
		pos++
		pos += (-pos)&(int(ins.alignment)-1) + int(ins.operands)
	}
	return n, addr, nil
}

func TestTridentBytecodeExperiment(t *testing.T) {
	out := os.Getenv("OMHY_TRIDENT_TRACE_DIR")
	if out == "" {
		t.Skip("explicit opt-in loopback bytecode experiment; no public listener")
	}
	require.NoError(t, os.Mkdir(out, 0o700), "refuse reusing an earlier experiment directory")
	cases := make([][2]int, 0, 64)
	for key := range 16 {
		for session := range 4 {
			cases = append(cases, [2]int{key, session})
		}
	}
	order := rand.New(rand.NewPCG(0x74726964656e74, 1))
	order.Shuffle(len(cases), func(i, j int) { cases[i], cases[j] = cases[j], cases[i] })
	for _, testCase := range cases {
		keyIndex, session := testCase[0], testCase[1]
		key := sha256.Sum256([]byte(fmt.Sprintf("oh-my-hysteria/trident/experiment/password/%02d", keyIndex)))
		password := []byte(hex.EncodeToString(key[:])) // Public, test-only corpus.
		name := fmt.Sprintf("key-%02d-session-%02d.json", keyIndex, session)
		t.Run(name, func(t *testing.T) {
			isa, err := compileTridentISA(password)
			require.NoError(t, err)
			su, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer su.Close()
			cu, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer cu.Close()
			for _, pc := range []net.PacketConn{su, cu} {
				require.NoError(t, pc.SetDeadline(time.Now().Add(20*time.Second)))
			}
			sraw := &tridentRecordingConn{PacketConn: su, isa: isa, digest: sha256.New()}
			craw := &tridentRecordingConn{PacketConn: cu, isa: isa, digest: sha256.New()}
			sw, err := WrapPacketConnTrident(sraw, TridentOptions{Password: password, Server: true})
			require.NoError(t, err)
			defer sw.Close()
			cw, err := WrapPacketConnTrident(craw, TridentOptions{Password: password})
			require.NoError(t, err)
			defer cw.Close()
			counts := make([]int, 0, 128)
			done := make(chan error, 1)
			go func() {
				buf := make([]byte, 1200)
				for range 128 {
					before := sraw.record.Programs
					n, addr, err := sw.ReadFrom(buf)
					if err == nil {
						counts = append(counts, sraw.record.Programs-before)
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
			for message := range 128 {
				size := []int{1200, 64, 256, 512, 900, 1200, 1200, 1200}[message%8]
				payload := bytes.Repeat([]byte{byte(message)}, size)
				_, err := cw.WriteTo(payload, su.LocalAddr())
				require.NoError(t, err)
				n, _, err := cw.ReadFrom(buf)
				require.NoError(t, err)
				require.Equal(t, payload, buf[:n])
				application += size
			}
			require.NoError(t, <-done)
			cs := cw.(interface{ TridentStats() TridentStats }).TridentStats()
			ss := sw.(interface{ TridentStats() TridentStats }).TridentStats()
			for _, stats := range []TridentStats{cs, ss} {
				require.Zero(t, stats.AuthDrops+stats.MalformedDrops+stats.RateDrops+stats.ResourceDrops)
				require.Equal(t, stats.SentInnerBytes+stats.SentPackets*84+stats.PackingBytes, stats.SentWireBytes)
			}
			for i, count := range counts {
				if i%8 == 0 || i%8 >= 5 {
					require.Contains(t, []int{3, 4}, count)
				}
			}
			for _, raw := range []*tridentRecordingConn{sraw, craw} {
				raw.record.SequenceHash = hex.EncodeToString(raw.digest.Sum(nil))
				for _, size := range raw.record.Lengths {
					require.LessOrEqual(t, size, 1232)
				}
				for _, ins := range isa.code {
					require.Positive(t, raw.record.OpcodeCounts[ins.opcode])
				}
			}
			record := struct {
				KeyIndex, Session        int
				C2S, S2C                 tridentWireRecord
				MessagePackets           []int
				ApplicationPerDirection  int
				ClientStats, ServerStats TridentStats
				Runtime                  string
			}{keyIndex, session, sraw.record, craw.record, counts, application, cs, ss, runtime.Version() + "/" + runtime.GOOS + "/" + runtime.GOARCH}
			data, err := json.Marshal(record)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(out, name), data, 0o600))
		})
	}
}
