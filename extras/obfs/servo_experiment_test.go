// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type servoWireCounter struct {
	net.PacketConn
	mu             sync.Mutex
	bytes, packets int
}

func (c *servoWireCounter) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if err == nil && n == len(p) {
		c.mu.Lock()
		c.bytes += n
		c.packets++
		c.mu.Unlock()
	}
	return n, err
}

func TestServoTrafficExperiment(t *testing.T) {
	out := os.Getenv("OMHY_SERVO_EXPERIMENT")
	if out == "" {
		t.Skip("explicit native loopback paired experiment")
	}
	require.NoError(t, os.Mkdir(out, 0o700))
	workloads := []struct {
		name   string
		sizes  []int
		burst  int
		sparse bool
	}{
		{"first-1200", []int{1200}, 1, false},
		{"first-1KiB", []int{1024}, 1, false},
		{"first-10KiB", []int{1200, 1200, 1200, 1200, 1200, 1200, 1200, 1200, 640}, 8, false},
		{"mixed-sequential", []int{64, 256, 512, 900, 1200, 1200, 1200, 1200}, 1, false},
		{"mixed-burst", []int{64, 256, 512, 900, 1200, 1200, 1200, 1200}, 8, false},
		{"sparse-64", []int{64, 64, 64, 64, 64, 64, 64, 64}, 1, true},
	}
	long := make([]int, 256)
	for i := range long {
		long[i] = 1200
	}
	workloads = append(workloads, struct {
		name   string
		sizes  []int
		burst  int
		sparse bool
	}{"long-300KiB", long, 8, false})
	for _, workload := range workloads {
		for _, mode := range []string{"servo", "servo-no-wait-ablation", "presto"} {
			t.Run(workload.name+"/"+mode, func(t *testing.T) {
				password := []byte("servo-paired-experiment-public-password-32+")
				var raws [2]*servoWireCounter
				var conns [2]net.PacketConn
				for i := range 2 {
					pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
					require.NoError(t, err)
					raws[i] = &servoWireCounter{PacketConn: pc}
					if mode == "presto" {
						conns[i], err = WrapPacketConnPresto(raws[i], PrestoOptions{Password: password, Server: i == 1})
					} else {
						conns[i], err = WrapPacketConnServo(raws[i], ServoOptions{Password: password, Server: i == 1})
					}
					require.NoError(t, err)
					defer conns[i].Close()
					if mode == "servo-no-wait-ablation" {
						c := conns[i].(*servoPacketConn)
						c.mu.Lock()
						c.profile.wait = 0
						c.mu.Unlock()
					}
					require.NoError(t, conns[i].SetDeadline(time.Now().Add(15*time.Second)))
				}
				go func() {
					var buf [1200]byte
					for {
						n, addr, err := conns[1].ReadFrom(buf[:])
						if err != nil {
							return
						}
						if _, err = conns[1].WriteTo(buf[:n], addr); err != nil {
							return
						}
					}
				}()
				starts := make(map[uint32]time.Time)
				payloads := make(map[uint32][]byte)
				var latency []int64
				inner := 0
				begin := time.Now()
				for pos := 0; pos < len(workload.sizes); {
					end := min(len(workload.sizes), pos+workload.burst)
					for i := pos; i < end; i++ {
						p := bytes.Repeat([]byte{byte(i)}, workload.sizes[i])
						binary.BigEndian.PutUint32(p[:4], uint32(i+1))
						payloads[uint32(i+1)] = bytes.Clone(p)
						starts[uint32(i+1)] = time.Now()
						n, err := conns[0].WriteTo(p, conns[1].LocalAddr())
						require.NoError(t, err)
						inner += n
						clear(p)
					}
					for i := pos; i < end; i++ {
						var p [1200]byte
						n, _, err := conns[0].ReadFrom(p[:])
						require.NoError(t, err)
						id := binary.BigEndian.Uint32(p[:4])
						require.Equal(t, payloads[id], p[:n])
						delete(payloads, id)
						latency = append(latency, int64(time.Since(starts[id])))
					}
					pos = end
					if workload.sparse {
						time.Sleep(5 * time.Millisecond)
					}
				}
				sort.Slice(latency, func(i, j int) bool { return latency[i] < latency[j] })
				stats := []ServoStats{}
				if mode != "presto" {
					for _, pc := range conns {
						c := pc.(*servoPacketConn)
						waitServoDrained(t, c)
						s := c.ServoStats()
						require.Zero(t, s.AsyncErrors)
						stats = append(stats, s)
					}
				} else {
					// Kernel receive can beat the writer's post-syscall counter
					// update. Wait for BOTH synchronous Presto writers to finish
					// accounting before reading the raw wire counters.
					for _, pc := range conns {
						c := pc.(interface{ PrestoStats() PrestoStats })
						require.Eventually(t, func() bool { return c.PrestoStats().SentInnerBytes == uint64(inner) }, time.Second, time.Millisecond)
					}
				}
				rows := []map[string]any{}
				for _, raw := range raws {
					raw.mu.Lock()
					b, n := raw.bytes, raw.packets
					raw.mu.Unlock()
					rows = append(rows, map[string]any{"inner_bytes": inner, "inner_datagrams": len(workload.sizes), "outer_udp_payload_bytes": b, "outer_packets": n, "udp_expansion": float64(b) / float64(inner), "ipv4_expansion": float64(b+28*n) / float64(inner+28*len(workload.sizes)), "packet_expansion": float64(n) / float64(len(workload.sizes))})
				}
				record := map[string]any{"mode": mode, "workload": workload.name, "directions": rows, "elapsed_ns": time.Since(begin).Nanoseconds(), "echo_p95_ns": latency[(len(latency)-1)*95/100], "echo_p99_ns": latency[(len(latency)-1)*99/100], "servo_stats": stats, "note": "direct native UDP loopback, not QUIC goodput or an isolated CPU/throughput ranking"}
				encoded, err := json.MarshalIndent(record, "", "  ")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(out, workload.name+"-"+mode+".json"), encoded, 0o600))
			})
		}
	}
}

func BenchmarkServoCodec(b *testing.B) {
	c := servoTestCipher(b, 0)
	frame := servoTestFixture("max", 0)
	wire, err := c.seal(&frame)
	require.NoError(b, err)
	b.Run("seal-1100", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(1100)
		for b.Loop() {
			_, err := c.seal(&frame)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("open-1232", func(b *testing.B) {
		var scratch [servoWireMax]byte
		b.ReportAllocs()
		b.SetBytes(1232)
		for b.Loop() {
			_, err := c.open(wire, &scratch)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
