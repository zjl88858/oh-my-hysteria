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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Native-loopback cost experiment. Explicit laboratory reservations are not
// claimed to be the QUIC congestion-control / application throughput experiment.
func TestTasmanTrafficExperiment(t *testing.T) {
	out := os.Getenv("OMHY_TASMAN_EXPERIMENT")
	if out == "" {
		t.Skip("explicit owned loopback experiment")
	}
	require.NoError(t, os.Mkdir(out, 0o700))
	workloads := []struct {
		name  string
		sizes []int
		burst int
	}{{"first1200", []int{1200}, 1}, {"first1KiB", []int{1024}, 1}, {"first10KiB", []int{1200, 1200, 1200, 1200, 1200, 1200, 1200, 1200, 640}, 8}, {"mixedSequential", []int{64, 256, 512, 900, 1200, 1200, 1200, 1200}, 1}, {"mixedBurst", []int{64, 256, 512, 900, 1200, 1200, 1200, 1200}, 8}, {"sparse1B", []int{1, 1, 1, 1, 1, 1, 1, 1}, 1}}
	long := make([]int, 256)
	for i := range long {
		long[i] = 1200
	}
	workloads = append(workloads, struct {
		name  string
		sizes []int
		burst int
	}{"long300KiB", long, 8})
	for _, w := range workloads {
		for _, mode := range []string{"tasman", "tasman-no-fec", "tasman-no-carrier", "servo", "presto"} {
			t.Run(w.name+"/"+mode, func(t *testing.T) {
				var conns [2]net.PacketConn
				var raws [2]*servoWireCounter
				for i := range 2 {
					pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
					require.NoError(t, err)
					raws[i] = &servoWireCounter{PacketConn: pc}
					switch mode {
					case "servo":
						conns[i], err = WrapPacketConnServo(raws[i], ServoOptions{Password: tasmanTestPassword, Server: i == 1})
					case "presto":
						conns[i], err = WrapPacketConnPresto(raws[i], PrestoOptions{Password: tasmanTestPassword, Server: i == 1})
					default:
						conns[i], err = WrapPacketConnTasman(raws[i], TasmanOptions{Password: tasmanTestPassword, Server: i == 1})
						if err == nil {
							c := conns[i].(*tasmanPacketConn)
							c.mu.Lock()
							if mode == "tasman-no-fec" {
								c.profile.repairs = 0
							}
							if mode == "tasman-no-carrier" {
								c.profile.collect = 0
								c.profile.tails = 0
							}
							c.mu.Unlock()
						}
					}
					require.NoError(t, err)
					defer conns[i].Close()
					require.NoError(t, conns[i].SetDeadline(time.Now().Add(20*time.Second)))
				}
				write := func(pc net.PacketConn, p []byte, addr net.Addr) (int, error) {
					if c, ok := pc.(*tasmanPacketConn); ok {
						return c.WriteToWithQUICBudget(p, addr, time.Now(), time.Now(), 2*len(p)+62)
					}
					return pc.WriteTo(p, addr)
				}
				go func() {
					var b [1200]byte
					for {
						n, addr, err := conns[1].ReadFrom(b[:])
						if err != nil {
							return
						}
						if _, err = write(conns[1], b[:n], addr); err != nil {
							return
						}
					}
				}()
				inner := 0
				var latency []int64
				begin := time.Now()
				for pos := 0; pos < len(w.sizes); {
					end := min(len(w.sizes), pos+w.burst)
					started := make(map[byte]time.Time)
					expected := make(map[byte][]byte)
					for i := pos; i < end; i++ {
						p := bytes.Repeat([]byte{byte(i)}, w.sizes[i])
						if len(p) >= 4 {
							binary.BigEndian.PutUint32(p, uint32(i))
						}
						started[byte(i)] = time.Now()
						expected[byte(i)] = bytes.Clone(p)
						_, err := write(conns[0], p, conns[1].LocalAddr())
						require.NoError(t, err)
						inner += len(p)
						clear(p)
					}
					for i := pos; i < end; i++ {
						var b [1200]byte
						n, _, err := conns[0].ReadFrom(b[:])
						require.NoError(t, err)
						id := byte(i)
						if n >= 4 {
							id = byte(binary.BigEndian.Uint32(b[:4]))
						}
						require.Equal(t, expected[id], b[:n])
						latency = append(latency, time.Since(started[id]).Nanoseconds())
					}
					pos = end
					if w.name == "sparse1B" {
						time.Sleep(5 * time.Millisecond)
					}
				}
				rows := []map[string]any{}
				for i, pc := range conns {
					var stats any
					switch mode {
					case "presto":
						c := pc.(interface{ PrestoStats() PrestoStats })
						require.Eventually(t, func() bool { return c.PrestoStats().SentInnerBytes == uint64(inner) }, time.Second, time.Millisecond)
						stats = c.PrestoStats()
					case "servo":
						c := pc.(interface{ ServoStats() ServoStats })
						require.Eventually(t, func() bool { return c.ServoStats().PendingDatagrams == 0 }, time.Second, time.Millisecond)
						stats = c.ServoStats()
					default:
						c := pc.(*tasmanPacketConn)
						tasmanDrained(t, c)
						time.Sleep(3 * c.profile.carrier)
						s := c.TasmanStats()
						require.Zero(t, s.AsyncErrors)
						require.LessOrEqual(t, s.OuterSentBytes, 2*s.InnerAcceptedBytes+s.TinyExceptionBytes)
						stats = s
					}
					raws[i].mu.Lock()
					b, n := raws[i].bytes, raws[i].packets
					raws[i].mu.Unlock()
					rows = append(rows, map[string]any{"inner_bytes": inner, "inner_datagrams": len(w.sizes), "outer_udp_payload_bytes": b, "outer_packets": n, "udp_expansion": float64(b) / float64(inner), "ipv4_expansion": float64(b+28*n) / float64(inner+28*len(w.sizes)), "ipv6_expansion": float64(b+48*n) / float64(inner+48*len(w.sizes)), "stats": stats})
				}
				sort.Slice(latency, func(i, j int) bool { return latency[i] < latency[j] })
				data, err := json.MarshalIndent(map[string]any{"mode": mode, "workload": w.name, "directions": rows, "echo_p95_ns": latency[(len(latency)-1)*95/100], "echo_p99_ns": latency[(len(latency)-1)*99/100], "elapsed_ns": time.Since(begin).Nanoseconds(), "note": "direct loopback; explicit lab permits, not application goodput or isolated CPU ranking"}, "", "  ")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(out, w.name+"-"+mode+".json"), data, 0o600))
			})
		}
	}
}
