// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMarinerTrafficExperiment(t *testing.T) {
	out := os.Getenv("OMHY_MARINER_EXPERIMENT")
	if out == "" {
		t.Skip("owned loopback experiment")
	}
	require.NoError(t, os.Mkdir(out, 0o700))
	workloads := []struct {
		name  string
		sizes []int
	}{{"first1200", []int{1200}}, {"first1KiB", []int{1024}}, {"first10KiB", []int{1200, 1200, 1200, 1200, 1200, 1200, 1200, 1200, 640}}, {"mixed6532", []int{64, 256, 512, 900, 1200, 1200, 1200, 1200}}, {"sparse64", []int{64, 64, 64, 64, 64, 64, 64, 64}}, {"tiny1", []int{1}}}
	long := make([]int, 256)
	for i := range long {
		long[i] = 1200
	}
	workloads = append(workloads, struct {
		name  string
		sizes []int
	}{"long300KiB", long})
	for _, work := range workloads {
		for _, mode := range []string{"mariner", "presto"} {
			t.Run(work.name+"/"+mode, func(t *testing.T) {
				var conns [2]net.PacketConn
				var raws [2]*servoWireCounter
				for i := range 2 {
					pc, e := net.ListenPacket("udp4", "127.0.0.1:0")
					require.NoError(t, e)
					raws[i] = &servoWireCounter{PacketConn: pc}
					if mode == "mariner" {
						conns[i], e = WrapPacketConnMariner(raws[i], MarinerOptions{Password: marinerTestPassword, Server: i == 1})
					} else {
						conns[i], e = WrapPacketConnPresto(raws[i], PrestoOptions{Password: marinerTestPassword, Server: i == 1})
					}
					require.NoError(t, e)
					defer conns[i].Close()
					require.NoError(t, conns[i].SetDeadline(time.Now().Add(20*time.Second)))
				}
				go func() {
					var b [1200]byte
					for {
						n, a, e := conns[1].ReadFrom(b[:])
						if e != nil {
							return
						}
						if _, e = conns[1].WriteTo(b[:n], a); e != nil {
							return
						}
					}
				}()
				inner := 0
				var latency []int64
				begin := time.Now()
				for i, n := range work.sizes {
					p := bytes.Repeat([]byte{byte(i)}, n)
					start := time.Now()
					_, e := conns[0].WriteTo(p, conns[1].LocalAddr())
					require.NoError(t, e)
					var out [1200]byte
					got, _, e := conns[0].ReadFrom(out[:])
					require.NoError(t, e)
					require.Equal(t, p, out[:got])
					latency = append(latency, time.Since(start).Nanoseconds())
					inner += n
					if work.name == "sparse64" {
						time.Sleep(5 * time.Millisecond)
					}
				}
				rows := []map[string]any{}
				for i, pc := range conns {
					var stats any
					if mode == "mariner" {
						c := pc.(*marinerPacketConn)
						require.Eventually(t, func() bool { return c.MarinerStats().InnerSentBytes == uint64(inner) }, time.Second, time.Millisecond)
						stats = c.MarinerStats()
					} else {
						c := pc.(interface{ PrestoStats() PrestoStats })
						require.Eventually(t, func() bool { return c.PrestoStats().SentInnerBytes == uint64(inner) }, time.Second, time.Millisecond)
						stats = c.PrestoStats()
					}
					raws[i].mu.Lock()
					b, n := raws[i].bytes, raws[i].packets
					raws[i].mu.Unlock()
					rows = append(rows, map[string]any{"inner_bytes": inner, "inner_datagrams": len(work.sizes), "outer_udp_payload_bytes": b, "outer_packets": n, "udp_expansion": float64(b) / float64(inner), "ipv4_expansion": float64(b+28*n) / float64(inner+28*len(work.sizes)), "ipv6_expansion": float64(b+48*n) / float64(inner+48*len(work.sizes)), "stats": stats})
				}
				sort.Slice(latency, func(i, j int) bool { return latency[i] < latency[j] })
				data, e := json.MarshalIndent(map[string]any{"mode": mode, "workload": work.name, "directions": rows, "elapsed_ns": time.Since(begin).Nanoseconds(), "echo_p95_ns": latency[(len(latency)-1)*95/100], "echo_p99_ns": latency[(len(latency)-1)*99/100], "note": "single owned loopback sample; sequential echo, not application goodput"}, "", "  ")
				require.NoError(t, e)
				require.NoError(t, os.WriteFile(filepath.Join(out, work.name+"-"+mode+".json"), data, 0o600))
			})
		}
	}
}

// Same L/r and balanced per-session sample counts. Offline public test keys
// only; train/test grouping is recorded explicitly for the external learner.
func TestMarinerShapeDataset(t *testing.T) {
	path := os.Getenv("OMHY_MARINER_DATASET")
	if path == "" {
		t.Skip("explicit offline classifier dataset")
	}
	file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	require.NoError(t, e)
	defer file.Close()
	buf := bufio.NewWriter(file)
	defer buf.Flush()
	enc := json.NewEncoder(buf)
	passwords := [][]byte{}
	for candidate := 0; len(passwords) < 12; candidate++ {
		password := []byte(fmt.Sprintf("mariner-shape-public-password-%08d", candidate))
		p, e := compileMarinerProfile(password, 0)
		require.NoError(t, e)
		if p.density == 18 {
			passwords = append(passwords, password)
		}
	}
	for id, password := range passwords {
		p, e := compileMarinerProfile(password, 0)
		require.NoError(t, e)
		c, e := newMarinerCipher(password, 0)
		require.NoError(t, e)
		const l = 512
		var original marinerGraph
		require.NoError(t, p.graph(l, &original))
		n := original.k - 62 // delta is exactly zero at this chosen length
		modes := []string{"mixed", "order3", "order4", "order5", "pool16", "poolAll", "no-interleave", "random-padding", "raw-aead", "random"}
		profiles := make([]marinerProfile, len(modes))
		graphs := make([]marinerGraph, len(modes))
		for i, mode := range modes {
			profiles[i], graphs[i] = p, original
			switch mode {
			case "order3":
				profiles[i].orders = [3]int{1, 0, 0}
			case "order4":
				profiles[i].orders = [3]int{0, 1, 0}
			case "order5":
				profiles[i].orders = [3]int{0, 0, 1}
			case "pool16":
				profiles[i].pool = 16
			case "poolAll":
				profiles[i].pool = 0
			}
			if mode == "order3" || mode == "order4" || mode == "order5" || mode == "pool16" || mode == "poolAll" {
				require.NoError(t, profiles[i].graph(l, &graphs[i]))
			}
			if mode == "no-interleave" {
				for j := range l {
					graphs[i].positions[j] = uint16(j)
				}
			}
		}
		for session := range 4 {
			var prefix [16]byte
			_, e = rand.Read(prefix[:])
			require.NoError(t, e)
			for packet := range 256 {
				f := marinerTestFrame(n)
				_, e = rand.Read(f.data)
				require.NoError(t, e)
				f.session = prefix
				f.counter = uint64(packet)
				var raw, out [1232]byte
				b, e := c.seal(raw[:], &f, &p, l)
				require.NoError(t, e)
				for index, mode := range modes {
					profile, graph := &profiles[index], &graphs[index]
					w, e := profile.encode(out[:], b, graph)
					require.NoError(t, e)
					if mode == "random-padding" {
						for j := range graph.r {
							_, e = rand.Read(w[graph.positions[graph.k+j]:][:1])
							require.NoError(t, e)
						}
					}
					if mode == "raw-aead" {
						copy(w, b)
						_, e = rand.Read(w[len(b):])
						require.NoError(t, e)
					}
					if mode == "random" {
						_, e = rand.Read(w)
						require.NoError(t, e)
					}
					require.NoError(t, enc.Encode(map[string]any{"password_id": id, "session": session, "packet": packet, "mode": mode, "density": p.density, "wire": w, "raw_sha256": fmt.Sprintf("%x", sha256.Sum256(b))}))
				}
			}
		}
	}
}

func TestMarinerDeltaLengthExperiment(t *testing.T) {
	path := os.Getenv("OMHY_MARINER_DELTA")
	if path == "" {
		t.Skip("explicit length ablation")
	}
	p, e := compileMarinerProfile(marinerTestPassword, 0)
	require.NoError(t, e)
	rows := []map[string]any{}
	for density := 16; density <= 20; density++ {
		p.density = density
		without, with := map[int]bool{}, map[int]bool{}
		for n := 1; n <= p.capacity(); n++ {
			base := p.wireBase(62 + n)
			without[base] = true
			for delta := 0; delta <= min(3, 1232-base); delta++ {
				with[base+delta] = true
			}
		}
		rows = append(rows, map[string]any{"density": density, "without_delta_lengths": len(without), "with_delta_lengths": len(with), "continuous_expected": 1233 - p.wireBase(63)})
	}
	data, e := json.MarshalIndent(rows, "", "  ")
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

// End-to-end synchronous wrapper + codec CPU cost without kernel scheduling.
func BenchmarkMarinerWrite1200(b *testing.B) {
	c, raw := newMarinerTestConn(b)
	p := make([]byte, 1200)
	b.ReportAllocs()
	b.SetBytes(1200)
	b.ResetTimer()
	for b.Loop() {
		_, e := c.WriteTo(p, blinkServerAddr)
		if e != nil {
			b.Fatal(e)
		}
		raw.mu.Lock()
		raw.writes = raw.writes[:0]
		raw.mu.Unlock()
	}
}

func TestMarinerCaptureAudit(t *testing.T) { marinerAuditCapture(t) }

func TestMarinerFamilyDataset(t *testing.T) {
	path, controls := os.Getenv("OMHY_MARINER_FAMILY"), os.Getenv("OMHY_MARINER_CONTROLS")
	if path == "" || controls == "" {
		t.Skip("explicit matched-length public-capture dataset")
	}
	in, e := os.Open(controls)
	require.NoError(t, e)
	defer in.Close()
	var rows []struct {
		Source string
		Sample int
		Wire   []byte
	}
	dec := json.NewDecoder(in)
	for {
		var row struct {
			Source string
			Sample int
			Wire   []byte
		}
		e = dec.Decode(&row)
		if e == io.EOF {
			break
		}
		require.NoError(t, e)
		require.GreaterOrEqual(t, len(row.Wire), 83)
		require.LessOrEqual(t, len(row.Wire), 1232)
		rows = append(rows, row)
	}
	file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	require.NoError(t, e)
	defer file.Close()
	buffer := bufio.NewWriter(file)
	defer buffer.Flush()
	enc := json.NewEncoder(buffer)
	id := 0
	for candidate := 0; id < 12; candidate++ {
		password := []byte(fmt.Sprintf("mariner-shape-public-password-%08d", candidate))
		p, e := compileMarinerProfile(password, 0)
		require.NoError(t, e)
		if p.density != 18 {
			continue
		}
		c, e := newMarinerCipher(password, 0)
		require.NoError(t, e)
		var session [16]byte
		_, e = rand.Read(session[:])
		require.NoError(t, e)
		for index, row := range rows {
			l := len(row.Wire)
			var g marinerGraph
			require.NoError(t, p.graph(l, &g))
			f := marinerTestFrame(g.k - 62)
			f.session = session
			f.counter = uint64(index)
			_, e = rand.Read(f.data)
			require.NoError(t, e)
			var raw, wire [1232]byte
			b, e := c.seal(raw[:], &f, &p, l)
			require.NoError(t, e)
			w, e := p.encode(wire[:], b, &g)
			require.NoError(t, e)
			require.NoError(t, enc.Encode(map[string]any{"password_id": id, "source": row.Source, "sample": row.Sample, "wire": w}))
		}
		id++
	}
}
