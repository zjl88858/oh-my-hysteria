// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type prestoWireEvent struct {
	Length int   `json:"length"`
	AtNS   int64 `json:"at_ns"`
}

// Record REAL received UDP datagrams, before decoding. No payload or nonce is
// retained; timing is the receiver's monotonic userspace timestamp, not a NIC
// hardware timestamp. Each direction is measured independently.
type prestoRecordingConn struct {
	net.PacketConn
	start  time.Time
	events []prestoWireEvent
}

func (c *prestoRecordingConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		c.events = append(c.events, prestoWireEvent{Length: n, AtNS: time.Since(c.start).Nanoseconds()})
	}
	return n, addr, err
}

func TestPrestoTrafficGrammarExperiment(t *testing.T) {
	out := os.Getenv("OMHY_PRESTO_TRACE_DIR")
	if out == "" {
		t.Skip("explicit opt-in native UDP experiment; no public listener")
	}
	require.NoError(t, os.MkdirAll(out, 0o700))
	cases := make([][2]int, 0, 128)
	for key := range 16 {
		for session := range 8 {
			cases = append(cases, [2]int{key, session})
		}
	}
	order := rand.New(rand.NewPCG(0x70726573746f, 1))
	order.Shuffle(len(cases), func(i, j int) { cases[i], cases[j] = cases[j], cases[i] })
	for _, testCase := range cases {
		keyIndex, session := testCase[0], testCase[1]
		key := sha256.Sum256([]byte(fmt.Sprintf("oh-my-hysteria/presto/experiment/password/%02d", keyIndex)))
		password := []byte(hex.EncodeToString(key[:])) // public test-only corpus
		name := fmt.Sprintf("key-%02d-session-%02d.json", keyIndex, session)
		t.Run(name, func(t *testing.T) {
			_, err := os.Stat(filepath.Join(out, name))
			require.True(t, os.IsNotExist(err), "refuse overwriting an earlier result")
			start := time.Now()
			serverUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer serverUDP.Close()
			clientUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer clientUDP.Close()
			for _, pc := range []net.PacketConn{serverUDP, clientUDP} {
				require.NoError(t, pc.SetDeadline(time.Now().Add(20*time.Second)))
			}
			sraw := &prestoRecordingConn{PacketConn: serverUDP, start: start}
			craw := &prestoRecordingConn{PacketConn: clientUDP, start: start}
			sw, err := WrapPacketConnPresto(sraw, PrestoOptions{Password: password, Server: true})
			require.NoError(t, err)
			defer sw.Close()
			cw, err := WrapPacketConnPresto(craw, PrestoOptions{Password: password})
			require.NoError(t, err)
			defer cw.Close()
			c, s := cw.(*prestoPacketConn), sw.(*prestoPacketConn)
			counts := make([]int, 0, 1024)
			serverDone := make(chan error, 1)
			clientDone := make(chan struct{})
			replies := make(chan error, 1)
			// Both receivers must already be reading while the other side
			// sends: draining a socket only after WriteTo would erase the
			// within-message pacing in userspace receive timestamps.
			go func() {
				buf := make([]byte, 1200)
				for range 1024 {
					before := len(sraw.events)
					n, addr, err := s.ReadFrom(buf)
					if err != nil {
						serverDone <- err
						return
					}
					counts = append(counts, len(sraw.events)-before)
					if _, err := s.WriteTo(buf[:n], addr); err != nil {
						serverDone <- err
						return
					}
				}
				serverDone <- nil
			}()
			go func() {
				defer close(clientDone)
				buf := make([]byte, 1200)
				for message := range 1024 {
					n, _, err := c.ReadFrom(buf)
					size := []int{64, 256, 512, 900, 1200, 1200, 1200, 1200}[message%8]
					if err == nil && !bytes.Equal(buf[:n], bytes.Repeat([]byte{byte(message)}, size)) {
						err = fmt.Errorf("echo mismatch at message %d", message)
					}
					replies <- err
					if err != nil {
						return
					}
				}
			}()
			application := 0
			for message := range 1024 {
				size := []int{64, 256, 512, 900, 1200, 1200, 1200, 1200}[message%8]
				data := bytes.Repeat([]byte{byte(message)}, size)
				_, err = c.WriteTo(data, serverUDP.LocalAddr())
				require.NoError(t, err)
				select {
				case err := <-replies:
					require.NoError(t, err)
				case <-time.After(20 * time.Second):
					t.Fatal("native echo timeout")
				}
				application += size
				if message%16 == 15 {
					time.Sleep(2 * time.Millisecond)
				}
			}
			require.NoError(t, <-serverDone)
			<-clientDone
			cs, ss := c.PrestoStats(), s.PrestoStats()
			require.Zero(t, cs.RateDrops)
			require.Zero(t, ss.RateDrops)
			require.Zero(t, cs.ResourceDrops)
			require.Zero(t, ss.ResourceDrops)
			record := struct {
				KeyIndex                 int `json:"key_index"`
				Session                  int `json:"session"`
				C2S, S2C                 []prestoWireEvent
				MessagePackets           []int `json:"message_packets"`
				ClientStats, ServerStats PrestoStats
				ApplicationPerDirection  int     `json:"application_per_direction"`
				WallSeconds              float64 `json:"wall_seconds"`
				Runtime                  string  `json:"runtime"`
			}{keyIndex, session, sraw.events, craw.events, counts, cs, ss, application, time.Since(start).Seconds(), runtime.Version() + "/" + runtime.GOOS + "/" + runtime.GOARCH}
			data, err := json.Marshal(record)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(out, name), data, 0o600))
		})
	}
}
