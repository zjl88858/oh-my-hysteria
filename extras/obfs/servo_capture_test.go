// SPDX-License-Identifier: MIT-0

package obfs

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

// Linux isolated-namespace pcap, independent of the wrapper's method counters.
// Known-key parsing establishes envelope correctness, NOT blind indistinguishability.
func TestServoCaptureAudit(t *testing.T) {
	path, metadata := os.Getenv("OMHY_SERVO_PCAP"), os.Getenv("OMHY_SERVO_WIRE_AUDIT")
	if path == "" || metadata == "" {
		t.Skip("explicit owned-loopback capture only")
	}
	directions := make(map[[2]int]byte)
	files, err := filepath.Glob(filepath.Join(metadata, "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, file := range files {
		var m struct{ Server, Client string }
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &m))
		_, sp, err := net.SplitHostPort(m.Server)
		require.NoError(t, err)
		_, cp, err := net.SplitHostPort(m.Client)
		require.NoError(t, err)
		s, err := strconv.Atoi(sp)
		require.NoError(t, err)
		c, err := strconv.Atoi(cp)
		require.NoError(t, err)
		directions[[2]int{c, s}], directions[[2]int{s, c}] = 0, 1
	}
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	ciphers := [2]*servoCipher{}
	for i := range 2 {
		ciphers[i], err = newServoCipher([]byte("servo-integration-public-random-test-32+"), byte(i))
		require.NoError(t, err)
	}
	matched, largest := 0, 0
	for {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		p := gopacket.NewPacket(data, r.LinkType(), gopacket.NoCopy)
		layer := p.Layer(layers.LayerTypeUDP)
		if layer == nil {
			continue
		}
		udp := layer.(*layers.UDP)
		dir, ok := directions[[2]int{int(udp.SrcPort), int(udp.DstPort)}]
		if !ok {
			continue
		}
		var scratch [servoWireMax]byte
		_, err = ciphers[dir].open(udp.Payload, &scratch)
		require.NoError(t, err, "actual pcap UDP %d -> %d", udp.SrcPort, udp.DstPort)
		largest = max(largest, len(udp.Payload))
		matched++
	}
	require.Positive(t, matched)
	t.Logf("SERVO_PCAP_AUTHENTICATED=%d MAX_UDP_PAYLOAD=%d", matched, largest)
}
