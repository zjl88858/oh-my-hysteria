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

func TestTasmanCaptureAudit(t *testing.T) {
	path, metadata := os.Getenv("OMHY_TASMAN_PCAP"), os.Getenv("OMHY_TASMAN_WIRE_AUDIT")
	if path == "" || metadata == "" {
		t.Skip("owned namespace pcap only")
	}
	dirs := map[[2]int]byte{}
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
		dirs[[2]int{c, s}], dirs[[2]int{s, c}] = 0, 1
	}
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	var ciphers [2]*tasmanCipher
	for d := range 2 {
		ciphers[d], err = newTasmanCipher([]byte("tasman-integration-public-password-32+"), byte(d))
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
		l := p.Layer(layers.LayerTypeUDP)
		if l == nil {
			continue
		}
		u := l.(*layers.UDP)
		d, ok := dirs[[2]int{int(u.SrcPort), int(u.DstPort)}]
		if !ok {
			continue
		}
		var scratch [1232]byte
		_, err = ciphers[d].open(u.Payload, &scratch)
		require.NoError(t, err)
		matched++
		largest = max(largest, len(u.Payload))
	}
	require.Positive(t, matched)
	t.Logf("TASMAN_PCAP_AUTHENTICATED=%d MAX_UDP_PAYLOAD=%d", matched, largest)
}
