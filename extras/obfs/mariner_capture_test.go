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

func marinerAuditCapture(t *testing.T) {
	path, metadata := os.Getenv("OMHY_MARINER_PCAP"), os.Getenv("OMHY_MARINER_WIRE_AUDIT")
	if path == "" || metadata == "" {
		t.Skip("owned namespace pcap only")
	}
	dirs := map[[2]int]byte{}
	files, e := filepath.Glob(filepath.Join(metadata, "*.json"))
	require.NoError(t, e)
	require.NotEmpty(t, files)
	for _, file := range files {
		var m struct{ Server, Client string }
		data, e := os.ReadFile(file)
		require.NoError(t, e)
		require.NoError(t, json.Unmarshal(data, &m))
		_, sp, e := net.SplitHostPort(m.Server)
		require.NoError(t, e)
		_, cp, e := net.SplitHostPort(m.Client)
		require.NoError(t, e)
		s, e := strconv.Atoi(sp)
		require.NoError(t, e)
		c, e := strconv.Atoi(cp)
		require.NoError(t, e)
		dirs[[2]int{c, s}], dirs[[2]int{s, c}] = 0, 1
	}
	f, e := os.Open(path)
	require.NoError(t, e)
	defer f.Close()
	r, e := pcapgo.NewReader(f)
	require.NoError(t, e)
	var receivers [2]*marinerReceiver
	for dir := range 2 {
		receivers[dir], e = newMarinerReceiver([]byte("mariner-integration-public-password-32+"), byte(dir))
		require.NoError(t, e)
	}
	matched, largest := 0, 0
	for {
		data, _, e := r.ReadPacketData()
		if e == io.EOF {
			break
		}
		require.NoError(t, e)
		p := gopacket.NewPacket(data, r.LinkType(), gopacket.NoCopy)
		l := p.Layer(layers.LayerTypeUDP)
		if l == nil {
			continue
		}
		u := l.(*layers.UDP)
		dir, ok := dirs[[2]int{int(u.SrcPort), int(u.DstPort)}]
		if !ok {
			continue
		}
		rx := receivers[dir]
		var g marinerGraph
		require.NoError(t, rx.profile.graph(len(u.Payload), &g))
		raw, e := rx.profile.decode(rx.raw[:], u.Payload, &g)
		require.NoError(t, e)
		_, e = rx.cipher.open(rx.plain[:], raw, &rx.profile, len(u.Payload))
		require.NoError(t, e)
		matched++
		largest = max(largest, len(u.Payload))
	}
	require.Positive(t, matched)
	t.Logf("MARINER_PCAP_AUTHENTICATED=%d MAX_UDP_PAYLOAD=%d", matched, largest)
}
