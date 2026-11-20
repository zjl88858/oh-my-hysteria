// SPDX-License-Identifier: MIT-0

package obfs

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// All events are within one real client session. Vary the order in which a
// previously sent data frame and a renewal arrive; no packet is lost on wire.
func TestNetFrontRenewalInFlight(t *testing.T) {
	now := time.Now()
	mainC, srcC, _ := blinkAddress(blinkClientAddr)
	mainS, srcS, _ := blinkAddress(blinkServerAddr)
	sideC := netip.AddrPortFrom(mainC.Addr(), 45111)
	sideS := netip.AddrPortFrom(mainS.Addr(), 45112)
	dests := []netip.AddrPort{sideS, netip.AddrPortFrom(mainS.Addr(), 45113)}
	o := NetFrontOptions{[]byte(netfrontTestKey), []int{45112, 45113}}
	client, _ := newPrestoTest(t, false)
	server, _ := newPrestoTest(t, true)
	cp, err := prestoStandard.compileNetfront(o, false)
	require.NoError(t, err)
	sp, err := prestoStandard.compileNetfront(o, true)
	require.NoError(t, err)
	c := netfrontWire{presto: client, primary: mainS, profile: cp, dests: dests}
	s := netfrontWire{presto: server, profile: sp}
	tx, err := client.sender(mainS, now)
	require.NoError(t, err)
	h := prestoHeaderFields{session: tx.session, born: tx.born, total: 1, size: 1, count: 1}
	_, ok := server.accept(mainC, srcC, h, []byte{1}, now)
	require.True(t, ok)
	h.session = [16]byte{7}
	_, ok = client.accept(mainS, srcS, h, []byte{2}, now)
	require.True(t, ok)
	cs := c.session(mainS, now)
	cs.lanes[1].probeAt = now.Add(time.Hour) // only lane 1 is eligible
	probe := func(at time.Time) netfrontFrame {
		for range 4 {
			cs.credit(1000)
		}
		a := cs.choose(&c.profile, dests, 100, at)
		require.Equal(t, 1, a.lane)
		require.Equal(t, nfProbe, a.frame.kind)
		return a.frame
	}
	offer := func(f netfrontFrame, addr netip.AddrPort, at time.Time) netfrontFrame {
		_, reply, ok := s.acceptSide(f, addr, 1, 106, at)
		require.True(t, ok)
		return reply.frame
	}
	activate := func(f netfrontFrame, at time.Time) netfrontFrame {
		_, _, ok := c.acceptSide(f, sideS, 1, 106, at)
		require.True(t, ok)
		f.kind = nfData
		dest, _, ok := s.acceptSide(f, sideC, 1, 240, at)
		require.True(t, ok)
		require.Equal(t, mainC, dest)
		return f
	}
	old := activate(offer(probe(now), sideC, now), now)
	later := now.Add(14 * time.Second)
	newProbe := probe(later)
	check := func(label string, w *netfrontWire, addr, logical netip.AddrPort, lane int, f netfrontFrame, at time.Time, want bool) {
		dest, reply, accepted := w.acceptSide(f, addr, lane, 240, at)
		require.Equal(t, want, accepted, label)
		require.Zero(t, reply.wire, label)
		if want {
			require.Equal(t, logical, dest, label)
		}
	}
	check("downlink crossed client renewal", &c, sideS, mainS, 1, old, later, true)
	newOffer := offer(newProbe, sideC, later)
	check("uplink crossed server renewal", &s, sideC, mainC, 1, old, later, true)
	require.False(t, s.session(mainC, later).lanes[0].verified, "old data must not prove the new challenge")
	fresh := activate(newOffer, later)
	check("previous in flight after new proof", &s, sideC, mainC, 1, old, later.Add(time.Millisecond), true)
	check("previous in flight after new offer", &c, sideS, mainS, 1, old, later.Add(time.Millisecond), true)
	check("wrong physical source", &s, netip.AddrPortFrom(sideC.Addr(), 2222), mainC, 1, old, later, false)
	check("wrong lane", &s, sideC, mainC, 2, old, later, false)
	bad := old
	bad.token[0] ^= 1
	check("wrong token", &s, sideC, mainC, 1, bad, later, false)
	check("receive grace is not extended by traffic", &s, sideC, mainC, 1, old, later.Add(2*time.Second), false)
	check("expired prior proof", &s, sideC, mainC, 1, old, now.Add(netfrontLease), false)
	check("expired prior offer", &c, sideS, mainS, 1, old, now.Add(netfrontLease), false)
	// A changed NAT mapping must immediately revoke use of the former address.
	newProbe.seq++
	offer(newProbe, netip.AddrPortFrom(sideC.Addr(), 2222), later.Add(time.Second))
	check("rebind revokes immediately preceding proof", &s, sideC, mainC, 1, fresh, later.Add(time.Second), false)
	check("rebind also revokes older proof", &s, sideC, mainC, 1, old, later.Add(time.Second), false)
}
