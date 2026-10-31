// SPDX-License-Identifier: MIT-0

package obfs

import (
	"container/list"
	"hash/maphash"
	"math/bits"
	"net/netip"
	"time"
)

// Adapted from the project's MIT-0 Trident receiver, independent state with
// 32-fragment masks. Address, token-bucket and 256-message replay primitives
// are shared, not either protocol's keys, tables or wire decoder.
const (
	carakanMaxSessions   = 1024
	carakanMaxAssemblies = 512
	carakanPerSession    = 32
	carakanPerSource     = 8
	carakanSessionTTL    = 2 * time.Minute
	carakanAssemblyTTL   = 3 * time.Second
)

type carakanPeer struct {
	session       [16]byte
	addr          netip.AddrPort
	source        netip.Prefix
	born          uint64
	used          time.Time
	window        blinkPeer
	elem          *list.Element
	assemblyOrder *list.List
}

type (
	carakanAssemblyKey struct {
		session [16]byte
		id      uint64
	}
	carakanAssembly struct {
		key            carakanAssemblyKey
		peer           *carakanPeer
		data           []byte
		parity         []byte
		count          uint8
		width          uint16
		mask           uint32
		deadline       time.Time
		elem, peerElem *list.Element
	}
)

func (c *carakanPacketConn) dropAssembly(a *carakanAssembly, abandon bool) {
	delete(c.assemblies, a.key)
	c.assemblyOrder.Remove(a.elem)
	a.peer.assemblyOrder.Remove(a.peerElem)
	c.assemblyBytes -= len(a.data) + len(a.parity)
	if abandon {
		a.peer.window.finish(a.key.id)
	}
}

func (c *carakanPacketConn) maintain(now time.Time, limit int) {
	for range limit {
		e := c.assemblyOrder.Front()
		if e == nil {
			break
		}
		a := e.Value.(*carakanAssembly)
		if now.Before(a.deadline) {
			break
		}
		c.dropAssembly(a, true)
		c.stats.ExpiredAssemblies++
	}
	for range limit {
		e := c.peerOrder.Front()
		if e == nil {
			break
		}
		p := e.Value.(*carakanPeer)
		if now.Sub(p.used) < carakanSessionTTL || p.assemblyOrder.Len() != 0 {
			break
		}
		delete(c.peers, p.session)
		c.peerOrder.Remove(e)
		c.sources[p.source]--
		if c.sources[p.source] == 0 {
			delete(c.sources, p.source)
		}
		if c.routes[p.addr] == p {
			delete(c.routes, p.addr)
			delete(c.senders, p.addr)
		}
	}
}

func (c *carakanPacketConn) verifyBudget(source netip.Prefix, now time.Time) bool {
	// Decoding and canonical re-encoding are linear in at most 1232 symbols.
	if !c.verify.allow(now, 16384, 2048) {
		return false
	}
	i := maphash.Comparable(c.hashSeed, source) % uint64(len(c.verifyShards))
	return c.verifyShards[i].allow(now, 4096, 1024)
}

// Only entered after canonical decoding, direction AEAD and header validation.
func (c *carakanPacketConn) accept(addr netip.AddrPort, source netip.Prefix, h carakanHeaderFields, payload []byte, now time.Time) ([]byte, bool) {
	c.maintain(now, 8)
	if !h.valid(c.table.partMax) || len(payload) != int(h.size) {
		c.stats.MalformedDrops++
		return nil, false
	}
	if h.index >= h.count {
		c.stats.ReceivedRepairPackets++
	}
	p := c.peers[h.session]
	if p != nil && (p.addr != addr || p.born != h.born || now.Sub(p.used) >= carakanSessionTTL) {
		c.stats.ReplayDrops++
		return nil, false
	}
	if p == nil {
		unix := now.Unix()
		if unix < 30 || h.born < uint64(unix-30) || h.born > uint64(unix+30) {
			c.stats.FreshnessDrops++
			return nil, false
		}
		if len(c.peers) >= carakanMaxSessions || c.sources[source] >= carakanPerSource || !c.admit.allow(now, 64, 128) {
			c.stats.ResourceDrops++
			return nil, false
		}
		p = &carakanPeer{session: h.session, addr: addr, source: source, born: h.born, used: now, assemblyOrder: list.New()}
		p.elem = c.peerOrder.PushBack(p)
		c.peers[h.session] = p
		c.sources[source]++
	}
	if p.window.replay(h.message) {
		if h.index >= h.count {
			c.stats.RedundantRepairPackets++
		} else {
			c.stats.ReplayDrops++
		}
		return nil, false
	}
	p.used = now
	c.peerOrder.MoveToBack(p.elem)
	ak := carakanAssemblyKey{session: h.session, id: h.message}
	if h.count == 1 {
		if a := c.assemblies[ak]; a != nil {
			c.dropAssembly(a, true)
			c.stats.MalformedDrops++
			return nil, false
		}
		p.window.finish(h.message)
		c.setRoute(p)
		return payload, true
	}
	a := c.assemblies[ak]
	if a != nil && !now.Before(a.deadline) {
		c.dropAssembly(a, true)
		c.stats.ExpiredAssemblies++
		return nil, false
	}
	if a == nil {
		if p.assemblyOrder.Len() >= carakanPerSession {
			c.dropAssembly(p.assemblyOrder.Front().Value.(*carakanAssembly), true)
			c.stats.EvictedAssemblies++
		}
		paritySize := carakanRepairCount(int(h.count)) * int(h.width)
		allocated := int(h.total) + paritySize
		if len(c.assemblies) >= carakanMaxAssemblies || c.assemblyBytes+allocated > carakanReassemblyBudget {
			c.stats.ResourceDrops++
			return nil, false
		}
		storage := make([]byte, allocated)
		a = &carakanAssembly{key: ak, peer: p, data: storage[:h.total], parity: storage[h.total:], count: h.count, width: h.width, deadline: now.Add(carakanAssemblyTTL)}
		a.elem = c.assemblyOrder.PushBack(a)
		a.peerElem = p.assemblyOrder.PushBack(a)
		c.assemblies[ak] = a
		c.assemblyBytes += allocated
	} else if len(a.data) != int(h.total) || a.count != h.count || a.width != h.width {
		c.dropAssembly(a, true)
		c.stats.MalformedDrops++
		return nil, false
	}
	bit := uint32(1) << h.index
	if a.mask&bit != 0 {
		c.stats.ReplayDrops++
		return nil, false
	}
	if h.index < h.count {
		copy(a.data[int(h.index)*int(h.width):], payload)
	} else {
		copy(a.parity[int(h.index-h.count)*int(h.width):], payload)
	}
	a.mask |= bit
	if bits.OnesCount32(a.mask) < int(a.count) {
		return nil, false
	}
	recovered, ok := a.recover()
	if !ok {
		c.dropAssembly(a, true)
		c.stats.MalformedDrops++
		c.stats.FECRecoveryFailures++
		return nil, false
	}
	if recovered > 0 {
		c.stats.FECRecoveredMessages++
		c.stats.FECRecoveredShards += uint64(recovered)
	}
	out := a.data
	c.dropAssembly(a, false)
	p.window.finish(h.message)
	c.setRoute(p)
	c.stats.Reassembled++
	return out, true
}

func (c *carakanPacketConn) setRoute(p *carakanPeer) {
	if c.server && c.routes[p.addr] != p {
		delete(c.senders, p.addr)
	}
	c.routes[p.addr] = p
}
