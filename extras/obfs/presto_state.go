// SPDX-License-Identifier: MIT-0

package obfs

import (
	"container/list"
	"hash/maphash"
	"net/netip"
	"time"
)

// Reuse this project's MIT-0 source-prefix normalization, fixed token bucket,
// and 256-message replay-window primitives. No Blink wire format is reused.
const (
	prestoMaxSessions   = 1024
	prestoMaxAssemblies = 512
	prestoPerSession    = 32
	prestoPerSource     = 8
	prestoSessionTTL    = 2 * time.Minute
	prestoAssemblyTTL   = 3 * time.Second
)

type prestoPeer struct {
	session       [16]byte
	addr          netip.AddrPort
	source        netip.Prefix
	born          uint64
	used          time.Time
	window        blinkPeer
	elem          *list.Element
	assemblyOrder *list.List
}

type prestoAssemblyKey struct {
	session [16]byte
	id      uint64
}

type prestoAssembly struct {
	key            prestoAssemblyKey
	peer           *prestoPeer
	data           []byte
	count, mask    uint8
	starts, sizes  [4]uint16
	filled         int
	deadline       time.Time
	elem, peerElem *list.Element
}

func (c *prestoPacketConn) dropAssembly(a *prestoAssembly, abandon bool) {
	delete(c.assemblies, a.key)
	c.assemblyOrder.Remove(a.elem)
	a.peer.assemblyOrder.Remove(a.peerElem)
	c.assemblyBytes -= len(a.data)
	if abandon {
		a.peer.window.finish(a.key.id)
	}
}

func (c *prestoPacketConn) maintain(now time.Time, limit int) {
	for range limit {
		e := c.assemblyOrder.Front()
		if e == nil {
			break
		}
		a := e.Value.(*prestoAssembly)
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
		p := e.Value.(*prestoPeer)
		if now.Sub(p.used) < prestoSessionTTL || p.assemblyOrder.Len() != 0 {
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

func (c *prestoPacketConn) verifyBudget(source netip.Prefix, now time.Time) bool {
	if !c.verify.allow(now, 32768, 4096) {
		return false
	}
	i := maphash.Comparable(c.hashSeed, source) % uint64(len(c.verifyShards))
	return c.verifyShards[i].allow(now, 8192, 2048)
}

func (c *prestoPacketConn) accept(addr netip.AddrPort, source netip.Prefix, h prestoHeaderFields, payload []byte, now time.Time) ([]byte, bool) {
	c.maintain(now, 8)
	if h.kind == prestoCover && c.opts.Server {
		c.stats.MalformedDrops++
		return nil, false
	}
	p := c.peers[h.session]
	if p != nil && (p.addr != addr || p.born != h.born || now.Sub(p.used) >= prestoSessionTTL) {
		c.stats.ReplayDrops++
		return nil, false
	}
	if p == nil {
		// Freshness is only for new sessions. Established sessions can live
		// longer; idle senders rotate before receivers expire them. The old
		// timestamp cannot reopen a session after its replay window expires.
		unix := now.Unix()
		if unix < 30 || h.born < uint64(unix-30) || h.born > uint64(unix+30) {
			c.stats.FreshnessDrops++
			return nil, false
		}
		if len(c.peers) >= prestoMaxSessions || c.sources[source] >= prestoPerSource || !c.admit.allow(now, 64, 128) {
			c.stats.ResourceDrops++
			return nil, false
		}
		p = &prestoPeer{session: h.session, addr: addr, source: source, born: h.born, used: now, assemblyOrder: list.New()}
		p.elem = c.peerOrder.PushBack(p)
		c.peers[h.session] = p
		c.sources[source]++
	}
	if p.window.replay(h.message) {
		c.stats.ReplayDrops++
		return nil, false
	}
	p.used = now
	c.peerOrder.MoveToBack(p.elem)
	ak := prestoAssemblyKey{session: h.session, id: h.message}
	if h.kind == prestoCover {
		if a := c.assemblies[ak]; a != nil {
			c.dropAssembly(a, true)
			c.stats.MalformedDrops++
			return nil, false
		}
		p.window.finish(h.message)
		c.stats.ReceivedCoverPackets++
		return nil, false
	}
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
		if p.assemblyOrder.Len() >= prestoPerSession {
			c.dropAssembly(p.assemblyOrder.Front().Value.(*prestoAssembly), true)
			c.stats.EvictedAssemblies++
		}
		if len(c.assemblies) >= prestoMaxAssemblies {
			c.stats.ResourceDrops++
			return nil, false
		}
		a = &prestoAssembly{key: ak, peer: p, data: make([]byte, h.total), count: h.count, deadline: now.Add(prestoAssemblyTTL)}
		a.elem = c.assemblyOrder.PushBack(a)
		a.peerElem = p.assemblyOrder.PushBack(a)
		c.assemblies[ak] = a
		c.assemblyBytes += len(a.data)
	} else if len(a.data) != int(h.total) || a.count != h.count {
		c.dropAssembly(a, true)
		c.stats.MalformedDrops++
		return nil, false
	}
	bit := uint8(1) << h.index
	if a.mask&bit != 0 {
		c.stats.ReplayDrops++
		return nil, false
	}
	start, end := int(h.offset), int(h.offset)+len(payload)
	for i := range a.count {
		if a.mask&(uint8(1)<<i) != 0 && start < int(a.starts[i])+int(a.sizes[i]) && end > int(a.starts[i]) {
			c.dropAssembly(a, true)
			c.stats.MalformedDrops++
			return nil, false
		}
	}
	copy(a.data[start:end], payload)
	a.starts[h.index], a.sizes[h.index] = h.offset, h.size
	a.filled += len(payload)
	a.mask |= bit
	if a.mask != (1<<a.count)-1 {
		return nil, false
	}
	if a.filled != len(a.data) {
		c.dropAssembly(a, true)
		c.stats.MalformedDrops++
		return nil, false
	}
	out := a.data
	c.dropAssembly(a, false)
	p.window.finish(h.message)
	c.setRoute(p)
	c.stats.Reassembled++
	return out, true
}

func (c *prestoPacketConn) setRoute(p *prestoPeer) {
	// A restarted client may reuse its UDP endpoint but has no receive state.
	// Reply with a freshly born server session, not an old (>30s) session the
	// new client cannot admit. Never reset the client's sender on server rotation.
	if c.opts.Server && c.routes[p.addr] != p {
		delete(c.senders, p.addr)
	}
	c.routes[p.addr] = p
}
