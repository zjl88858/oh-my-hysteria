// SPDX-License-Identifier: MIT-0

package obfs

import (
	"container/list"
	"hash/maphash"
	"net"
	"net/netip"
	"time"
)

const (
	blinkSessionTTL    = 2 * time.Minute
	blinkAssemblyTTL   = 3 * time.Second
	blinkPerSource     = 8
	blinkPerSession    = 32
	blinkMaxAssemblies = 512
)

// A fixed table avoids allocating attacker-controlled rate-limiter keys.
// IPv4 uses an IP, IPv6 a /64 (not a changing source port).
func blinkAddress(addr net.Addr) (netip.AddrPort, netip.Prefix, bool) {
	u, ok := addr.(*net.UDPAddr)
	if !ok || u.Port < 1 || u.Port > 65535 {
		return netip.AddrPort{}, netip.Prefix{}, false
	}
	ap := u.AddrPort()
	ip := ap.Addr().Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.AddrPort{}, netip.Prefix{}, false
	}
	bits := 128
	if ip.Is4() {
		bits = 32
	} else {
		bits = 64
	}
	// Scope IDs remain part of endpoint identity, not of source quota keys.
	return netip.AddrPortFrom(ip, ap.Port()), netip.PrefixFrom(ip.WithZone(""), bits).Masked(), true
}

type blinkBucket struct {
	tokens float64
	at     time.Time
}

func (b *blinkBucket) allow(now time.Time, rate, burst int) bool {
	if b.at.IsZero() {
		b.tokens = float64(burst)
		b.at = now
	}
	if now.After(b.at) {
		b.tokens = min(float64(burst), b.tokens+now.Sub(b.at).Seconds()*float64(rate))
		b.at = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type (
	blinkPeerKey struct {
		addr    netip.AddrPort
		session [16]byte
	}
	blinkPeer struct {
		key    blinkPeerKey
		source netip.Prefix
		used   time.Time
		elem   *list.Element
		// A fixed 256-message completed/abandoned replay window. Unfinished
		// messages live in the separately bounded assembly map, never a slice
		// indexed by an untrusted sequence number.
		high          uint64
		seen          [4]uint64
		hasHigh       bool
		active        int
		assemblyOrder *list.List
	}
)

func (p *blinkPeer) replay(id uint64) bool {
	if !p.hasHigh || id > p.high {
		return false
	}
	d := p.high - id
	return d >= 256 || p.seen[d/64]&(uint64(1)<<(d%64)) != 0
}

func (p *blinkPeer) finish(id uint64) {
	if !p.hasHigh {
		p.high = id
		p.hasHigh = true
	}
	if id > p.high {
		d := id - p.high
		if d >= 256 {
			clear(p.seen[:])
		} else {
			var next [4]uint64
			words, bits := int(d/64), d%64
			for i := 3; i >= words; i-- {
				next[i] = p.seen[i-words] << bits
				if bits > 0 && i > words {
					next[i] |= p.seen[i-words-1] >> (64 - bits)
				}
			}
			p.seen = next
		}
		p.high = id
	}
	if d := p.high - id; d < 256 {
		p.seen[d/64] |= uint64(1) << (d % 64)
	}
}

type (
	blinkAssemblyKey struct {
		peer blinkPeerKey
		id   uint64
	}
	blinkAssembly struct {
		key         blinkAssemblyKey
		peer        *blinkPeer
		data        []byte
		total       uint16
		count, mask uint8
		deadline    time.Time
		elem        *list.Element
		peerElem    *list.Element
	}
)

func (c *blinkPacketConn) dropAssembly(a *blinkAssembly, abandon bool) {
	delete(c.assemblies, a.key)
	c.assemblyOrder.Remove(a.elem)
	a.peer.assemblyOrder.Remove(a.peerElem)
	c.assemblyBytes -= len(a.data)
	a.peer.active--
	if abandon {
		a.peer.finish(a.key.id)
	}
}

func (c *blinkPacketConn) maintain(now time.Time, limit int) {
	for i := 0; i < limit; i++ {
		e := c.assemblyOrder.Front()
		if e == nil {
			break
		}
		a := e.Value.(*blinkAssembly)
		if now.Before(a.deadline) {
			break
		}
		c.dropAssembly(a, true)
		c.stats.ExpiredAssemblies++
	}
	for i := 0; i < limit; i++ {
		e := c.peerOrder.Front()
		if e == nil {
			break
		}
		p := e.Value.(*blinkPeer)
		if now.Sub(p.used) < blinkSessionTTL || p.active > 0 {
			break
		}
		delete(c.peers, p.key)
		c.peerOrder.Remove(e)
		c.sources[p.source]--
		if c.sources[p.source] == 0 {
			delete(c.sources, p.source)
		}
		if c.routes[p.key.addr] == p {
			delete(c.routes, p.key.addr)
			delete(c.senders, p.key.addr)
		}
	}
}

// No allocation or session lookup before size/rate/AEAD/header validation.
// The limiter is shared by valid and invalid traffic: overload can drop valid
// traffic too; it is not a magic way to classify unauthenticated senders.
func (c *blinkPacketConn) verifyBudget(source netip.Prefix, now time.Time) bool {
	if !c.verify.allow(now, c.opts.VerifyPacketsPerSecond, 4096) {
		return false
	}
	i := maphash.Comparable(c.hashSeed, source) % uint64(len(c.verifyShards))
	return c.verifyShards[i].allow(now, max(1, c.opts.VerifyPacketsPerSecond/4), 2048)
}

func (c *blinkPacketConn) accept(addr netip.AddrPort, source netip.Prefix, h blinkHeaderFields, payload []byte, now time.Time) ([]byte, bool) {
	c.maintain(now, 8)
	if h.count > 1 && !c.opts.Fragmentation {
		c.stats.ResourceDrops++
		return nil, false
	}
	key := blinkPeerKey{addr: addr, session: h.session}
	p := c.peers[key]
	if p != nil && now.Sub(p.used) >= blinkSessionTTL {
		c.stats.ResourceDrops++
		return nil, false
	}
	if p == nil {
		if len(c.peers) >= c.opts.MaxSessions || c.sources[source] >= blinkPerSource || !c.admit.allow(now, 64, 128) {
			c.stats.ResourceDrops++
			return nil, false
		}
		p = &blinkPeer{key: key, source: source, used: now, assemblyOrder: list.New()}
		p.elem = c.peerOrder.PushBack(p)
		c.peers[key] = p
		c.sources[source]++
	}
	if p.replay(h.message) {
		c.stats.ReplayDrops++
		return nil, false
	}
	p.used = now
	c.peerOrder.MoveToBack(p.elem)
	ak := blinkAssemblyKey{peer: key, id: h.message}
	if h.count == 1 {
		if a := c.assemblies[ak]; a != nil {
			c.dropAssembly(a, true)
			c.stats.MalformedDrops++
			return nil, false
		}
		p.finish(h.message)
		c.routes[addr] = p
		return payload, true
	}
	a := c.assemblies[ak]
	if a != nil && !now.Before(a.deadline) {
		c.dropAssembly(a, true)
		c.stats.ExpiredAssemblies++
		return nil, false
	}
	if a == nil {
		// Loss must not pin every slot for the entire TTL. Reclaim only
		// this authenticated session's oldest partial message, in O(1).
		// Other sessions cannot have their assemblies evicted by this peer.
		if p.active >= blinkPerSession {
			c.dropAssembly(p.assemblyOrder.Front().Value.(*blinkAssembly), true)
			c.stats.EvictedAssemblies++
		}
		if len(c.assemblies) >= blinkMaxAssemblies || c.assemblyBytes+int(h.total) > c.opts.MaxReassemblyBytes {
			c.stats.ResourceDrops++
			return nil, false
		}
		a = &blinkAssembly{key: ak, peer: p, total: h.total, count: h.count, data: make([]byte, h.total), deadline: now.Add(blinkAssemblyTTL)}
		a.elem = c.assemblyOrder.PushBack(a)
		a.peerElem = p.assemblyOrder.PushBack(a)
		c.assemblies[ak] = a
		p.active++
		c.assemblyBytes += len(a.data)
	} else if a.count != h.count || a.total != h.total {
		c.dropAssembly(a, true)
		c.stats.MalformedDrops++
		return nil, false
	}
	bit := uint8(1) << h.index
	if a.mask&bit != 0 {
		c.stats.ReplayDrops++
		return nil, false
	}
	span := (int(h.total) + int(h.count) - 1) / int(h.count)
	copy(a.data[int(h.index)*span:], payload)
	a.mask |= bit
	if a.mask != (1<<h.count)-1 {
		return nil, false
	}
	out := a.data
	c.dropAssembly(a, false)
	p.finish(h.message)
	c.routes[addr] = p
	c.stats.Reassembled++
	return out, true
}
