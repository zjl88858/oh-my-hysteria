// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"container/list"
	"errors"
	"hash/maphash"
	"io"
	"net/netip"
	"time"
)

const (
	servoWindowSize       = 131072
	servoMaxSessions      = 1024
	servoPerSource        = 32
	servoSessionSlots     = 2048 // active + tombstones; reserve retirement capacity
	servoSessionTTL       = 2 * time.Minute
	servoAssemblyTTL      = 3 * time.Second
	servoPerSession       = 128
	servoMaxAssemblies    = 2048
	servoMaxAssemblyBytes = 2457600
	servoQueueItems       = 1024
	servoQueueBytes       = 1 << 20
	servoPeerQueueItems   = 64
	servoPeerQueueBytes   = 64 << 10
)

var (
	errServoReplay   = errors.New("servo: replay or displaced window")
	errServoConflict = errors.New("servo: conflicting fragments")
	errServoResource = errors.New("servo: receive resource limit")
	errServoRate     = errors.New("servo: receive rate limit")
	errServoFresh    = errors.New("servo: stale or inconsistent session")
	errServoEmpty    = errors.New("servo: no completed datagram")
)

// Circular bitset: old IDs stay rejected even after their bit is overwritten.
// No O(window-size) shifting per normal packet. Separate instances MUST be
// used for packets and completed/abandoned messages.
type servoWindow struct {
	high    uint64
	hasHigh bool
	bits    [servoWindowSize / 64]uint64
}

func (w *servoWindow) seen(id uint64) bool {
	if !w.hasHigh || id > w.high {
		return false
	}
	if w.high-id >= servoWindowSize {
		return true
	}
	i := id % servoWindowSize
	return w.bits[i/64]&(uint64(1)<<(i%64)) != 0
}

func (w *servoWindow) mark(id uint64) {
	if w.hasHigh && id > w.high {
		delta := id - w.high
		if delta >= servoWindowSize {
			clear(w.bits[:])
		} else {
			start := w.high + 1
			for delta > 0 {
				i := start % servoWindowSize
				n := min(delta, 64-i%64)
				mask := (^uint64(0) >> (64 - n)) << (i % 64)
				w.bits[i/64] &^= mask
				start += n
				delta -= n
			}
		}
	}
	if !w.hasHigh || id > w.high {
		w.high, w.hasHigh = id, true
	}
	if w.high-id < servoWindowSize {
		i := id % servoWindowSize
		w.bits[i/64] |= uint64(1) << (i % 64)
	}
}

type servoPeer struct {
	session         [16]byte
	addr            netip.AddrPort
	source          netip.Prefix
	born            uint64
	used            time.Time
	packets, done   servoWindow
	verify, records blinkBucket
	assemblies      map[uint32]*servoAssembly
	order           *list.List
	elem            *list.Element
	routeReady      bool // only a complete authenticated inner datagram sets this
}

type servoAssembly struct {
	peer           *servoPeer
	message        uint32
	data           []byte
	starts, sizes  [2]int
	count, filled  int
	deadline       time.Time
	elem, peerElem *list.Element
}

type servoTombstone struct {
	session [16]byte
	until   time.Time
}

type servoCompleted struct {
	session [16]byte
	addr    netip.AddrPort
	data    []byte
}

type servoQueueUsage struct{ items, bytes int }

type servoReceiveStats struct {
	OuterPackets, OuterBytes, AuthDrops, MalformedDrops, RateDrops uint64
	PacketReplayDrops, MessageReplayDrops, ConflictDrops           uint64
	FreshnessDrops, ResourceDrops, DuplicateFragments              uint64
	ExpiredAssemblies, EvictedAssemblies, Completed, QueueDrops    uint64
	DeliveredBytes, ShortBufferDrops                               uint64
}

// Offline owner-serialized receive engine, not a PacketConn. Each direction
// owns its cipher, maps and windows. Never shares wire keys with another obfs.
type servoReceiver struct {
	cipher                    *servoCipher
	scratch                   [servoWireMax]byte
	peers                     map[[16]byte]*servoPeer
	sources                   map[netip.Prefix]int
	endpoints                 map[netip.AddrPort]int
	tombstones                map[[16]byte]*list.Element
	peerOrder, tombOrder      *list.List
	assemblyOrder, queue      *list.List
	queued                    map[[16]byte]servoQueueUsage
	assemblyBytes, queueBytes int
	verify, unknown, admit    blinkBucket
	unknownShards             [256]blinkBucket
	hashSeed                  maphash.Seed
	stats                     servoReceiveStats
	onComplete                func(*servoPeer) // owner callback, after a whole authenticated inner datagram
}

func newServoReceiver(password []byte, direction byte) (*servoReceiver, error) {
	cipher, err := newServoCipher(password, direction)
	if err != nil {
		return nil, err
	}
	r := newFramedReceiveState()
	r.cipher = cipher
	return r, nil
}

// Shared only after protocol-specific authentication and canonical parsing.
// There are no wire keys or protocol decoders in a new state-only instance.
func newFramedReceiveState() *servoReceiver {
	return &servoReceiver{
		peers: make(map[[16]byte]*servoPeer), sources: make(map[netip.Prefix]int),
		endpoints: make(map[netip.AddrPort]int), tombstones: make(map[[16]byte]*list.Element),
		peerOrder: list.New(), tombOrder: list.New(), assemblyOrder: list.New(), queue: list.New(),
		queued: make(map[[16]byte]servoQueueUsage), hashSeed: maphash.MakeSeed(),
	}
}

func servoEndpoint(addr netip.AddrPort) (netip.AddrPort, netip.Prefix, bool) {
	ip := addr.Addr().Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || addr.Port() == 0 {
		return netip.AddrPort{}, netip.Prefix{}, false
	}
	bits := 128
	if ip.Is4() {
		bits = 32
	} else {
		bits = 64
	}
	return netip.AddrPortFrom(ip, addr.Port()), netip.PrefixFrom(ip.WithZone(""), bits).Masked(), true
}

func (r *servoReceiver) dropAssembly(a *servoAssembly, abandon bool) {
	delete(a.peer.assemblies, a.message)
	a.peer.order.Remove(a.peerElem)
	r.assemblyOrder.Remove(a.elem)
	r.assemblyBytes -= len(a.data)
	if abandon {
		a.peer.done.mark(uint64(a.message))
	}
}

func (r *servoReceiver) retire(p *servoPeer, now time.Time) {
	for p.order.Len() > 0 {
		r.dropAssembly(p.order.Front().Value.(*servoAssembly), false)
	}
	delete(r.peers, p.session)
	r.peerOrder.Remove(p.elem)
	r.sources[p.source]--
	if r.sources[p.source] == 0 {
		delete(r.sources, p.source)
	}
	r.endpoints[p.addr]--
	if r.endpoints[p.addr] == 0 {
		delete(r.endpoints, p.addr)
	}
	until := now.Add(servoAssemblyTTL)
	if freshUntil := time.Unix(int64(p.born), 0).Add(31 * time.Second); freshUntil.After(until) {
		until = freshUntil
	}
	t := servoTombstone{session: p.session, until: until}
	r.tombstones[p.session] = r.tombOrder.PushBack(t)
}

func (r *servoReceiver) maintain(now time.Time) {
	// Bounded work, even for adversarial authenticated arrivals. Tombstone
	// expirations aren't ordered by insertion (born can be in the future).
	for range min(32, r.tombOrder.Len()) {
		e := r.tombOrder.Front()
		t := e.Value.(servoTombstone)
		if !now.Before(t.until) {
			delete(r.tombstones, t.session)
			r.tombOrder.Remove(e)
		} else {
			r.tombOrder.MoveToBack(e)
		}
	}
	for range 32 {
		e := r.assemblyOrder.Front()
		if e == nil || now.Before(e.Value.(*servoAssembly).deadline) {
			break
		}
		r.dropAssembly(e.Value.(*servoAssembly), true)
		r.stats.ExpiredAssemblies++
	}
	for range 32 {
		e := r.peerOrder.Front()
		if e == nil || now.Sub(e.Value.(*servoPeer).used) < servoSessionTTL {
			break
		}
		r.retire(e.Value.(*servoPeer), now)
	}
}

// Errors are local diagnostics only. A future wrapper MUST silently drop
// malformed/unauthenticated traffic and never send these strings to a peer.
func (r *servoReceiver) receive(wire []byte, addr netip.AddrPort, now time.Time) error {
	r.stats.OuterPackets++
	r.stats.OuterBytes += uint64(len(wire))
	addr, source, ok := servoEndpoint(addr)
	if !ok || len(wire) < servoWireMin || len(wire) > servoWireMax {
		r.stats.MalformedDrops++
		return errServoFrame
	}
	r.maintain(now)
	if !r.verify.allow(now, 131072, 8192) {
		r.stats.RateDrops++
		return errServoRate
	}
	if r.endpoints[addr] == 0 {
		i := maphash.Comparable(r.hashSeed, source) % uint64(len(r.unknownShards))
		if !r.unknown.allow(now, 16384, 2048) || !r.unknownShards[i].allow(now, 4096, 512) {
			r.stats.RateDrops++
			return errServoRate
		}
	}
	f, err := r.cipher.open(wire, &r.scratch)
	if err != nil {
		if errors.Is(err, errServoAuth) {
			r.stats.AuthDrops++
		} else {
			r.stats.MalformedDrops++
		}
		return err
	}
	return r.acceptAuthenticated(f, addr, now)
}

func (r *servoReceiver) acceptAuthenticated(f servoFrame, addr netip.AddrPort, now time.Time) error {
	addr, source, ok := servoEndpoint(addr)
	if !ok {
		return errServoFrame
	}
	p := r.peers[f.session]
	if p != nil && now.Sub(p.used) >= servoSessionTTL {
		r.retire(p, now)
		p = nil
	}
	if p == nil {
		unix := now.Unix()
		if unix < 30 || int64(f.born)-unix < -30 || int64(f.born)-unix > 30 {
			r.stats.FreshnessDrops++
			return errServoFresh
		}
		if r.tombstones[f.session] != nil {
			r.stats.PacketReplayDrops++
			return errServoReplay
		}
		if len(r.peers) >= servoMaxSessions || len(r.peers)+len(r.tombstones) >= servoSessionSlots || r.sources[source] >= servoPerSource {
			r.stats.ResourceDrops++
			return errServoResource
		}
	} else {
		if p.born != f.born || p.addr != addr {
			r.stats.FreshnessDrops++
			return errServoFresh
		}
		if p.packets.seen(f.counter) {
			r.stats.PacketReplayDrops++
			return errServoReplay
		}
		// Transaction preflight: no record can be delivered before discovering
		// a conflict in a later record of this same authenticated container.
		for i := range f.count {
			record := &f.records[i]
			if p.done.seen(uint64(record.message)) {
				continue
			}
			a := p.assemblies[record.message]
			if a != nil && now.Before(a.deadline) && servoFragmentConflict(a, record) {
				r.stats.ConflictDrops++
				return errServoConflict
			}
		}
	}
	if p == nil {
		if !r.admit.allow(now, 128, 256) {
			r.stats.RateDrops++
			return errServoRate
		}
		p = &servoPeer{
			session: f.session, addr: addr, source: source, born: f.born, used: now,
			assemblies: make(map[uint32]*servoAssembly), order: list.New(),
		}
		p.elem = r.peerOrder.PushBack(p)
		r.peers[f.session] = p
		r.sources[source]++
		r.endpoints[addr]++
	}
	if !p.verify.allow(now, 32768, 4096) {
		r.stats.RateDrops++
		return errServoRate
	}
	for range f.count {
		if !p.records.allow(now, 16384, 4096) {
			r.stats.RateDrops++
			return errServoRate
		}
	}
	p.packets.mark(f.counter)
	p.used = now
	r.peerOrder.MoveToBack(p.elem)
	for i := range f.count {
		r.commitRecord(p, &f.records[i], now)
	}
	return nil
}

func servoFragmentConflict(a *servoAssembly, r *servoRecord) bool {
	if len(a.data) != int(r.total) {
		return true
	}
	start, end := int(r.offset), int(r.offset)+len(r.data)
	for i := range a.count {
		x, y := a.starts[i], a.starts[i]+a.sizes[i]
		if start == x && end == y {
			return !bytes.Equal(a.data[x:y], r.data)
		}
		if start < y && end > x {
			return true
		}
	}
	return a.count >= 2
}

func (r *servoReceiver) commitRecord(p *servoPeer, record *servoRecord, now time.Time) {
	if p.done.seen(uint64(record.message)) {
		r.stats.MessageReplayDrops++
		return
	}
	a := p.assemblies[record.message]
	if a != nil && !now.Before(a.deadline) {
		r.dropAssembly(a, true)
		r.stats.ExpiredAssemblies++
		return
	}
	if a != nil {
		for i := range a.count {
			if a.starts[i] == int(record.offset) && a.sizes[i] == len(record.data) {
				r.stats.DuplicateFragments++
				return // equality was checked in whole-container preflight
			}
		}
	}
	if a == nil && record.offset == 0 && len(record.data) == int(record.total) {
		r.complete(p, record.message, bytes.Clone(record.data))
		return
	}
	if a == nil {
		if len(p.assemblies) >= servoPerSession {
			r.dropAssembly(p.order.Front().Value.(*servoAssembly), true)
			r.stats.EvictedAssemblies++
		}
		if r.assemblyOrder.Len() >= servoMaxAssemblies || r.assemblyBytes+int(record.total) > servoMaxAssemblyBytes {
			r.stats.ResourceDrops++
			return
		}
		a = &servoAssembly{peer: p, message: record.message, data: make([]byte, record.total), deadline: now.Add(servoAssemblyTTL)}
		a.elem = r.assemblyOrder.PushBack(a)
		a.peerElem = p.order.PushBack(a)
		p.assemblies[record.message] = a
		r.assemblyBytes += len(a.data)
	}
	start := int(record.offset)
	copy(a.data[start:], record.data)
	a.starts[a.count], a.sizes[a.count] = start, len(record.data)
	a.count++
	a.filled += len(record.data)
	if a.filled == len(a.data) {
		r.dropAssembly(a, false)
		r.complete(p, record.message, a.data)
	}
}

func (r *servoReceiver) complete(p *servoPeer, message uint32, data []byte) {
	p.done.mark(uint64(message))
	p.routeReady = true
	if r.onComplete != nil {
		r.onComplete(p)
	}
	r.stats.Completed++
	q := r.queued[p.session]
	if r.queue.Len() >= servoQueueItems || r.queueBytes+len(data) > servoQueueBytes || q.items >= servoPeerQueueItems || q.bytes+len(data) > servoPeerQueueBytes {
		r.stats.QueueDrops++
		return
	}
	r.queue.PushBack(servoCompleted{session: p.session, addr: p.addr, data: data})
	r.queueBytes += len(data)
	q.items++
	q.bytes += len(data)
	r.queued[p.session] = q
}

// A too-small buffer consumes the entire datagram, never truncated ciphertext.
func (r *servoReceiver) pop(out []byte) (int, netip.AddrPort, error) {
	e := r.queue.Front()
	if e == nil {
		return 0, netip.AddrPort{}, errServoEmpty
	}
	d := e.Value.(servoCompleted)
	r.queue.Remove(e)
	r.queueBytes -= len(d.data)
	q := r.queued[d.session]
	q.items--
	q.bytes -= len(d.data)
	if q.items == 0 {
		delete(r.queued, d.session)
	} else {
		r.queued[d.session] = q
	}
	if len(out) < len(d.data) {
		r.stats.ShortBufferDrops++
		return 0, d.addr, io.ErrShortBuffer
	}
	n := copy(out, d.data)
	r.stats.DeliveredBytes += uint64(n)
	return n, d.addr, nil
}
