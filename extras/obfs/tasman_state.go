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
	tasmanGenerationTTL   = 3 * time.Second
	tasmanGenerationLimit = 4096
	tasmanPeerGenerations = 256
	tasmanSymbolBytes     = 32 << 20
)

type tasmanGeneration struct {
	id       uint32
	width, k int
	sources  [8][]byte
	repairs  [2][]byte
	deadline time.Time
	peer     *tasmanPeer
	elem     *list.Element
}
type tasmanAssembly struct {
	data     []byte
	ends     [1200]uint16 // bounded exact duplicate / overlap recognition, even 1B fragments
	filled   int
	deadline time.Time
	id       uint32
	peer     *tasmanPeer
	elem     *list.Element
}
type tasmanPeer struct {
	session             [16]byte
	addr                netip.AddrPort
	source              netip.Prefix
	born                uint64
	used                time.Time
	packets, done, gone servoWindow // pure replay bitset, no Servo wire state
	verify              blinkBucket
	generations         map[uint32]*tasmanGeneration
	assemblies          map[uint32]*tasmanAssembly
	elem                *list.Element
	ready               bool
	recovered           uint64
}
type TasmanReceiveStats struct {
	OuterPackets, OuterBytes, AuthDrops, MalformedDrops, RateDrops, ReplayDrops, ConflictDrops, ResourceDrops uint64
	RecoveredSymbols, Completed, DeliveredBytes, QueueDrops, ExpiredGenerations, ExpiredMessages, Covers      uint64
}
type tasmanReceiver struct {
	cipher                                    *tasmanCipher
	scratch                                   [tasmanWireMax]byte
	peers                                     map[[16]byte]*tasmanPeer
	sources                                   map[netip.Prefix]int
	endpoints                                 map[netip.AddrPort]int
	tombs                                     map[[16]byte]time.Time
	peerOrder, genOrder, assemblyOrder, queue *list.List
	queued                                    map[[16]byte]servoQueueUsage
	symbolBytes, assemblyBytes, queueBytes    int
	verify, unknown, admit                    blinkBucket
	shards                                    [256]blinkBucket
	seed                                      maphash.Seed
	stats                                     TasmanReceiveStats
	onComplete                                func(*tasmanPeer)
	onPadding                                 func(netip.AddrPort, []byte)
}

func newTasmanReceiver(password []byte, dir byte) (*tasmanReceiver, error) {
	c, err := newTasmanCipher(password, dir)
	if err != nil {
		return nil, err
	}
	return &tasmanReceiver{cipher: c, peers: make(map[[16]byte]*tasmanPeer), sources: make(map[netip.Prefix]int), endpoints: make(map[netip.AddrPort]int), tombs: make(map[[16]byte]time.Time), peerOrder: list.New(), genOrder: list.New(), assemblyOrder: list.New(), queue: list.New(), queued: make(map[[16]byte]servoQueueUsage), seed: maphash.MakeSeed()}, nil
}

func (r *tasmanReceiver) dropGeneration(g *tasmanGeneration) {
	for _, b := range g.sources {
		r.symbolBytes -= len(b)
	}
	for _, b := range g.repairs {
		r.symbolBytes -= len(b)
	}
	delete(g.peer.generations, g.id)
	g.peer.gone.mark(uint64(g.id))
	r.genOrder.Remove(g.elem)
}

func (r *tasmanReceiver) dropAssembly(a *tasmanAssembly, abandon bool) {
	delete(a.peer.assemblies, a.id)
	r.assemblyBytes -= len(a.data)
	r.assemblyOrder.Remove(a.elem)
	if abandon {
		a.peer.done.mark(uint64(a.id))
	}
}

func (r *tasmanReceiver) retire(p *tasmanPeer, now time.Time) {
	for _, g := range p.generations {
		r.dropGeneration(g)
	}
	for _, a := range p.assemblies {
		r.dropAssembly(a, false)
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
	r.tombs[p.session] = maxTime(now.Add(3*time.Second), time.Unix(int64(p.born), 0).Add(31*time.Second))
}

func maxTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}

func (r *tasmanReceiver) maintain(now time.Time) {
	// At most 2048 tombs, 32 expired sessions / objects per maintenance turn.
	for id, t := range r.tombs {
		if !now.Before(t) {
			delete(r.tombs, id)
		}
	}
	for range 32 {
		e := r.genOrder.Front()
		if e == nil || now.Before(e.Value.(*tasmanGeneration).deadline) {
			break
		}
		r.dropGeneration(e.Value.(*tasmanGeneration))
		r.stats.ExpiredGenerations++
	}
	for range 32 {
		e := r.assemblyOrder.Front()
		if e == nil || now.Before(e.Value.(*tasmanAssembly).deadline) {
			break
		}
		r.dropAssembly(e.Value.(*tasmanAssembly), true)
		r.stats.ExpiredMessages++
	}
	for range 32 {
		e := r.peerOrder.Front()
		if e == nil || now.Sub(e.Value.(*tasmanPeer).used) < 2*time.Minute {
			break
		}
		r.retire(e.Value.(*tasmanPeer), now)
	}
}

func (r *tasmanReceiver) receive(wire []byte, addr netip.AddrPort, now time.Time) error {
	r.stats.OuterPackets++
	r.stats.OuterBytes += uint64(len(wire))
	addr, source, ok := servoEndpoint(addr)
	if !ok || len(wire) < 60 || len(wire) > 1232 {
		r.stats.MalformedDrops++
		return errTasmanFrame
	}
	r.maintain(now)
	// Authenticated endpoint throughput is distinct from unknown-source admission.
	if !r.verify.allow(now, 524288, 32768) {
		r.stats.RateDrops++
		return errTasmanResource
	}
	if r.endpoints[addr] == 0 {
		bucket := maphash.Comparable(r.seed, source) % 256
		if !r.unknown.allow(now, 16384, 2048) || !r.shards[bucket].allow(now, 4096, 512) {
			r.stats.RateDrops++
			return errTasmanResource
		}
	}
	f, err := r.cipher.open(wire, &r.scratch)
	if err != nil {
		if errors.Is(err, errTasmanAuth) {
			r.stats.AuthDrops++
		} else {
			r.stats.MalformedDrops++
		}
		return err
	}
	p := r.peers[f.session]
	if p != nil && now.Sub(p.used) >= 2*time.Minute {
		r.retire(p, now)
		p = nil
	}
	if p == nil {
		if f.kind == tasmanCover {
			return nil
		} // no session, route, generation or reply from cover
		delta := int64(f.born) - now.Unix()
		if delta < -30 || delta > 30 || now.Unix() < 30 {
			return errTasmanFrame
		}
		if _, ok := r.tombs[f.session]; ok {
			return errTasmanConflict
		}
		if len(r.peers) >= 1024 || len(r.peers)+len(r.tombs) >= 2048 || r.sources[source] >= 32 {
			r.stats.ResourceDrops++
			return errTasmanResource
		}
		if !r.admit.allow(now, 128, 256) {
			r.stats.RateDrops++
			return errTasmanResource
		}
		p = &tasmanPeer{session: f.session, addr: addr, source: source, born: f.born, used: now, generations: make(map[uint32]*tasmanGeneration), assemblies: make(map[uint32]*tasmanAssembly)}
		p.elem = r.peerOrder.PushBack(p)
		r.peers[f.session] = p
		r.sources[source]++
		r.endpoints[addr]++
	} else if p.addr != addr || p.born != f.born {
		return errTasmanConflict
	}
	if p.packets.seen(f.counter) {
		r.stats.ReplayDrops++
		return errTasmanConflict
	}
	if !p.verify.allow(now, 262144, 16384) {
		r.stats.RateDrops++
		return errTasmanResource
	}
	p.packets.mark(f.counter)
	if r.onPadding != nil {
		r.onPadding(addr, f.padding)
	}
	p.used = now
	r.peerOrder.MoveToBack(p.elem)
	if f.kind == tasmanCover {
		r.stats.Covers++
		return nil
	}
	var records [tasmanRecordsMax]tasmanRecord
	if f.kind == tasmanShort {
		n, _ := parseTasmanRecords(f.body, &records)
		return r.submit(p, records[:n], now)
	}
	if p.gone.seen(uint64(f.generation)) {
		r.stats.ReplayDrops++
		return errTasmanConflict
	}
	g := p.generations[f.generation]
	if g != nil && !now.Before(g.deadline) {
		r.dropGeneration(g)
		r.stats.ExpiredGenerations++
		return errTasmanConflict
	}
	if g != nil {
		if g.width != f.width || f.finalK != 0 && g.k != 0 && g.k != int(f.finalK) {
			r.stats.ConflictDrops++
			return errTasmanConflict
		}
		if f.kind == tasmanSource && g.k != 0 && int(f.index) >= g.k {
			return errTasmanConflict
		}
		if f.kind == tasmanRepair {
			for i := int(f.finalK); i < 8; i++ {
				if g.sources[i] != nil {
					return errTasmanConflict
				}
			}
		}
		var prior []byte
		if f.kind == tasmanSource {
			prior = g.sources[f.index]
		} else {
			prior = g.repairs[f.index-128]
		}
		if prior != nil {
			if !bytes.Equal(prior, f.body) {
				r.stats.ConflictDrops++
				return errTasmanConflict
			}
			return nil
		}
	}
	if f.kind == tasmanSource {
		n, _ := parseTasmanSymbol(f.body, &records)
		if err = r.preflight(p, records[:n], now); err != nil {
			return err
		}
	}
	if g == nil {
		if len(p.generations) >= tasmanPeerGenerations || r.genOrder.Len() >= tasmanGenerationLimit {
			r.stats.ResourceDrops++
			return errTasmanResource
		}
		g = &tasmanGeneration{id: f.generation, width: f.width, deadline: now.Add(tasmanGenerationTTL), peer: p}
		g.elem = r.genOrder.PushBack(g)
		p.generations[g.id] = g
	}
	if r.symbolBytes+len(f.body) > tasmanSymbolBytes {
		r.stats.ResourceDrops++
		return errTasmanResource
	}
	if f.kind == tasmanSource {
		g.sources[f.index] = bytes.Clone(f.body)
		r.symbolBytes += len(f.body)
		n, _ := parseTasmanSymbol(f.body, &records)
		r.submit(p, records[:n], now)
	} else {
		g.k = int(f.finalK)
		g.repairs[f.index-128] = bytes.Clone(f.body)
		r.symbolBytes += len(f.body)
	}
	if g.k == 0 {
		return nil
	}
	recovered, e := tasmanRecover(g.sources, g.repairs, g.k, g.width)
	if e != nil {
		return nil
	} // insufficient equations, not malformed
	// Validate ALL reconstructed symbols and all conflicting records before any delivery.
	var sets [2][tasmanRecordsMax]tasmanRecord
	var counts [2]int
	slot := 0
	for _, s := range recovered {
		if s != nil {
			n, e := parseTasmanSymbol(s, &sets[slot])
			if e != nil {
				r.stats.MalformedDrops++
				return e
			}
			counts[slot] = n
			if e = r.preflight(p, sets[slot][:n], now); e != nil {
				return e
			}
			slot++
		}
	}
	if slot == 2 {
		for _, a := range sets[0][:counts[0]] {
			for _, b := range sets[1][:counts[1]] {
				if a.message == b.message && tasmanRecordsConflict(a, b) {
					return errTasmanConflict
				}
			}
		}
	}
	for i, s := range recovered {
		if s != nil {
			if r.symbolBytes+len(s) > tasmanSymbolBytes {
				return errTasmanResource
			}
			g.sources[i] = s
			r.symbolBytes += len(s)
			r.stats.RecoveredSymbols++
			p.recovered++
		}
	}
	for i := range slot {
		r.submit(p, sets[i][:counts[i]], now)
	}
	// Fully reconstructed closed generations need no retained matrices. The
	// separate generation window rejects all delayed source / repair arrivals.
	complete := true
	for i := range g.k {
		if g.sources[i] == nil {
			complete = false
			break
		}
	}
	if complete {
		r.dropGeneration(g)
	}
	return nil
}

func tasmanRecordsConflict(a, b tasmanRecord) bool {
	if a.total != b.total {
		return true
	}
	x, y := int(a.offset), int(b.offset)
	endA, endB := x+len(a.data), y+len(b.data)
	if x == y && endA == endB {
		return !bytes.Equal(a.data, b.data)
	}
	return x < endB && y < endA
}

func (r *tasmanReceiver) preflight(p *tasmanPeer, records []tasmanRecord, now time.Time) error {
	for _, rec := range records {
		if p.done.seen(uint64(rec.message)) {
			continue
		}
		a := p.assemblies[rec.message]
		if a == nil {
			continue
		}
		if !now.Before(a.deadline) {
			r.dropAssembly(a, true)
			r.stats.ExpiredMessages++
			continue
		}
		if len(a.data) != int(rec.total) {
			return errTasmanConflict
		}
		start, end := int(rec.offset), int(rec.offset)+len(rec.data)
		for x, e := range a.ends {
			if e == 0 {
				continue
			}
			y := int(e)
			if start == x && end == y {
				if !bytes.Equal(a.data[x:y], rec.data) {
					return errTasmanConflict
				}
			} else if start < y && x < end {
				return errTasmanConflict
			}
		}
	}
	return nil
}

func (r *tasmanReceiver) submit(p *tasmanPeer, records []tasmanRecord, now time.Time) error {
	if err := r.preflight(p, records, now); err != nil {
		r.stats.ConflictDrops++
		return err
	}
	for _, rec := range records {
		if p.done.seen(uint64(rec.message)) {
			continue
		}
		a := p.assemblies[rec.message]
		if a == nil && rec.offset == 0 && len(rec.data) == int(rec.total) {
			r.complete(p, rec.message, bytes.Clone(rec.data))
			continue
		}
		if a != nil && a.ends[rec.offset] != 0 {
			continue
		}
		if a == nil {
			if len(p.assemblies) >= 128 || r.assemblyOrder.Len() >= 2048 || r.assemblyBytes+int(rec.total) > 2457600 {
				r.stats.ResourceDrops++
				continue
			}
			a = &tasmanAssembly{data: make([]byte, rec.total), deadline: now.Add(3 * time.Second), id: rec.message, peer: p}
			a.elem = r.assemblyOrder.PushBack(a)
			p.assemblies[a.id] = a
			r.assemblyBytes += len(a.data)
		}
		copy(a.data[rec.offset:], rec.data)
		a.ends[rec.offset] = rec.offset + uint16(len(rec.data))
		a.filled += len(rec.data)
		if a.filled == len(a.data) {
			r.dropAssembly(a, false)
			r.complete(p, a.id, a.data)
		}
	}
	return nil
}

func (r *tasmanReceiver) complete(p *tasmanPeer, id uint32, data []byte) {
	p.done.mark(uint64(id))
	p.ready = true
	r.stats.Completed++
	if r.onComplete != nil {
		r.onComplete(p)
	}
	q := r.queued[p.session]
	if r.queue.Len() >= 1024 || r.queueBytes+len(data) > 1<<20 || q.items >= 64 || q.bytes+len(data) > 64<<10 {
		r.stats.QueueDrops++
		return
	}
	r.queue.PushBack(servoCompleted{session: p.session, addr: p.addr, data: data})
	r.queueBytes += len(data)
	q.items++
	q.bytes += len(data)
	r.queued[p.session] = q
}

func (r *tasmanReceiver) pop(out []byte) (int, netip.AddrPort, error) {
	e := r.queue.Front()
	if e == nil {
		return 0, netip.AddrPort{}, io.EOF
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
		return 0, d.addr, io.ErrShortBuffer
	}
	n := copy(out, d.data)
	r.stats.DeliveredBytes += uint64(n)
	return n, d.addr, nil
}
