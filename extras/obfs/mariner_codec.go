// SPDX-License-Identifier: MIT-0

package obfs

import (
	"container/list"
	"encoding/binary"
	"unsafe"
)

const marinerRelationsMax = 294 // max ceil(1232*20/84)
type (
	marinerRelation struct {
		parents [5]uint16
		tables  [6]byte
		order   byte
	}
	marinerGraph struct {
		k, r, l   int
		positions [marinerWireMax]uint16
		relations [marinerRelationsMax]marinerRelation
	}
)

func (p *marinerProfile) graph(l int, g *marinerGraph) error {
	k, r, err := p.dimensions(l)
	if err != nil {
		return err
	}
	*g = marinerGraph{k: k, r: r, l: l}
	label := append([]byte("graph"), byte(l>>8), byte(l))
	s := newMarinerStream(p.key[:], label)
	var sources [marinerWireMax]uint16
	for i := range k {
		sources[i] = uint16(i)
	}
	shuffle := func(a []uint16) error {
		for i := len(a) - 1; i > 0; i-- {
			j, e := s.below(i + 1)
			if e != nil {
				return e
			}
			a[i], a[j] = a[j], a[i]
		}
		return nil
	}
	if err = shuffle(sources[:k]); err != nil {
		return err
	}
	poolSize := k - r
	if p.pool > 0 {
		poolSize = min(poolSize, p.pool)
	}
	pool := sources[r : r+poolSize]
	for j := range r {
		rel := &g.relations[j]
		m, e := marinerWeighted(s, p.orders[:])
		if e != nil {
			return e
		}
		rel.order = byte(3 + m)
		rel.parents[0] = sources[j]
		var swaps [4]int
		for i := 0; i < int(rel.order)-1; i++ {
			x, e := s.below(poolSize - i)
			if e != nil {
				return e
			}
			x += i
			swaps[i] = x
			pool[i], pool[x] = pool[x], pool[i]
			rel.parents[i+1] = pool[i]
		}
		for i := int(rel.order) - 2; i >= 0; i-- {
			pool[i], pool[swaps[i]] = pool[swaps[i]], pool[i]
		}
		for i := 0; i <= int(rel.order); i++ {
			x, e := s.below(16)
			if e != nil {
				return e
			}
			rel.tables[i] = byte(x)
		}
	}
	for i := range l {
		g.positions[i] = uint16(i)
	}
	if err = shuffle(g.positions[:l]); err != nil {
		return err
	}
	return g.validate()
}

func (g *marinerGraph) validate() error {
	if g.k < 63 || g.l > marinerWireMax || g.r < 1 || g.r > marinerRelationsMax || g.k+g.r != g.l {
		return errMarinerFrame
	}
	var positions, anchors [marinerWireMax]bool
	for _, pos := range g.positions[:g.l] {
		if int(pos) >= g.l || positions[pos] {
			return errMarinerFrame
		}
		positions[pos] = true
	}
	for _, rel := range g.relations[:g.r] {
		if rel.order < 3 || rel.order > 5 || int(rel.parents[0]) >= g.k || anchors[rel.parents[0]] {
			return errMarinerFrame
		}
		anchors[rel.parents[0]] = true
	}
	for _, rel := range g.relations[:g.r] {
		for i := 0; i < int(rel.order); i++ {
			if int(rel.parents[i]) >= g.k || rel.tables[i] >= 16 || i > 0 && anchors[rel.parents[i]] {
				return errMarinerFrame
			}
			for j := range i {
				if rel.parents[i] == rel.parents[j] {
					return errMarinerFrame
				}
			}
		}
		if rel.tables[rel.order] >= 16 {
			return errMarinerFrame
		}
	}
	return nil
}

func (p *marinerProfile) evaluate(rel *marinerRelation, raw []byte) byte {
	x := byte(0)
	for i := 0; i < int(rel.order); i++ {
		x ^= p.tables[rel.tables[i]][raw[rel.parents[i]]]
	}
	return p.tables[rel.tables[rel.order]][x]
}

func (p *marinerProfile) encode(dst, raw []byte, g *marinerGraph) ([]byte, error) {
	if len(raw) != g.k || len(dst) < g.l {
		return nil, errMarinerFrame
	}
	for i, x := range raw {
		dst[g.positions[i]] = x
	}
	for j := range g.r {
		dst[g.positions[g.k+j]] = p.evaluate(&g.relations[j], raw)
	}
	return dst[:g.l], nil
}

func (p *marinerProfile) decode(dst, wire []byte, g *marinerGraph) ([]byte, error) {
	if len(wire) != g.l || len(dst) < g.k {
		return nil, errMarinerFrame
	}
	raw := dst[:g.k]
	for i := range g.k {
		raw[i] = wire[g.positions[i]]
	}
	for j := range g.r {
		if wire[g.positions[g.k+j]] != p.evaluate(&g.relations[j], raw) {
			return nil, errMarinerRelation
		}
	}
	return raw, nil
}

func (g *marinerGraph) bytes() []byte {
	b := make([]byte, 6)
	binary.BigEndian.PutUint16(b, uint16(g.k))
	binary.BigEndian.PutUint16(b[2:], uint16(g.r))
	binary.BigEndian.PutUint16(b[4:], uint16(g.l))
	for _, rel := range g.relations[:g.r] {
		b = append(b, rel.order)
		for i := 0; i < int(rel.order); i++ {
			b = append(b, byte(rel.parents[i]>>8), byte(rel.parents[i]), rel.tables[i])
		}
		b = append(b, rel.tables[rel.order])
	}
	for _, pos := range g.positions[:g.l] {
		b = append(b, byte(pos>>8), byte(pos))
	}
	return b
}

// Unauthenticated candidates live only in scratch and cannot evict hot graphs.
type marinerGraphCache struct {
	order                    *list.List
	entries                  map[int]*list.Element
	scratch                  marinerGraph
	hits, misses, promotions uint64
}

func newMarinerGraphCache() marinerGraphCache {
	return marinerGraphCache{order: list.New(), entries: make(map[int]*list.Element)}
}

func (c *marinerGraphCache) find(l int) *marinerGraph {
	if e := c.entries[l]; e != nil {
		c.order.MoveToBack(e)
		c.hits++
		return e.Value.(*marinerGraph)
	}
	c.misses++
	return nil
}

func (c *marinerGraphCache) promote(g *marinerGraph) {
	if c.entries[g.l] != nil {
		return
	}
	copyGraph := new(marinerGraph)
	*copyGraph = *g
	for c.order.Len() >= 32 || (c.order.Len()+1)*int(unsafe.Sizeof(marinerGraph{})) > 512<<10 {
		e := c.order.Front()
		delete(c.entries, e.Value.(*marinerGraph).l)
		c.order.Remove(e)
	}
	c.entries[g.l] = c.order.PushBack(copyGraph)
	c.promotions++
}
