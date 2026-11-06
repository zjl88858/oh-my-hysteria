// SPDX-License-Identifier: MIT-0

package obfs

import (
	"errors"
	"hash/maphash"
	"net/netip"
	"time"
)

type (
	MarinerReceiveStats = servoReceiveStats
	marinerReceiver     struct {
		state                       *servoReceiver
		profile                     marinerProfile
		cipher                      *marinerCipher
		cache                       marinerGraphCache
		raw, plain                  [marinerWireMax]byte
		compileBudget               blinkBucket
		unknownCompile              blinkBucket
		compileDrops, relationDrops uint64
	}
)

func newMarinerReceiver(password []byte, direction byte) (*marinerReceiver, error) {
	p, err := compileMarinerProfile(password, direction)
	if err != nil {
		return nil, err
	}
	c, err := newMarinerCipher(password, direction)
	if err != nil {
		return nil, err
	}
	return &marinerReceiver{state: newFramedReceiveState(), profile: p, cipher: c, cache: newMarinerGraphCache()}, nil
}

func (r *marinerReceiver) receive(wire []byte, addr netip.AddrPort, now time.Time) error {
	s := r.state
	s.stats.OuterPackets++
	s.stats.OuterBytes += uint64(len(wire))
	addr, source, ok := servoEndpoint(addr)
	if _, _, err := r.profile.dimensions(len(wire)); !ok || err != nil {
		s.stats.MalformedDrops++
		return errMarinerFrame
	}
	s.maintain(now)
	if !s.verify.allow(now, 262144, 16384) {
		s.stats.RateDrops++
		return errServoRate
	}
	if s.endpoints[addr] == 0 {
		i := maphash.Comparable(s.hashSeed, source) % 256
		if !s.unknown.allow(now, 16384, 2048) || !s.unknownShards[i].allow(now, 4096, 512) {
			s.stats.RateDrops++
			return errServoRate
		}
	}
	g := r.cache.find(len(wire))
	miss := g == nil
	if miss {
		if s.endpoints[addr] == 0 && !r.unknownCompile.allow(now, 128, 32) || !r.compileBudget.allow(now, 4096, 256) {
			r.compileDrops++
			s.stats.RateDrops++
			return errServoRate
		}
		g = &r.cache.scratch
		if err := r.profile.graph(len(wire), g); err != nil {
			s.stats.MalformedDrops++
			return err
		}
	}
	raw, err := r.profile.decode(r.raw[:], wire, g)
	if err != nil {
		r.relationDrops++
		s.stats.MalformedDrops++
		return err
	}
	f, err := r.cipher.open(r.plain[:], raw, &r.profile, len(wire))
	if err != nil {
		if errors.Is(err, errMarinerAuth) {
			s.stats.AuthDrops++
		} else {
			s.stats.MalformedDrops++
		}
		return err
	}
	if miss {
		r.cache.promote(g)
	}
	frame := servoFrame{session: f.session, counter: f.counter, born: f.born, count: 1}
	frame.records[0] = servoRecord{message: f.message, total: f.total, offset: f.offset, data: f.data}
	return s.acceptAuthenticated(frame, addr, now)
}
