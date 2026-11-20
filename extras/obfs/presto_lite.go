// SPDX-License-Identifier: MIT-0

package obfs

import "time"

// Selected by the named wrapper, never negotiated or inferred from a packet.
type prestoVariant uint8

const (
	prestoStandard prestoVariant = iota
	prestoLite
)

// Keep the password-derived length grammar (and NetFront lane roles), but
// authenticate the chosen mode. A standard listener never accepts Lite traffic.
func (v prestoVariant) authLabel(label string) string {
	if v == prestoLite {
		return "lite/" + label
	}
	return label
}

const (
	prestoLiteWarmBytes  = 32 << 10
	prestoLiteIdle       = 40 * time.Millisecond
	prestoLiteWaitPerKiB = 80 * time.Microsecond
	prestoLiteMaxWait    = 2500 * time.Microsecond
	prestoLiteCreditTTL  = 250 * time.Millisecond
	prestoLiteExtraRate  = 16384
	prestoLiteExtraBurst = 256
)

func prestoLiteBulkPacket(p []byte) bool {
	return len(p) >= 1000 && p[0]&0x80 == 0 // a large QUIC short-header datagram
}

// Per sending session, serialized by writeMu. Idle never banks future work.
type prestoLitePacing struct {
	last    time.Time
	warm    int
	balance time.Duration
}

func (s *prestoLitePacing) enter(p []byte, now time.Time) bool {
	if len(p) == 0 || p[0]&0x80 != 0 {
		*s = prestoLitePacing{}
		return false
	}
	if now.Sub(s.last) > prestoLiteIdle {
		*s = prestoLitePacing{}
	}
	if !prestoLiteBulkPacket(p) {
		return false
	}
	s.last = now
	if s.warm < prestoLiteWarmBytes {
		s.warm = min(prestoLiteWarmBytes, s.warm+len(p))
		return false
	}
	s.balance = min(prestoLiteMaxWait, s.balance+prestoLiteWaitPerKiB*time.Duration(len(p))/1024)
	return true
}

// The original grammar is sampled even when a proposed pause is skipped:
// this decision must not advance the packet-length / fragmentation RNG.
func (s *prestoLitePacing) keep(gap time.Duration) bool {
	if s.balance < gap {
		return false
	}
	s.balance -= gap
	return true
}

// The extra source shards exist only on Lite sockets. Credits belong to an
// already-bound receive peer, not everyone sharing its IP or hash shard.
type prestoLiteBudget struct{ extra [256]blinkBucket }

type prestoLiteCredit struct {
	last time.Time
	left int
}

func (c *prestoLiteCredit) earn(now time.Time, pieces int) {
	if now.Sub(c.last) >= prestoLiteCreditTTL {
		c.left = 0
	}
	c.left = min(prestoLiteExtraBurst, c.left+pieces)
	c.last = now
}

func (b *prestoLiteBudget) spend(p *prestoPeer, shard uint64, now time.Time) bool {
	if p == nil || p.credit.left == 0 || now.Sub(p.credit.last) >= prestoLiteCreditTTL ||
		now.Sub(p.used) >= prestoSessionTTL || !b.extra[shard].allow(now, prestoLiteExtraRate, prestoLiteExtraBurst) {
		return false
	}
	p.credit.left--
	return true
}
