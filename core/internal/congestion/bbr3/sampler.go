// SPDX-License-Identifier: MIT-0

package bbr3

import (
	"errors"
	"math"
	"math/bits"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

var (
	errInvalidSampleInput = errors.New("bbr3: invalid sampling input")
	errSampleCapacity     = errors.New("bbr3: send history full; transport must retire obsolete records")
	errSampleOverflow     = errors.New("bbr3: cumulative byte counter overflow")
)

// Delivery counters use bytes, never bits or packet counts. They cover packets
// admitted to this sampler, not traffic sent before controller installation.
// Declared loss remains cumulative even if the packet is subsequently ACKed.
type deliveryTotals struct {
	sent, delivered, lost, congestionLost uint64
}

type sentPacket struct {
	number                          congestion.PacketNumber
	bytes                           congestion.ByteCount
	sentAt, firstSent, deliveredAt  monotime.Time
	delivered, lost, congestionLost uint64
	inFlight                        congestion.ByteCount // AFTER this packet, including its bytes.
	anchorValid, appLimited         bool
	declaredLost, probe             bool
}

// rateSample describes one whole ACK event. Its rate is in bytes/second, and
// only usable when valid is true. ACK timing and send timing are independent;
// the longer interval limits the rate, including under ACK compression.
//
// A late ACK of a retained lost packet counts delivery once but does NOT imply
// that the entire loss recovery episode was spurious. Model undo will need a
// separate transport notification.
type rateSample struct {
	hasData, valid, appLimited bool
	rate                       uint64
	interval, sendElapsed      time.Duration
	ackElapsed, rtt            time.Duration // rtt is raw, NOT adjusted for peer ACK delay.
	delivered, priorDelivered  uint64
	newlyAcked, lostSinceSent  uint64
	congestionLostSinceSent    uint64 // Excludes MTU probes; raw loss above remains observable.
	spuriousAcked              uint64
	unknownPackets             int
	packet                     congestion.PacketNumber
	inFlightAtSend             congestion.ByteCount
}

// lossSample distinguishes congestion loss from failed MTU probes. Losing a
// probe still removes the transport's bytes in flight, but must not inflate
// BBR's congestion-loss ratio. A timeout/PTO is not itself a loss notification.
type lossSample struct {
	known, newlyLost, congestion bool
	bytes                        congestion.ByteCount
	state                        sentPacket
}

// deliverySampler is connection-local and intentionally not goroutine-safe.
// Its future caller must serialize QUIC congestion-control events.
//
// It never reconstructs current bytes in flight by adding/subtracting events:
// only the transport knows about key discard, Retry, PTO removal and migration.
// Per-send snapshots take authoritative AFTER-send values. Retained history is
// bounded; exhausting it is an explicit error, never silent sample corruption.
type deliverySampler struct {
	packets       map[congestion.PacketNumber]sentPacket
	capacity      int
	totals        deliveryTotals
	lastSent      congestion.PacketNumber
	lastSentAt    monotime.Time
	hasSent       bool
	firstSent     monotime.Time
	deliveredAt   monotime.Time
	anchorValid   bool
	appLimitedEnd uint64 // A delivered-byte waterline, not a packet number.
}

func newDeliverySampler(capacity int) (*deliverySampler, error) {
	if capacity <= 0 {
		return nil, errInvalidSampleInput
	}
	return &deliverySampler{
		packets:  make(map[congestion.PacketNumber]sentPacket, min(capacity, 256)),
		capacity: capacity,
	}, nil
}

// sent requires a single, monotonically numbered packet space (1-RTT for the
// eventual replacement controller). ackEliciting is quic-go's current meaning
// of the public callback's historical "isRetransmittable" argument.
//
// Pure ACK packets participate in packet-number ordering but not delivery
// counters/history. Zero monotonic timestamps are valid; validity is explicit.
// Every validation error leaves state unchanged.
func (s *deliverySampler) sent(at monotime.Time, number congestion.PacketNumber, bytes, inFlightAfter congestion.ByteCount, ackEliciting, probe bool) error {
	if number < 0 || bytes <= 0 || inFlightAfter < 0 ||
		(s.hasSent && (number <= s.lastSent || at.Before(s.lastSentAt))) ||
		(ackEliciting && inFlightAfter < bytes) || (probe && !ackEliciting) {
		return errInvalidSampleInput
	}
	if ackEliciting {
		if len(s.packets) >= s.capacity {
			return errSampleCapacity
		}
		if uint64(bytes) > math.MaxUint64-s.totals.sent {
			return errSampleOverflow
		}
		// Empty flight, not an inferred app-limited notification. Resetting the
		// sampling clocks excludes time spent idle from the next flight's rate.
		if inFlightAfter == bytes {
			s.firstSent, s.deliveredAt = at, at
			s.anchorValid = true
		}
		s.packets[number] = sentPacket{
			number: number, bytes: bytes, sentAt: at,
			firstSent: s.firstSent, deliveredAt: s.deliveredAt,
			delivered: s.totals.delivered, lost: s.totals.lost, congestionLost: s.totals.congestionLost,
			inFlight: inFlightAfter, anchorValid: s.anchorValid,
			appLimited: s.appLimitedEnd != 0, probe: probe,
		}
		s.totals.sent += uint64(bytes)
	}
	s.lastSent, s.lastSentAt, s.hasSent = number, at, true
	return nil
}

// markAppLimited must only be called after the TRANSPORT has established that
// it ran out of unsent data and lower-layer pending transmissions, is not cwnd
// limited, and has no unretransmitted loss. Pacing/flow-control waits are not
// sufficient evidence. The local AdvancedControl transport establishes these
// conditions; the legacy upstream interface cannot.
func (s *deliverySampler) markAppLimited(inFlight congestion.ByteCount) error {
	if inFlight < 0 {
		return errInvalidSampleInput
	}
	if uint64(inFlight) > math.MaxUint64-s.totals.delivered {
		return errSampleOverflow
	}
	s.appLimitedEnd = max(1, s.totals.delivered+uint64(inFlight))
	return nil
}

// lost is idempotent while the snapshot is retained. MTU-probe classification
// must be known at send time, not guessed from the size of a lost packet.
func (s *deliverySampler) lost(number congestion.PacketNumber) (lossSample, error) {
	if number < 0 {
		return lossSample{}, errInvalidSampleInput
	}
	p, ok := s.packets[number]
	if !ok {
		return lossSample{}, nil
	}
	result := lossSample{known: true, bytes: p.bytes, state: p, congestion: !p.probe}
	if p.declaredLost {
		return result, nil
	}
	if uint64(p.bytes) > math.MaxUint64-s.totals.lost ||
		(!p.probe && uint64(p.bytes) > math.MaxUint64-s.totals.congestionLost) {
		return lossSample{}, errSampleOverflow
	}
	p.declaredLost = true
	s.packets[number] = p
	s.totals.lost += uint64(p.bytes)
	if !p.probe {
		s.totals.congestionLost += uint64(p.bytes)
	}
	result.newlyLost = true
	return result, nil
}

// ack processes a whole ACK batch, selecting the newest SENT packet explicitly
// instead of depending on array/map order. Packet IDs must be newly acknowledged
// by the transport, but duplicate IDs in the batch and already-removed records
// never double-count bytes. Caller-owned input is not sorted or modified.
//
// Unknown records make this batch's rate unusable: we must not invent a send
// snapshot for a pre-installation, discarded or previously acknowledged packet.
// Known delivery is still accounted for. The controller's eventual transport
// adapter must distinguish these cases rather than treating unknown ACKs as
// loss or assuming an arbitrary app-limited state.
func (s *deliverySampler) ack(at monotime.Time, numbers []congestion.PacketNumber, minRTT time.Duration) (rateSample, error) {
	var sample rateSample
	if minRTT < 0 {
		return sample, errInvalidSampleInput
	}
	seen := make(map[congestion.PacketNumber]struct{}, len(numbers))
	var newest sentPacket
	// Validate first: malformed time or counter overflow cannot half-commit ACKs.
	for _, number := range numbers {
		if number < 0 {
			return rateSample{}, errInvalidSampleInput
		}
		if _, duplicate := seen[number]; duplicate {
			continue
		}
		seen[number] = struct{}{}
		p, ok := s.packets[number]
		if !ok {
			sample.unknownPackets++
			continue
		}
		if _, valid := sampleElapsed(at, p.sentAt); !valid {
			return rateSample{}, errInvalidSampleInput
		}
		if uint64(p.bytes) > math.MaxUint64-sample.newlyAcked {
			return rateSample{}, errSampleOverflow
		}
		sample.newlyAcked += uint64(p.bytes)
		if p.declaredLost {
			sample.spuriousAcked += uint64(p.bytes)
		}
		if !sample.hasData || p.sentAt.After(newest.sentAt) ||
			(p.sentAt == newest.sentAt && p.number > newest.number) {
			newest = p
			sample.hasData = true
		}
	}
	if sample.newlyAcked > math.MaxUint64-s.totals.delivered {
		return rateSample{}, errSampleOverflow
	}
	if !sample.hasData {
		return sample, nil
	}
	s.totals.delivered += sample.newlyAcked
	for number := range seen {
		delete(s.packets, number)
	}
	// A sample's app-limited flag comes from its send-time snapshot, even if
	// this ACK clears the delivered-byte bubble for future transmissions.
	if s.appLimitedEnd != 0 && s.totals.delivered > s.appLimitedEnd {
		s.appLimitedEnd = 0
	}
	sample.packet, sample.appLimited = newest.number, newest.appLimited
	sample.priorDelivered = newest.delivered
	sample.delivered = s.totals.delivered - newest.delivered
	sample.lostSinceSent = s.totals.lost - newest.lost
	sample.congestionLostSinceSent = s.totals.congestionLost - newest.congestionLost
	sample.inFlightAtSend = newest.inFlight
	sample.rtt, _ = sampleElapsed(at, newest.sentAt) // Validated before committing.
	var sendValid, ackValid bool
	sample.sendElapsed, sendValid = sampleElapsed(newest.sentAt, newest.firstSent)
	sample.ackElapsed, ackValid = sampleElapsed(at, newest.deliveredAt)
	sample.interval = max(sample.sendElapsed, sample.ackElapsed)
	// Even when this packet lacked an initial anchor, its acknowledgment gives
	// a real anchor to packets sent after this event.
	s.firstSent, s.deliveredAt, s.anchorValid = newest.sentAt, at, true
	sample.valid = newest.anchorValid && sample.unknownPackets == 0 &&
		sendValid && ackValid &&
		sample.interval > 0 && sample.interval >= minRTT && sample.delivered > 0
	if sample.valid {
		sample.rate = bytesPerSecond(sample.delivered, sample.interval)
	}
	return sample, nil
}

// discard removes a snapshot without declaring loss or delivery (key discard,
// cancellation, a PTO packet removed by the transport, or explicit retirement).
// This does not decide how a future BBRv3 sender should react to the reason.
func (s *deliverySampler) discard(number congestion.PacketNumber) {
	delete(s.packets, number)
}

// forgetBefore requires an authoritative transport retirement boundary, not
// "largest ACK + 1": reordered/lost packets below that ACK can still matter.
func (s *deliverySampler) forgetBefore(number congestion.PacketNumber) {
	for retained := range s.packets {
		if retained < number {
			delete(s.packets, retained)
		}
	}
}

// Monotonic Time has an implementation-dependent origin: negative and zero
// values are legitimate. Check the difference, not the absolute timestamp, and
// don't let an unrepresentable interval wrap into a plausible short duration.
func sampleElapsed(later, earlier monotime.Time) (time.Duration, bool) {
	if later < earlier {
		return 0, false
	}
	delta := uint64(later) - uint64(earlier)
	if delta > math.MaxInt64 {
		return 0, false
	}
	return time.Duration(delta), true
}

// bytesPerSecond avoids intermediate bytes*1e9 overflow. An unrepresentable
// rate saturates instead of wrapping into a low rate or dividing by zero.
func bytesPerSecond(bytes uint64, interval time.Duration) uint64 {
	if bytes == 0 || interval <= 0 {
		return 0
	}
	hi, lo := bits.Mul64(bytes, uint64(time.Second))
	if hi >= uint64(interval) {
		return math.MaxUint64
	}
	rate, _ := bits.Div64(hi, lo, uint64(interval))
	return rate
}
