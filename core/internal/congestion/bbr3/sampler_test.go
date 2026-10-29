// SPDX-License-Identifier: MIT-0

package bbr3

import (
	"maps"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func newTestSampler(t *testing.T, capacity int) *deliverySampler {
	t.Helper()
	s, err := newDeliverySampler(capacity)
	require.NoError(t, err)
	return s
}

func snapshotSampler(s *deliverySampler) deliverySampler {
	copy := *s
	copy.packets = maps.Clone(s.packets)
	return copy
}

func sendTestPacket(t *testing.T, s *deliverySampler, number congestion.PacketNumber, at monotime.Time, inFlight congestion.ByteCount) {
	t.Helper()
	require.NoError(t, s.sent(at, number, 1200, inFlight, true, false))
}

func ackTestPackets(t *testing.T, s *deliverySampler, at monotime.Time, numbers ...congestion.PacketNumber) rateSample {
	t.Helper()
	sample, err := s.ack(at, numbers, 0)
	require.NoError(t, err)
	return sample
}

func TestSamplerAfterSendContractAndZeroTimestamp(t *testing.T) {
	s := newTestSampler(t, 4)
	// The transport already added this packet: never add 1200 a second time.
	sendTestPacket(t, s, 0, 0, 1200)
	require.Equal(t, congestion.ByteCount(1200), s.packets[0].inFlight)
	sample := ackTestPackets(t, s, monotime.Time(100*time.Millisecond), 0)
	require.True(t, sample.valid)
	require.Equal(t, uint64(12000), sample.rate)
	require.Equal(t, uint64(1200), sample.delivered)
	require.Equal(t, congestion.ByteCount(1200), sample.inFlightAtSend)
	require.Equal(t, 100*time.Millisecond, sample.rtt)
	require.Equal(t, deliveryTotals{sent: 1200, delivered: 1200}, s.totals)
	require.Empty(t, s.packets)
}

func TestSamplerPureACKDoesNotEnterDeliveryAccounting(t *testing.T) {
	s := newTestSampler(t, 1)
	require.NoError(t, s.sent(0, 0, 40, 0, false, false))
	require.Empty(t, s.packets)
	require.Zero(t, s.totals)
	// Pure ACKs do not consume history capacity, even while history is full.
	sendTestPacket(t, s, 1, 1, 1200)
	require.NoError(t, s.sent(2, 2, 40, 1200, false, false))
	require.Len(t, s.packets, 1)
	sample := ackTestPackets(t, s, monotime.Time(time.Second), 0)
	require.False(t, sample.hasData)
	require.False(t, sample.valid)
	require.Equal(t, 1, sample.unknownPackets)
	require.Zero(t, s.totals.delivered)
}

func TestSamplerACKBatchOrderDuplicatesAndNewestPacket(t *testing.T) {
	orders := [][]congestion.PacketNumber{{0, 1, 2}, {2, 0, 1}, {1, 2, 0, 2, 0}}
	var first rateSample
	for i, order := range orders {
		original := append([]congestion.PacketNumber(nil), order...)
		s := newTestSampler(t, 4)
		sendTestPacket(t, s, 0, 0, 1200)
		sendTestPacket(t, s, 1, monotime.Time(time.Millisecond), 2400)
		sendTestPacket(t, s, 2, monotime.Time(time.Millisecond), 3600)
		sample := ackTestPackets(t, s, monotime.Time(100*time.Millisecond), order...)
		require.True(t, sample.valid)
		require.Equal(t, congestion.PacketNumber(2), sample.packet, "same timestamp: larger packet ID wins")
		require.Equal(t, uint64(3600), sample.newlyAcked)
		require.Equal(t, uint64(36000), sample.rate)
		require.Equal(t, uint64(3600), s.totals.delivered)
		if i == 0 {
			first = sample
		} else {
			require.Equal(t, first, sample, "sample must not depend on batch order or duplicate IDs")
		}
		require.Equal(t, original, order, "input is caller-owned")
		again := ackTestPackets(t, s, monotime.Time(200*time.Millisecond), order...)
		require.False(t, again.hasData)
		require.Zero(t, again.newlyAcked)
		require.Equal(t, uint64(3600), s.totals.delivered)
	}
}

func TestSamplerACKCompressionIsLimitedBySendInterval(t *testing.T) {
	s := newTestSampler(t, 4)
	sendTestPacket(t, s, 0, 0, 1200)
	sendTestPacket(t, s, 1, monotime.Time(100*time.Millisecond), 2400)
	ackTestPackets(t, s, monotime.Time(time.Second), 0)
	// Prior ACK at 1s; the new packet's send history spans two seconds.
	// Its ACK arrives only 1.1s after the previous ACK. Use 2s, not 1.1s.
	sendTestPacket(t, s, 2, monotime.Time(2*time.Second), 2400)
	sample := ackTestPackets(t, s, monotime.Time(2100*time.Millisecond), 2)
	require.True(t, sample.valid)
	require.Equal(t, 2*time.Second, sample.sendElapsed)
	require.Equal(t, 1100*time.Millisecond, sample.ackElapsed)
	require.Equal(t, 2*time.Second, sample.interval)
	require.Equal(t, uint64(600), sample.rate)
}

func TestSamplerSelectsNewestSendSnapshotAfterPriorACKs(t *testing.T) {
	s := newTestSampler(t, 8)
	sendTestPacket(t, s, 0, 0, 1200)
	ackTestPackets(t, s, monotime.Time(100*time.Millisecond), 0)
	sendTestPacket(t, s, 1, monotime.Time(110*time.Millisecond), 1200)
	sendTestPacket(t, s, 2, monotime.Time(120*time.Millisecond), 2400)
	ackTestPackets(t, s, monotime.Time(210*time.Millisecond), 1)
	sendTestPacket(t, s, 3, monotime.Time(220*time.Millisecond), 2400)
	sample := ackTestPackets(t, s, monotime.Time(320*time.Millisecond), 3, 2)
	require.True(t, sample.valid)
	require.Equal(t, congestion.PacketNumber(3), sample.packet)
	require.Equal(t, uint64(2400), sample.priorDelivered)
	require.Equal(t, uint64(2400), sample.delivered)
	require.Equal(t, uint64(2400), sample.newlyAcked)
	require.Equal(t, uint64(4800), s.totals.delivered)
	require.Equal(t, 110*time.Millisecond, sample.interval)
}

func TestSamplerIdleRestartResetsOnlySamplingClocks(t *testing.T) {
	s := newTestSampler(t, 4)
	sendTestPacket(t, s, 0, monotime.Time(time.Second), 1200)
	ackTestPackets(t, s, monotime.Time(1100*time.Millisecond), 0)
	sendTestPacket(t, s, 1, monotime.Time(time.Hour), 1200)
	sample := ackTestPackets(t, s, monotime.Time(time.Hour+100*time.Millisecond), 1)
	require.True(t, sample.valid)
	require.Equal(t, uint64(12000), sample.rate)
	require.Equal(t, uint64(1200), sample.delivered)
	require.Equal(t, uint64(2400), s.totals.delivered)
	require.False(t, sample.appLimited, "an empty flight alone is not proof of application limitation")
}

func TestSamplerAppLimitedUsesDeliveredByteWaterline(t *testing.T) {
	s := newTestSampler(t, 8)
	sendTestPacket(t, s, 0, 0, 1200)
	require.NoError(t, s.markAppLimited(1200))
	require.Equal(t, uint64(1200), s.appLimitedEnd)
	sendTestPacket(t, s, 1, 1, 2400)
	first := ackTestPackets(t, s, monotime.Time(time.Second), 0)
	require.False(t, first.appLimited, "flag is snapshotted when sent, not when ACKed")
	require.Equal(t, uint64(1200), s.appLimitedEnd, "equality does not clear the bubble")
	second := ackTestPackets(t, s, monotime.Time(2*time.Second), 1)
	require.True(t, second.appLimited)
	require.Zero(t, s.appLimitedEnd)
	sendTestPacket(t, s, 2, monotime.Time(3*time.Second), 1200)
	require.False(t, s.packets[2].appLimited)
	// A completely idle, never-delivered connection still needs a nonzero marker.
	empty := newTestSampler(t, 1)
	require.NoError(t, empty.markAppLimited(0))
	require.Equal(t, uint64(1), empty.appLimitedEnd)
}

func TestSamplerLossOnlyProbeLossAndLateACK(t *testing.T) {
	s := newTestSampler(t, 8)
	sendTestPacket(t, s, 0, 0, 1200)
	require.NoError(t, s.sent(1, 1, 1400, 2600, true, true))
	sendTestPacket(t, s, 2, 2, 3800)
	ordinary, err := s.lost(0)
	require.NoError(t, err)
	require.True(t, ordinary.known)
	require.True(t, ordinary.newlyLost)
	require.True(t, ordinary.congestion)
	require.Equal(t, congestion.ByteCount(1200), ordinary.state.inFlight)
	probe, err := s.lost(1)
	require.NoError(t, err)
	require.True(t, probe.newlyLost)
	require.False(t, probe.congestion)
	repeated, err := s.lost(0)
	require.NoError(t, err)
	require.False(t, repeated.newlyLost)
	unknown, err := s.lost(99)
	require.NoError(t, err)
	require.False(t, unknown.known)
	require.Equal(t, uint64(2600), s.totals.lost)
	require.Equal(t, uint64(1200), s.totals.congestionLost)
	empty := ackTestPackets(t, s, monotime.Time(time.Second))
	require.False(t, empty.valid, "a loss-only event cannot invent a delivery rate")
	require.Zero(t, s.totals.delivered)
	sample := ackTestPackets(t, s, monotime.Time(2*time.Second), 2)
	require.Equal(t, uint64(2600), sample.lostSinceSent)
	require.Equal(t, uint64(1200), sample.congestionLostSinceSent)
	late := ackTestPackets(t, s, monotime.Time(3*time.Second), 0, 1)
	require.Equal(t, uint64(2600), late.spuriousAcked)
	require.Equal(t, uint64(3800), s.totals.delivered)
	require.Equal(t, uint64(2600), s.totals.lost, "late ACKs don't undo lifetime loss accounting")
	require.Empty(t, s.packets)
}

func TestSamplerDiscardAndTransportRetirementAreNotLoss(t *testing.T) {
	s := newTestSampler(t, 8)
	for number := congestion.PacketNumber(0); number < 4; number++ {
		sendTestPacket(t, s, number, monotime.Time(number), 1200*(congestion.ByteCount(number)+1))
	}
	s.discard(1)
	s.discard(1) // Idempotent, just like repeated retirement notifications.
	s.forgetBefore(3)
	require.Len(t, s.packets, 1)
	require.Contains(t, s.packets, congestion.PacketNumber(3))
	require.Zero(t, s.totals.lost)
	require.Zero(t, s.totals.delivered)
	sample := ackTestPackets(t, s, monotime.Time(time.Second), 0, 3)
	require.True(t, sample.hasData)
	require.False(t, sample.valid, "a batch with a missing send snapshot cannot estimate a rate")
	require.Equal(t, uint64(1200), sample.newlyAcked)
	require.Equal(t, 1, sample.unknownPackets)
	require.Zero(t, sample.rate)
}

func TestSamplerCapacityFailureIsExplicitAndAtomic(t *testing.T) {
	s := newTestSampler(t, 1)
	sendTestPacket(t, s, 0, 0, 1200)
	_, err := s.lost(0)
	require.NoError(t, err)
	before := snapshotSampler(s)
	require.ErrorIs(t, s.sent(1, 1, 1200, 1200, true, false), errSampleCapacity)
	require.Equal(t, before, *s)
	require.Contains(t, s.packets, congestion.PacketNumber(0), "don't silently evict a possible spurious-loss ACK")
	s.discard(0)
	sendTestPacket(t, s, 1, 1, 1200)
	require.Len(t, s.packets, 1)
}

func TestSamplerNoAnchorAndInvalidIntervals(t *testing.T) {
	s := newTestSampler(t, 8)
	// Installation while the previous controller still has data in flight.
	sendTestPacket(t, s, 10, monotime.Time(time.Second), 2400)
	first := ackTestPackets(t, s, monotime.Time(1100*time.Millisecond), 10)
	require.True(t, first.hasData)
	require.False(t, first.valid, "don't invent a pre-installation delivery timestamp")
	sendTestPacket(t, s, 11, monotime.Time(1200*time.Millisecond), 2400)
	second := ackTestPackets(t, s, monotime.Time(1300*time.Millisecond), 11)
	require.True(t, second.valid, "a real ACK now supplies a sampling anchor")
	zero := newTestSampler(t, 1)
	sendTestPacket(t, zero, 0, 0, 1200)
	zeroSample := ackTestPackets(t, zero, 0, 0)
	require.False(t, zeroSample.valid)
	require.Zero(t, zeroSample.rate)
	short := newTestSampler(t, 1)
	sendTestPacket(t, short, 0, 0, 1200)
	tooShort, err := short.ack(monotime.Time(time.Millisecond), []congestion.PacketNumber{0}, 2*time.Millisecond)
	require.NoError(t, err)
	require.False(t, tooShort.valid, "an interval below min RTT is not a reliable sample")
	require.Zero(t, tooShort.rate)
	require.Equal(t, uint64(1200), short.totals.delivered, "rejected rate is still real delivered data")
}

func TestSamplerInvalidInputDoesNotMutateState(t *testing.T) {
	_, err := newDeliverySampler(0)
	require.ErrorIs(t, err, errInvalidSampleInput)
	s := newTestSampler(t, 4)
	sendTestPacket(t, s, 10, monotime.Time(time.Second), 1200)
	before := snapshotSampler(s)
	for _, call := range []func() error{
		func() error { return s.sent(0, 11, 1200, 1200, true, false) },
		func() error { return s.sent(monotime.Time(time.Second), 10, 1200, 1200, true, false) },
		func() error { return s.sent(monotime.Time(time.Second), -1, 1200, 1200, true, false) },
		func() error { return s.sent(monotime.Time(time.Second), 11, 0, 0, true, false) },
		func() error { return s.sent(monotime.Time(time.Second), 11, 1200, -1, true, false) },
		func() error { return s.sent(monotime.Time(time.Second), 11, 1200, 1199, true, false) },
		func() error { return s.sent(monotime.Time(time.Second), 11, 40, 0, false, true) },
		func() error { return s.markAppLimited(-1) },
		func() error { _, err := s.lost(-1); return err },
		func() error { _, err := s.ack(0, []congestion.PacketNumber{10}, 0); return err },
		func() error {
			_, err := s.ack(monotime.Time(time.Second), []congestion.PacketNumber{10, -1}, 0)
			return err
		},
		func() error {
			_, err := s.ack(monotime.Time(time.Second), []congestion.PacketNumber{10}, -1)
			return err
		},
	} {
		require.ErrorIs(t, call(), errInvalidSampleInput)
		require.Equal(t, before, *s)
	}
}

func TestSamplerCounterOverflowDoesNotWrapOrCommit(t *testing.T) {
	s := newTestSampler(t, 4)
	s.totals.sent = math.MaxUint64 - 1199
	require.ErrorIs(t, s.sent(0, 0, 1200, 1200, true, false), errSampleOverflow)
	require.False(t, s.hasSent)
	require.Empty(t, s.packets)
	s.totals.sent = 0
	sendTestPacket(t, s, 0, 0, 1200)
	s.totals.lost = math.MaxUint64 - 1199
	_, err := s.lost(0)
	require.ErrorIs(t, err, errSampleOverflow)
	require.False(t, s.packets[0].declaredLost)
	s.totals.lost = 0
	s.totals.congestionLost = math.MaxUint64 - 1199
	_, err = s.lost(0)
	require.ErrorIs(t, err, errSampleOverflow)
	require.Zero(t, s.totals.lost)
	s.totals.congestionLost = 0
	s.totals.delivered = math.MaxUint64 - 1199
	_, err = s.ack(monotime.Time(time.Second), []congestion.PacketNumber{0}, 0)
	require.ErrorIs(t, err, errSampleOverflow)
	require.Len(t, s.packets, 1)
	require.ErrorIs(t, s.markAppLimited(1200), errSampleOverflow)
	require.Zero(t, s.appLimitedEnd)
}

func TestBytesPerSecondAgainstBigIntegerReference(t *testing.T) {
	for _, tc := range []struct {
		bytes uint64
		time  time.Duration
	}{
		{0, time.Second},
		{1200, 100 * time.Millisecond},
		{1 << 50, time.Second},
		{math.MaxUint64, time.Second},
		{math.MaxUint64, time.Duration(math.MaxInt64)},
		{math.MaxUint64, 1},
		{1, 0},
		{1, -1},
	} {
		var expected uint64
		if tc.time > 0 {
			n := new(big.Int).SetUint64(tc.bytes)
			n.Mul(n, big.NewInt(int64(time.Second)))
			n.Div(n, big.NewInt(int64(tc.time)))
			if n.IsUint64() {
				expected = n.Uint64()
			} else {
				expected = math.MaxUint64
			}
		}
		require.Equal(t, expected, bytesPerSecond(tc.bytes, tc.time), "%+v", tc)
	}
}

func TestSamplerTimestampOriginAndDurationOverflow(t *testing.T) {
	s := newTestSampler(t, 4)
	start := monotime.Time(-time.Second)
	sendTestPacket(t, s, 0, start, 1200)
	sample := ackTestPackets(t, s, start.Add(100*time.Millisecond), 0)
	require.True(t, sample.valid, "the monotonic clock's origin need not be positive")
	require.Equal(t, uint64(12000), sample.rate)
	wide := newTestSampler(t, 4)
	sendTestPacket(t, wide, 0, monotime.Time(math.MinInt64), 1200)
	before := snapshotSampler(wide)
	_, err := wide.ack(monotime.Time(math.MaxInt64), []congestion.PacketNumber{0}, 0)
	require.ErrorIs(t, err, errInvalidSampleInput)
	require.Equal(t, before, *wide)
	_, valid := sampleElapsed(0, 1)
	require.False(t, valid)
	// An old sampling anchor can overflow even when the packet RTT is valid.
	sendTestPacket(t, wide, 1, monotime.Time(math.MaxInt64-1), 2400)
	invalid := ackTestPackets(t, wide, monotime.Time(math.MaxInt64), 1)
	require.True(t, invalid.hasData)
	require.False(t, invalid.valid)
	require.Zero(t, invalid.rate)
}
