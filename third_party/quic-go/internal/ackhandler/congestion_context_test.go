// SPDX-License-Identifier: MIT-0

package ackhandler

import (
	"testing"
	"time"

	public "github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

type contextRecorder struct {
	sent         []public.SentPacketContext
	events       []public.CongestionEventContext
	removed      []public.PacketNumber
	reasons      []public.RemovalReason
	spurious     []public.PacketNumber
	resets, idle int
	order        []string
}

func (*contextRecorder) SetRTTStatsProvider(public.RTTStatsProvider)  {}
func (*contextRecorder) TimeUntilSend(public.ByteCount) monotime.Time { return 0 }
func (*contextRecorder) HasPacingBudget(monotime.Time) bool           { return true }
func (*contextRecorder) OnPacketSent(monotime.Time, public.ByteCount, public.PacketNumber, public.ByteCount, bool) {
}
func (*contextRecorder) CanSend(public.ByteCount) bool { return true }
func (*contextRecorder) MaybeExitSlowStart()           {}
func (*contextRecorder) OnPacketAcked(public.PacketNumber, public.ByteCount, public.ByteCount, monotime.Time) {
}
func (*contextRecorder) OnCongestionEvent(public.PacketNumber, public.ByteCount, public.ByteCount) {}
func (*contextRecorder) OnRetransmissionTimeout(bool)                                              {}
func (*contextRecorder) SetMaxDatagramSize(public.ByteCount)                                       {}
func (*contextRecorder) InSlowStart() bool                                                         { return true }
func (*contextRecorder) InRecovery() bool                                                          { return false }
func (*contextRecorder) GetCongestionWindow() public.ByteCount                                     { return 1200000 }
func (*contextRecorder) SendQuantum() public.ByteCount                                             { return 4800 }
func (r *contextRecorder) OnPacketSentContext(e public.SentPacketContext)                          { r.sent = append(r.sent, e) }
func (r *contextRecorder) OnCongestionEventContext(e public.CongestionEventContext) {
	e.Acked = append([]public.AckedPacketInfo(nil), e.Acked...)
	e.Lost = append([]public.LostPacketInfo(nil), e.Lost...)
	r.events = append(r.events, e)
	r.order = append(r.order, "event")
}
func (r *contextRecorder) OnPacketRemoved(_ public.PacketSpace, pn public.PacketNumber, reason public.RemovalReason) {
	r.removed = append(r.removed, pn)
	r.reasons = append(r.reasons, reason)
	r.order = append(r.order, "remove")
}
func (r *contextRecorder) OnSpuriousPacket(pn public.PacketNumber, _ monotime.Time) {
	r.spurious = append(r.spurious, pn)
}
func (r *contextRecorder) OnApplicationLimited(monotime.Time, public.ByteCount) { r.idle++ }
func (r *contextRecorder) OnPathReset(monotime.Time, public.ByteCount)          { r.resets++ }

func richHandler() (*sentPacketHandler, *contextRecorder) {
	h := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, false, false, nil, protocol.PerspectiveClient, false, nil, utils.DefaultLogger)
	r := &contextRecorder{}
	h.SetCongestionControl(r)
	return h.(*sentPacketHandler), r
}

func richSend(h *sentPacketHandler, at monotime.Time, level protocol.EncryptionLevel, probe bool) protocol.PacketNumber {
	pn := h.PopPacketNumber(level)
	h.SentPacket(at, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, level, protocol.ECNNon, 1200, probe, false)
	return pn
}

func TestAdvancedContextPacketSpacesAndFreshRTT(t *testing.T) {
	h, r := richHandler()
	now := monotime.Now()
	i := richSend(h, now, protocol.EncryptionInitial, false)
	a := richSend(h, now, protocol.Encryption0RTT, false)
	b := richSend(h, now, protocol.Encryption1RTT, true)
	require.Equal(t, public.SpaceInitial, r.sent[0].Space)
	require.Equal(t, public.ByteCount(1200), r.sent[0].BytesInFlight)
	require.Zero(t, r.sent[0].ApplicationBytesInFlight)
	require.Equal(t, public.SpaceApplication, r.sent[1].Space)
	require.Equal(t, public.ByteCount(2400), r.sent[2].ApplicationBytesInFlight)
	require.True(t, r.sent[2].MTUProbe)
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(a, b)}, protocol.Encryption1RTT, now.Add(100*time.Millisecond))
	require.NoError(t, err)
	e := r.events[len(r.events)-1]
	require.True(t, e.RTTUpdated)
	require.Len(t, e.Acked, 2)
	require.Equal(t, now, e.Acked[0].SentTime)
	require.True(t, e.Acked[1].MTUProbe)
	require.Equal(t, public.ByteCount(1200), e.BytesInFlight)
	require.Zero(t, e.ApplicationBytesInFlight)
	n := len(r.events)
	_, err = h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(a, b)}, protocol.Encryption1RTT, now.Add(110*time.Millisecond))
	require.NoError(t, err)
	require.Len(t, r.events, n)
	_, err = h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(i)}, protocol.EncryptionInitial, now.Add(120*time.Millisecond))
	require.NoError(t, err)
	require.Zero(t, h.bytesInFlight)
	require.Zero(t, h.applicationBytesInFlight)
	require.Equal(t, protocol.ByteCount(4800), h.CongestionSendQuantum())
}

func TestAdvancedContextLossOnlySpuriousAndRetirementOrdering(t *testing.T) {
	h, r := richHandler()
	now := monotime.Now()
	var pns []protocol.PacketNumber
	for range 70 {
		pns = append(pns, richSend(h, now, protocol.Encryption1RTT, false))
	}
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[69])}, protocol.Encryption1RTT, now.Add(100*time.Millisecond))
	require.NoError(t, err)
	require.NotEmpty(t, r.events[0].Lost)
	require.NotEmpty(t, r.removed)
	require.Equal(t, "event", r.order[0])
	require.Equal(t, "remove", r.order[1])
	require.Len(t, h.lostPackets.lostPackets, 64)
	// An ACK containing ONLY a formerly lost packet must not be ignored.
	late := pns[65]
	_, err = h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(late)}, protocol.Encryption1RTT, now.Add(120*time.Millisecond))
	require.NoError(t, err)
	require.Contains(t, r.spurious, public.PacketNumber(late))
	// Loss-timer-only notifications contain no stale ACKs and no stale RTT.
	h2, r2 := richHandler()
	richSend(h2, now, protocol.Encryption1RTT, false)
	h2.appDataPackets.largestAcked = 10
	h2.appDataPackets.lossTime = now.Add(time.Second)
	require.NoError(t, h2.OnLossDetectionTimeout(now.Add(time.Second)))
	require.Len(t, r2.events, 1)
	require.Empty(t, r2.events[0].Acked)
	require.False(t, r2.events[0].RTTUpdated)
	require.Len(t, r2.events[0].Lost, 1)
}

func TestAdvancedContextPTOKeysRetryMigrationAndIdle(t *testing.T) {
	h, r := richHandler()
	now := monotime.Now()
	richSend(h, now, protocol.EncryptionInitial, false)
	richSend(h, now, protocol.Encryption0RTT, false)
	h.DropPackets(protocol.Encryption0RTT, now)
	require.Contains(t, r.reasons, public.RemovalKeys)
	require.Zero(t, h.applicationBytesInFlight)
	richSend(h, now, protocol.Encryption1RTT, false)
	require.True(t, h.QueueProbePacket(protocol.Encryption1RTT))
	require.Contains(t, r.reasons, public.RemovalPTO)
	require.Empty(t, r.events) // PTO removal is not congestion loss
	h.NotifyApplicationLimited(now)
	require.Equal(t, 1, r.idle)
	h.numProbesToSend = 1
	h.NotifyApplicationLimited(now)
	require.Equal(t, 1, r.idle)
	h.numProbesToSend = 0
	h.ResetForRetry(now.Add(time.Millisecond))
	require.Equal(t, 1, r.resets)
	require.Zero(t, h.applicationBytesInFlight)
	richSend(h, now.Add(2*time.Millisecond), protocol.Encryption1RTT, false)
	h.MigratedPath(now.Add(3*time.Millisecond), 1200)
	require.Equal(t, 2, r.resets)
	require.Same(t, r, advancedControl(h.getCongestionControl()))
	require.Zero(t, h.applicationBytesInFlight)
}
