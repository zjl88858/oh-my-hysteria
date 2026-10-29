// SPDX-License-Identifier: MIT-0

package congestion

import (
	"time"

	"github.com/apernet/quic-go/monotime"
)

type PacketSpace uint8

const (
	SpaceInitial PacketSpace = iota
	SpaceHandshake
	SpaceApplication
)

type SentPacketContext struct {
	Time                                           monotime.Time
	Space                                          PacketSpace
	PacketNumber                                   PacketNumber
	Bytes, BytesInFlight, ApplicationBytesInFlight ByteCount
	AckEliciting, MTUProbe                         bool
}

type CongestionEventContext struct {
	Time                                                        monotime.Time
	Space                                                       PacketSpace
	PriorBytesInFlight, BytesInFlight, ApplicationBytesInFlight ByteCount
	Acked                                                       []AckedPacketInfo
	Lost                                                        []LostPacketInfo
	RTT                                                         time.Duration
	RTTUpdated, ECNCongestion                                   bool
}

type RemovalReason uint8

const (
	RemovalKeys RemovalReason = iota
	RemovalPTO
	RemovalRetry
	RemovalHistory
)

// AdvancedControl is opt-in. Packet and congestion bookkeeping is performed
// exclusively through these richer methods by its implementation; the legacy
// per-packet methods required by CongestionControl must not bookkeep again.
// Calls are serialized on the connection loop, after installation publication.
// Borrowed ACK/loss slices must not be retained beyond the callback.
type AdvancedControl interface {
	CongestionControl
	OnPacketSentContext(SentPacketContext)
	OnCongestionEventContext(CongestionEventContext)
	OnPacketRemoved(PacketSpace, PacketNumber, RemovalReason)
	OnSpuriousPacket(PacketNumber, monotime.Time)
	OnApplicationLimited(monotime.Time, ByteCount)
	OnPathReset(monotime.Time, ByteCount)
}
