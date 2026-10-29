// SPDX-License-Identifier: MIT-0

package ackhandler

import (
	public "github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/congestion"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
)

func advancedControl(cc congestion.SendAlgorithmWithDebugInfos) public.AdvancedControl {
	if a, ok := cc.(interface{ Advanced() public.AdvancedControl }); ok {
		return a.Advanced()
	}
	return nil
}

func packetSpace(level protocol.EncryptionLevel) public.PacketSpace {
	switch level {
	case protocol.EncryptionInitial:
		return public.SpaceInitial
	case protocol.EncryptionHandshake:
		return public.SpaceHandshake
	default:
		return public.SpaceApplication
	}
}

func (h *sentPacketHandler) notifyRemoval(level protocol.EncryptionLevel, pn protocol.PacketNumber, reason public.RemovalReason) {
	if cc := advancedControl(h.getCongestionControl()); cc != nil {
		cc.OnPacketRemoved(packetSpace(level), public.PacketNumber(pn), reason)
	}
}

// Called only after the packetizer established no unsent stream (including
// flow-control-blocked data), DATAGRAM, crypto or retransmission data and no
// queued/in-progress lower-layer write. A pacing wait alone never calls this.
func (h *sentPacketHandler) NotifyApplicationLimited(now monotime.Time) {
	cc := h.getCongestionControl()
	if a := advancedControl(cc); a != nil && h.bytesInFlight < cc.GetCongestionWindow() && h.numProbesToSend == 0 {
		a.OnApplicationLimited(now, public.ByteCount(h.applicationBytesInFlight))
	}
}

func (h *sentPacketHandler) flushHistoryRemovals() {
	for _, pn := range h.pendingHistoryRemovals {
		h.notifyRemoval(protocol.Encryption1RTT, pn, public.RemovalHistory)
	}
	h.pendingHistoryRemovals = nil
}

func (h *sentPacketHandler) CongestionSendQuantum() protocol.ByteCount {
	if a := advancedControl(h.getCongestionControl()); a != nil {
		if q, ok := a.(interface{ SendQuantum() public.ByteCount }); ok {
			return protocol.ByteCount(q.SendQuantum())
		}
	}
	return 0
}
