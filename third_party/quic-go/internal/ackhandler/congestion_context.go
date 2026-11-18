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

// Publish the final flight counters before retiring the controller's samples.
// A spurious-only ACK has no fresh RTT or delivered bytes, but still undoes loss.
func (h *sentPacketHandler) finishAdvancedAck(cc congestion.SendAlgorithmWithDebugInfos, level protocol.EncryptionLevel, now monotime.Time, prior protocol.ByteCount, rttUpdated, ecn bool, spurious []protocol.PacketNumber) {
	if a := advancedControl(cc); a != nil {
		if len(h.ackedPacketsInfo) != 0 || len(h.lostPacketsInfo) != 0 || rttUpdated || ecn {
			a.OnCongestionEventContext(public.CongestionEventContext{
				Time: now, Space: packetSpace(level), PriorBytesInFlight: public.ByteCount(prior),
				BytesInFlight: public.ByteCount(h.bytesInFlight), ApplicationBytesInFlight: public.ByteCount(h.applicationBytesInFlight),
				Acked: h.ackedPacketsInfo, Lost: h.lostPacketsInfo, RTT: h.rttStats.LatestRTT(),
				RTTUpdated: rttUpdated, ECNCongestion: ecn,
			})
		}
		for _, pn := range spurious {
			a.OnSpuriousPacket(public.PacketNumber(pn), now)
		}
	}
	h.flushHistoryRemovals()
}

func (h *sentPacketHandler) CongestionSendQuantum() protocol.ByteCount {
	if a := advancedControl(h.getCongestionControl()); a != nil {
		if q, ok := a.(interface{ SendQuantum() public.ByteCount }); ok {
			return protocol.ByteCount(q.SendQuantum())
		}
	}
	return 0
}
