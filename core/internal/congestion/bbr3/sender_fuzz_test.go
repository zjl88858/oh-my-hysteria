// SPDX-License-Identifier: MIT-0

package bbr3

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

func FuzzSenderEvents(f *testing.F) {
	f.Add([]byte{0, 0, 1, 2, 0, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{0, 1, 0, 1, 0, 1, 0, 1, 9, 9, 0, 1})
	f.Add([]byte{1, 0, 1, 2, 3, 4, 5, 6, 7})
	f.Add([]byte{2, 0, 0, 1, 1, 2, 6, 7, 9})
	f.Fuzz(func(t *testing.T, events []byte) {
		if len(events) > 512 {
			events = events[:512]
		}
		profiles := []Profile{ProfileStandard, ProfileConservative, ProfileAggressive}
		profile := ProfileStandard
		if len(events) > 0 {
			profile = profiles[int(events[0])%len(profiles)]
		}
		s := NewSenderWithProfile(1200, profile)
		pn := 0
		at := time.Duration(0)
		for _, event := range events {
			at += (time.Duration(event) + 1) * time.Millisecond
			flight := 0
			target := -1
			for n, p := range s.sampler.packets {
				if !p.declaredLost {
					flight += int(p.bytes)
				}
				if target < 0 || int(n) < target {
					target = int(n)
				}
			}
			switch event % 10 {
			case 0, 9:
				senderSend(s, pn, at, flight+1200, event == 9)
				pn++
			case 1:
				if target >= 0 {
					senderAck(s, at, max(0, flight-1200), target)
				}
			case 2:
				if target >= 0 {
					senderLoss(s, at, max(0, flight-1200), target)
				}
			case 3:
				if target >= 0 {
					s.OnPacketRemoved(congestion.SpaceApplication, congestion.PacketNumber(target), congestion.RemovalHistory)
				}
			case 4:
				if target >= 0 {
					s.OnSpuriousPacket(congestion.PacketNumber(target), monotime.Time(at))
				}
			case 5:
				s.OnApplicationLimited(monotime.Time(at), congestion.ByteCount(flight))
			case 6:
				s.OnCongestionEventContext(congestion.CongestionEventContext{Time: monotime.Time(at), Space: congestion.SpaceApplication, ECNCongestion: true})
			case 7:
				s.OnPathReset(monotime.Time(at), 1200)
			case 8:
				s.SetMaxDatagramSize(congestion.ByteCount(s.size))
			}
			snap := s.Snapshot()
			if snap.Profile != profile {
				t.Fatalf("profile changed across lifecycle: %s -> %s", profile, snap.Profile)
			}
			if snap.Cwnd < s.floor() || snap.Cwnd > s.maximum() || snap.PacingRate == 0 || len(s.sampler.packets) > historyCapacity || len(s.undo.lost) > 64 || len(s.roundLost) > historyCapacity {
				t.Fatalf("invalid sender bounds: %+v", snap)
			}
			if snap.SamplingErrors != 0 {
				t.Fatalf("valid transport trace reset sampler: %+v", snap)
			}
		}
	})
}
