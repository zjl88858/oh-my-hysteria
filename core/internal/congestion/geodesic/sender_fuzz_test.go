// SPDX-License-Identifier: MIT-0

package geodesic

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

func FuzzSenderEvents(f *testing.F) {
	f.Add([]byte{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add([]byte{0, 1, 0, 1, 0, 1, 8, 0, 0, 1, 9, 9, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 512 {
			data = data[:512]
		}
		s := NewSender(1200)
		pn := 0
		var now time.Duration
		for _, b := range data {
			now += (time.Duration(b) + 1) * time.Millisecond
			flight := 0
			oldest := -1
			for n, p := range s.sampler.packets {
				if !p.declaredLost {
					flight += int(p.bytes)
				}
				if oldest < 0 || int(n) < oldest {
					oldest = int(n)
				}
			}
			switch b % 10 {
			case 0, 9:
				send(s, pn, now, flight+1200, b == 9)
				pn++
			case 1:
				if oldest >= 0 {
					ack(s, now, (time.Duration(b)+1)*time.Millisecond, max(0, flight-1200), oldest)
				}
			case 2:
				if oldest >= 0 {
					lose(s, now, max(0, flight-1200), oldest)
				}
			case 3:
				s.OnApplicationLimited(monotime.Time(now), congestion.ByteCount(flight))
			case 4:
				s.OnPacketRemoved(congestion.SpaceApplication, congestion.PacketNumber(oldest), congestion.RemovalPTO)
			case 5:
				s.OnSpuriousPacket(congestion.PacketNumber(oldest), monotime.Time(now))
			case 6:
				s.OnPathReset(monotime.Time(now), 1200)
				pn = 0
			case 7:
				s.SetMaxDatagramSize(congestion.ByteCount(s.size + 1))
			case 8:
				s.OnCongestionEventContext(congestion.CongestionEventContext{Time: monotime.Time(now), Space: congestion.SpaceApplication, ApplicationBytesInFlight: congestion.ByteCount(flight), ECNCongestion: true})
			}
			snap := s.Snapshot()
			if s.cwnd < s.floor() || s.cwnd > s.maximum() || s.rate == 0 || s.phase > 7 || len(s.sampler.packets) > historyCapacity || (s.geo.samples > 0 && (s.geo.minimum < 1 || s.geo.minimum > maxRTTUs || s.geo.x < 1024 || s.geo.x > maxRTTUs<<10)) {
				t.Fatalf("invalid state: %+v", snap)
			}
		}
	})
}
