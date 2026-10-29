// SPDX-License-Identifier: MIT-0

package copa

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
			oldest := -1
			for n := range s.packets {
				if oldest < 0 || int(n) < oldest {
					oldest = int(n)
				}
			}
			switch b % 10 {
			case 0, 9:
				send(s, pn, now, b == 9)
				pn++
			case 1:
				if oldest >= 0 {
					ack(s, now, (time.Duration(b)+1)*time.Millisecond, oldest)
				}
			case 2:
				if oldest >= 0 {
					s.OnCongestionEventContext(congestion.CongestionEventContext{Space: congestion.SpaceApplication, Time: monotime.Time(now), Lost: []congestion.LostPacketInfo{{PacketNumber: congestion.PacketNumber(oldest)}}})
				}
			case 3:
				s.OnApplicationLimited(monotime.Time(now), 0)
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
				s.OnCongestionEventContext(congestion.CongestionEventContext{Space: congestion.SpaceApplication, Time: monotime.Time(now), ECNCongestion: true})
			}
			snap := s.Snapshot()
			if s.cwnd < s.floor() || s.cwnd > s.maximum() || snap.PacingRate == 0 || snap.Delta < .04 || snap.Delta > .5 || len(s.packets) > historyCapacity || snap.Velocity < 1 || snap.Velocity > 1<<20 {
				t.Fatalf("invalid model: %+v", snap)
			}
		}
	})
}
