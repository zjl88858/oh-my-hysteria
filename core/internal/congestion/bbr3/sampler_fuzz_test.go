// SPDX-License-Identifier: MIT-0

package bbr3

import (
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func FuzzBytesPerSecond(f *testing.F) {
	f.Add(uint64(1200), int64(100*time.Millisecond))
	f.Add(uint64(math.MaxUint64), int64(1))
	f.Add(uint64(1), int64(0))
	f.Add(uint64(1), int64(-1))
	f.Fuzz(func(t *testing.T, bytes uint64, ns int64) {
		got := bytesPerSecond(bytes, time.Duration(ns))
		if ns <= 0 {
			require.Zero(t, got)
			return
		}
		want := new(big.Int).SetUint64(bytes)
		want.Mul(want, big.NewInt(int64(time.Second)))
		want.Div(want, big.NewInt(ns))
		if want.IsUint64() {
			require.Equal(t, want.Uint64(), got)
		} else {
			require.Equal(t, uint64(math.MaxUint64), got)
		}
	})
}

func FuzzSamplerLifecycle(f *testing.F) {
	f.Add([]byte{0, 0, 1, 2, 5, 4, 0, 2, 3})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{5, 5, 5, 2, 1, 4, 3, 0, 0, 2})
	f.Fuzz(func(t *testing.T, events []byte) {
		if len(events) > 512 {
			events = events[:512]
		}
		s := newTestSampler(t, 8)
		var next congestion.PacketNumber
		for i, event := range events {
			at := monotime.Time(time.Duration(i+1) * time.Millisecond)
			var number congestion.PacketNumber
			if next > 0 {
				number = congestion.PacketNumber(event/6) % next
			}
			switch event % 6 {
			case 0:
				err := s.sent(at, next, 1200, 1200, true, event&0x80 != 0)
				if err != nil {
					require.ErrorIs(t, err, errSampleCapacity)
				}
				next++
			case 1:
				_, err := s.lost(number)
				require.NoError(t, err)
			case 2:
				before := s.totals.delivered
				sample, err := s.ack(at, []congestion.PacketNumber{number, number}, 0)
				require.NoError(t, err)
				require.Equal(t, before+sample.newlyAcked, s.totals.delivered)
				if sample.valid {
					require.True(t, sample.hasData)
					require.Greater(t, sample.interval, time.Duration(0))
					require.Equal(t, bytesPerSecond(sample.delivered, sample.interval), sample.rate)
				} else {
					require.Zero(t, sample.rate)
				}
			case 3:
				if event&0x80 != 0 {
					s.forgetBefore(number)
				} else {
					s.discard(number)
				}
			case 4:
				require.NoError(t, s.markAppLimited(congestion.ByteCount(len(s.packets)*1200)))
			case 5:
				require.NoError(t, s.sent(at, next, 40, 0, false, false))
				next++
			}
			require.LessOrEqual(t, len(s.packets), s.capacity)
			require.LessOrEqual(t, s.totals.delivered, s.totals.sent)
			require.LessOrEqual(t, s.totals.lost, s.totals.sent)
			require.LessOrEqual(t, s.totals.congestionLost, s.totals.lost)
		}
	})
}
