// SPDX-License-Identifier: MIT-0

package copa

import (
	"math"
	"testing"
	"time"

	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func TestMinFilterExpiryAndBounds(t *testing.T) {
	var f minFilter
	require.Zero(t, f.get())
	f.add(0, time.Millisecond, time.Second)
	f.add(1, 2*time.Millisecond, time.Second)
	require.Equal(t, time.Millisecond, f.get())
	f.expire(monotime.Time(time.Second), time.Second)
	require.Equal(t, time.Millisecond, f.get())
	f.expire(monotime.Time(time.Second+2), time.Second)
	require.Zero(t, f.get())
	for i := range filterCapacity * 2 {
		f.add(monotime.Time(i), time.Duration(i+1), time.Hour)
	}
	require.LessOrEqual(t, len(f.values), filterCapacity)
	f.add(monotime.Time(filterCapacity*2), time.Nanosecond, time.Hour)
	require.Equal(t, time.Nanosecond, f.get())
}

func TestArithmeticAndPacerEdges(t *testing.T) {
	require.Equal(t, uint64(math.MaxUint64), mulDiv(math.MaxUint64, math.MaxUint64, 1))
	require.Equal(t, uint64(math.MaxUint64), mulDiv(1, 1, 0))
	require.Equal(t, uint64(math.MaxUint64), add(math.MaxUint64, 1))
	var p pacer
	p.sent(100, 2400, 12000, 2400)
	require.Equal(t, int64(0), p.budget(0, 12000, 2400))
	require.Greater(t, p.deadline(1200, 12000), monotime.Time(100))
	p.sent(101, math.MaxUint64, 1, 2400)
	require.Equal(t, int64(-65536), p.credit)
	require.Greater(t, p.deadline(1200, 1), p.last)
}

func TestExpiredRTTDoesNotGrow(t *testing.T) {
	s := NewSender(1200)
	send(s, 0, 0, false)
	ack(s, time.Second, time.Millisecond, 0)
	send(s, 1, 2*time.Second, false)
	before := s.cwnd
	ack(s, 12*time.Second, 0, 1)
	require.Equal(t, before, s.cwnd)
	require.Zero(t, s.minRTT)
	require.Zero(t, s.standingRTT)
}
