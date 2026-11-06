// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"container/list"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestServoTwoContainerReservationAndEightRecordLimit(t *testing.T) {
	for oldLeft := 1; oldLeft <= 64; oldLeft++ {
		queue := list.New()
		first := &servoMessage{id: 1, data: make([]byte, 640-oldLeft), accepted: servoTestNow}
		second := &servoMessage{id: 2, data: make([]byte, 1200), accepted: servoTestNow.Add(time.Microsecond)}
		queue.PushBack(first)
		queue.PushBack(second)
		draws := 0
		p := servoPacker{wait: 300 * time.Microsecond, sample: func() (int, error) { draws++; return 640, nil }}
		require.NoError(t, p.fill(queue))
		one := p.take(servoTestNow)
		require.NotNil(t, one)
		require.Equal(t, 1, one.count)
		require.Zero(t, second.planned, "must not put %d bytes in a third-container trap", oldLeft)
		require.Equal(t, 2, draws)
		require.NoError(t, p.fill(queue))
		two := p.take(servoTestNow)
		require.NotNil(t, two)
		require.Equal(t, 3, draws, "retain the pre-drawn next capacity")
		require.Equal(t, 640, two.data)
		require.NoError(t, p.fill(queue))
		require.Nil(t, p.take(servoTestNow))
		three := p.take(servoTestNow.Add(time.Millisecond))
		require.NotNil(t, three)
		require.Equal(t, 560, three.data)
		require.Equal(t, 2, second.parts)
		require.Equal(t, 3, draws)
	}
	queue := list.New()
	for i := range 9 {
		queue.PushBack(&servoMessage{id: uint32(i + 1), data: []byte{1}, accepted: servoTestNow})
	}
	p := servoPacker{wait: time.Second, sample: func() (int, error) { return 1100, nil }}
	require.NoError(t, p.fill(queue))
	packet := p.take(servoTestNow)
	require.NotNil(t, packet)
	require.Equal(t, 8, packet.count)
}

func TestServoPackerPreservesBoundaryDeadlineAndPayload(t *testing.T) {
	rng := rand.New(rand.NewPCG(9, 7))
	for range 100 {
		queue := list.New()
		original := make(map[uint32][]byte)
		for i := range 64 {
			data := bytes.Repeat([]byte{byte(i)}, 1+rng.IntN(1200))
			m := &servoMessage{id: uint32(i + 1), data: data, accepted: servoTestNow.Add(time.Duration(i) * time.Nanosecond)}
			queue.PushBack(m)
			original[m.id] = bytes.Clone(data)
		}
		p := servoPacker{wait: 200 * time.Microsecond, sample: func() (int, error) { return 640 + rng.IntN(461), nil }}
		got := make(map[uint32][]byte)
		parts := make(map[uint32]int)
		for n := 0; n < 130; n++ {
			require.NoError(t, p.fill(queue))
			packet := p.take(servoTestNow.Add(time.Second))
			if packet == nil {
				break
			}
			require.Greater(t, packet.count, 0)
			require.LessOrEqual(t, packet.count, 8)
			require.LessOrEqual(t, packet.data, 1100)
			require.LessOrEqual(t, servoOverhead+10*packet.count+packet.data, 1232)
			seen := make(map[uint32]bool)
			for i := range packet.count {
				r := packet.records[i]
				require.False(t, seen[r.message.id])
				seen[r.message.id] = true
				require.Equal(t, len(got[r.message.id]), r.offset)
				got[r.message.id] = append(got[r.message.id], r.message.data[r.offset:r.offset+r.size]...)
				parts[r.message.id]++
				require.LessOrEqual(t, parts[r.message.id], 2)
			}
		}
		require.Equal(t, original, got)
	}
}

func FuzzServoPacker(f *testing.F) {
	f.Add([]byte{0, 255, 1, 2, 200, 33})
	f.Fuzz(func(t *testing.T, data []byte) {
		queue := list.New()
		data = data[:min(64, len(data))]
		for i, b := range data {
			queue.PushBack(&servoMessage{id: uint32(i + 1), data: make([]byte, 1+int(b)*1200/255), accepted: servoTestNow})
		}
		p := servoPacker{sample: func() (int, error) { return 640, nil }}
		total := 0
		for range 130 {
			require.NoError(t, p.fill(queue))
			packet := p.take(servoTestNow)
			if packet == nil {
				break
			}
			total += packet.data
			for i := range packet.count {
				require.LessOrEqual(t, packet.records[i].message.parts, 2)
			}
		}
		want := 0
		for _, b := range data {
			want += 1 + int(b)*1200/255
		}
		require.Equal(t, want, total)
	})
}
