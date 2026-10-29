// SPDX-License-Identifier: MIT-0

package copa

import (
	"time"

	"github.com/apernet/quic-go/monotime"
)

type observation struct {
	at  monotime.Time
	rtt time.Duration
}

// A monotone deque with a hard capacity. On overflow, discard the oldest
// candidate (possibly overestimating RTT), never extend an expired sample.
// Changing the window cannot resurrect samples discarded by a shorter window.
type minFilter struct {
	values []observation
	head   int
	count  int
}

const filterCapacity = 32768

func (f *minFilter) expire(now monotime.Time, window time.Duration) {
	for f.count > 0 && now.Sub(f.values[f.head].at) > window {
		f.head = (f.head + 1) % len(f.values)
		f.count--
	}
}

func (f *minFilter) add(now monotime.Time, rtt, window time.Duration) {
	f.expire(now, window)
	for f.count > 0 && f.values[(f.head+f.count-1)%len(f.values)].rtt >= rtt {
		f.count--
	}
	if f.count == len(f.values) && len(f.values) < filterCapacity {
		values := make([]observation, min(filterCapacity, max(64, 2*len(f.values))))
		for i := range f.count {
			values[i] = f.values[(f.head+i)%len(f.values)]
		}
		f.values, f.head = values, 0
	}
	if f.count == filterCapacity {
		f.head = (f.head + 1) % len(f.values)
		f.count--
	}
	f.values[(f.head+f.count)%len(f.values)] = observation{now, rtt}
	f.count++
}

func (f *minFilter) get() time.Duration {
	if f.count == 0 {
		return 0
	}
	return f.values[f.head].rtt
}
