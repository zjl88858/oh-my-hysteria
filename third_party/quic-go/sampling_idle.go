// SPDX-License-Identifier: MIT-0

package quic

import (
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
)

func (s *SendStream) samplingHasPendingData() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.shutdownErr != nil || (s.resetErr != nil && s.writeOffset >= s.reliableOffset()) {
		return false
	}
	return len(s.dataForWriting) != 0 || s.nextFrame != nil || len(s.retransmissionQueue) != 0 ||
		(s.finishedWriting && !s.finSent)
}

func (f *framer) samplingHasPendingData() bool {
	if f.HasData() {
		return true
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	for id, stream := range f.samplingStreams {
		s, ok := stream.(interface{ samplingHasPendingData() bool })
		if !ok || s.samplingHasPendingData() {
			return true
		}
		delete(f.samplingStreams, id)
	}
	return false
}

func (c *Conn) maybeNotifyApplicationLimited(now monotime.Time) {
	if !c.advancedCongestion.Load() || !c.handshakeConfirmed {
		return
	}
	q, ok := c.sendQueue.(*sendQueue)
	if !ok || q.pending.Load() != 0 {
		return
	}
	if c.framer.samplingHasPendingData() || c.retransmissionQueue.HasData(protocol.Encryption1RTT) ||
		(c.oneRTTStream != nil && c.oneRTTStream.HasData()) || (c.datagramQueue != nil && c.datagramQueue.Peek() != nil) {
		return
	}
	if h, ok := c.sentPacketHandler.(interface{ NotifyApplicationLimited(monotime.Time) }); ok {
		h.NotifyApplicationLimited(now)
	}
}

func (c *Conn) samplingSendQueueIdle() {
	if c.advancedCongestion.Load() {
		c.scheduleSending()
	}
}
