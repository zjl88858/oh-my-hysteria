// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"encoding/binary"
	"net"
)

// Authenticated padding control: version marker4, target session16,
// cumulative recovered SOURCE count8. Counted as padding, never as a source,
// route proof, ARQ request or reason for a stand-alone response.
var tasmanFeedbackTag = []byte{'T', 'F', 'B', 1}

func (c *tasmanPacketConn) feedback(s *tasmanSender) []byte {
	p := c.rx.peers[c.routes[s.addr]]
	if p == nil || p.recovered == 0 {
		return nil
	}
	b := make([]byte, 28)
	copy(b, tasmanFeedbackTag)
	copy(b[4:20], p.session[:])
	binary.BigEndian.PutUint64(b[20:], p.recovered)
	return b
}

func (c *tasmanPacketConn) acceptFeedback(addr net.Addr, padding []byte) {
	if len(padding) != 28 || !bytes.Equal(padding[:4], tasmanFeedbackTag) {
		return
	}
	ap, _, ok := blinkAddress(addr)
	if !ok {
		return
	}
	s := c.senders[ap]
	if s == nil || !bytes.Equal(padding[4:20], s.session[:]) {
		return
	}
	n := binary.BigEndian.Uint64(padding[20:])
	if n > s.feedback && n-s.feedback <= 8192 {
		c.stats.ReportedRecoveredSources += n - s.feedback
		s.feedback = n
	}
}

// No invented outer ACKs or packet numbers: the core applies a separate guard.
func (c *tasmanPacketConn) QUICOuterRecovery(addr net.Addr) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	ap, _, ok := blinkAddress(addr)
	if !ok {
		return 0
	}
	if s := c.senders[ap]; s != nil {
		return s.feedback
	}
	return 0
}
