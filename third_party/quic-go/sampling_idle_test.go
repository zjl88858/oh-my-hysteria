// SPDX-License-Identifier: MIT-0

package quic

import (
	"testing"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestSamplingIdleRetainsFlowControlBlockedData(t *testing.T) {
	f := newFramer(nil)
	s := &SendStream{dataForWriting: []byte("blocked"), streamID: 4}
	// Flow-control-blocked streams have left the active scheduler, but are
	// not application limited: retain them until their unsent data is gone.
	f.samplingStreams[protocol.StreamID(4)] = s
	require.True(t, f.samplingHasPendingData())
	s.dataForWriting = nil
	require.False(t, f.samplingHasPendingData())
	require.Empty(t, f.samplingStreams)
	s.finishedWriting = true
	require.True(t, s.samplingHasPendingData())
	s.finSent = true
	require.False(t, s.samplingHasPendingData())
}

func TestSamplingIdleNilOneRTTCryptoStream(t *testing.T) {
	c := &Conn{handshakeConfirmed: true, framer: newFramer(nil), retransmissionQueue: &retransmissionQueue{}, sendQueue: &sendQueue{}}
	c.advancedCongestion.Store(true)
	require.NotPanics(t, func() { c.maybeNotifyApplicationLimited(0) })
}
