// SPDX-License-Identifier: MIT-0

package ackhandler

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/mocks"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestOuterRecoveryPacingGuard(t *testing.T) {
	h := &sentPacketHandler{rttStats: utils.NewRTTStats()}
	now := monotime.Now()
	h.ObserveOuterRecovery(now)
	require.Greater(t, h.outerRecoveryUntil, now)
	require.LessOrEqual(t, h.outerRecoveryUntil.Sub(now), 100*time.Millisecond)
	until := h.outerRecoveryUntil
	h.ObserveOuterRecovery(now)
	require.Equal(t, until, h.outerRecoveryUntil)
}

func TestOuterRecoveryDisabledPreservesNegativeClock(t *testing.T) {
	ctrl := gomock.NewController(t)
	cc := mocks.NewMockSendAlgorithmWithDebugInfos(ctrl)
	at := monotime.Time(-1_000_000_000)
	h := &sentPacketHandler{appDataPackets: newPacketNumberSpace(0, true), peerAddressValidated: true, congestion: cc, rttStats: utils.NewRTTStats(), logger: utils.DefaultLogger}
	cc.EXPECT().CanSend(gomock.Any()).Return(true).AnyTimes()
	cc.EXPECT().HasPacingBudget(at).Return(true).AnyTimes()
	cc.EXPECT().TimeUntilSend(gomock.Any()).Return(at).AnyTimes()
	require.Equal(t, SendAny, h.SendMode(at))
	require.Equal(t, at, h.TimeUntilSend())
	h.ObserveOuterRecovery(at)
	require.Less(t, h.outerRecoveryUntil, monotime.Time(0))
	require.Equal(t, SendPacingLimited, h.SendMode(at))
	require.Greater(t, h.TimeUntilSend(), at)
}
