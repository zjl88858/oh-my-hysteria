// SPDX-License-Identifier: MIT-0

package bbr3

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

var testProfiles = []Profile{ProfileConservative, ProfileStandard, ProfileAggressive}

func TestParseProfile(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Profile
	}{
		{"", ProfileStandard}, {"STANDARD", ProfileStandard}, {"Conservative", ProfileConservative}, {"aggressive", ProfileAggressive},
	} {
		p, err := ParseProfile(tc.in)
		require.NoError(t, err)
		require.Equal(t, tc.want, p)
	}
	for _, value := range []string{"unknown", " standard", "aggressive "} {
		_, err := ParseProfile(value)
		require.ErrorContains(t, err, "BBRv3 profile")
	}
	require.Panics(t, func() { NewSenderWithProfile(1200, "invalid") })
}

func TestProfileStandardPreservesBaseline(t *testing.T) {
	s := NewSender(1200)
	require.Equal(t, ProfileStandard, s.Snapshot().Profile)
	require.Equal(t, profileConfig{
		startupPacingGain: 277, cwndGain: 200, probeUpPacingGain: 125, probeUpCwndGain: 225,
		headroomPercent: 15, probeRoundCap: 63, probeWaitBase: 2 * time.Second, probeWaitRange: time.Second,
	}, s.tuning)
	require.Equal(t, uint64(38400), s.cwnd)
	require.Equal(t, uint64(1063680), s.rate)
}

func TestProfileGainsAndHeadroom(t *testing.T) {
	for _, tc := range []struct {
		profile                                   Profile
		startup, upRate, upWindow, headroomFlight uint64
	}{
		{ProfileConservative, 225, 1138500, 202400, 80000},
		{ProfileStandard, 277, 1237500, 227400, 85000},
		{ProfileAggressive, 300, 1336500, 252400, 90000},
	} {
		t.Run(string(tc.profile), func(t *testing.T) {
			s := NewSenderWithProfile(1200, tc.profile)
			require.Equal(t, mulDiv(384000, tc.startup, 100), s.rate)
			s.fullReached = true
			s.hasMin = true
			s.minRTT = 100 * time.Millisecond
			s.bwCurrent = 1000000
			s.state = probeUp
			s.cwnd = 1000000
			s.updateControls(0)
			require.Equal(t, tc.upRate, s.rate)
			require.Equal(t, tc.upWindow, s.cwnd)
			s.flightLong = 100000
			require.Equal(t, tc.headroomFlight, s.withHeadroom())
			require.Equal(t, tc.profile, s.Snapshot().Profile)
		})
	}
}

func TestProfileProbeScheduling(t *testing.T) {
	for _, p := range testProfiles {
		t.Run(string(p), func(t *testing.T) {
			s := NewSenderWithProfile(1200, p)
			s.setClock(0)
			s.fullReached = true
			s.hasMin = true
			s.minRTT = 100 * time.Millisecond
			s.bwCurrent = 12000000
			s.cwnd = 2000000
			for range 100 {
				s.enterDown()
				require.GreaterOrEqual(t, s.probeWait, s.tuning.probeWaitBase)
				require.Less(t, s.probeWait, s.tuning.probeWaitBase+s.tuning.probeWaitRange)
			}
			s.roundsSinceProbe = s.tuning.probeRoundCap - 1
			s.advanceProbe(rateSample{}, false)
			require.Equal(t, probeCruise, s.state)
			s.roundsSinceProbe++
			s.advanceProbe(rateSample{}, false)
			require.Equal(t, probeRefill, s.state)
			s.enterDown()
			s.roundsSinceProbe = 0
			s.now = monotime.Time(s.probeWait + time.Nanosecond)
			s.advanceProbe(rateSample{}, false)
			require.Equal(t, probeRefill, s.state)
		})
	}
}

func TestProfileSurvivesResetAndSamplingFault(t *testing.T) {
	for _, p := range testProfiles {
		t.Run(string(p), func(t *testing.T) {
			s := NewSenderWithProfile(1200, p)
			config := s.tuning
			s.sampler.capacity = 1
			senderSend(s, 0, 0, 1200, false)
			senderSend(s, 1, time.Millisecond, 2400, false)
			require.Equal(t, uint64(1), s.faults)
			require.Equal(t, p, s.Snapshot().Profile)
			require.Equal(t, config, s.tuning)
			s.OnPathReset(monotime.Time(time.Second), 1280)
			require.Equal(t, p, s.profile)
			require.Equal(t, config, s.tuning)
			require.Equal(t, 32*uint64(1280), s.cwnd)
			s.SetMaxDatagramSize(1400)
			require.Equal(t, config, s.tuning)
			require.Equal(t, 32*uint64(1400), s.initial)
		})
	}
}

func TestProfilesKeepCEAndLossSafety(t *testing.T) {
	for _, p := range testProfiles {
		t.Run(string(p), func(t *testing.T) {
			s := NewSenderWithProfile(1200, p)
			s.fullReached = true
			s.state = probeCruise
			s.hasMin = true
			s.minRTT = 100 * time.Millisecond
			s.bwCurrent = 1000000
			s.cwnd = 100000
			s.respondCE()
			require.Equal(t, uint64(70000), s.cwnd)
			require.Equal(t, uint64(700000), s.bwShort)
			s.respondCE()
			require.Equal(t, uint64(70000), s.cwnd)
			s.bwShort = unlimited
			s.cwnd = 100000
			s.handleExcessLoss(20000, false)
			require.Equal(t, uint64(70000), s.flightLong)
			s.probeStamp = 0
			s.hasProbeStamp = true
			s.now = monotime.Time(6 * time.Second)
			s.updateMinRTT(100 * time.Millisecond)
			require.Equal(t, probeRTT, s.state)
			s.inFlight = 0
			s.handleProbeRTT(rateSample{}, false)
			require.Equal(t, s.now.Add(200*time.Millisecond), s.probeDone)
			require.Equal(t, uint64(50000), s.probeWindow())
			require.Equal(t, uint64(4800), s.floor())
			require.Equal(t, historyCapacity, s.sampler.capacity)
			// MTU failures still do not become congestion losses in any profile.
			s.OnPathReset(0, 1200)
			senderSend(s, 0, 0, 1200, true)
			senderLoss(s, time.Millisecond, 0, 0)
			require.Zero(t, s.sampler.totals.congestionLost)
			require.False(t, s.inRecovery)
			s.OnPacketRemoved(congestion.SpaceApplication, 0, congestion.RemovalHistory)
		})
	}
}
