// SPDX-License-Identifier: MIT-0

package bbr3

import (
	"fmt"
	"strings"
	"time"
)

// Profile selects a local experimental probing policy, not a wire protocol or
// an interpretation of the legacy BBRv1 profiles. Standard preserves the
// original draft-06-based controller's parameters.
type Profile string

const (
	ProfileConservative Profile = "conservative"
	ProfileStandard     Profile = "standard"
	ProfileAggressive   Profile = "aggressive"
)

func ParseProfile(value string) (Profile, error) {
	switch p := Profile(strings.ToLower(value)); p {
	case "", ProfileStandard:
		return ProfileStandard, nil
	case ProfileConservative, ProfileAggressive:
		return p, nil
	default:
		return "", fmt.Errorf("unsupported BBRv3 profile %q", value)
	}
}

// Gains are integer percentages. Profiles deliberately do not change loss
// thresholds, beta / CE response, sampling, history bounds or ProbeRTT timers.
// Nonstandard profiles are policy experiments, not additional draft defaults.
type profileConfig struct {
	startupPacingGain, cwndGain, probeUpPacingGain, probeUpCwndGain uint64
	headroomPercent, probeRoundCap                                  uint64
	probeWaitBase, probeWaitRange                                   time.Duration
}

func configForProfile(p Profile) profileConfig {
	switch p {
	case ProfileConservative:
		return profileConfig{
			startupPacingGain: 225, cwndGain: 175, probeUpPacingGain: 115, probeUpCwndGain: 200,
			headroomPercent: 20, probeRoundCap: 80, probeWaitBase: 3 * time.Second, probeWaitRange: time.Second,
		}
	case ProfileAggressive:
		return profileConfig{
			startupPacingGain: 300, cwndGain: 225, probeUpPacingGain: 135, probeUpCwndGain: 250,
			headroomPercent: 10, probeRoundCap: 48, probeWaitBase: time.Second, probeWaitRange: time.Second,
		}
	default:
		return profileConfig{
			startupPacingGain: 277, cwndGain: 200, probeUpPacingGain: 125, probeUpCwndGain: 225,
			headroomPercent: 15, probeRoundCap: 63, probeWaitBase: 2 * time.Second, probeWaitRange: time.Second,
		}
	}
}
