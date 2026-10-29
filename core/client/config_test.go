// SPDX-License-Identifier: MIT-0

package client

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCongestionConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		typ, mode, errorField string
	}{
		{"", "", ""},
		{"CUBIC", "", ""},
		{"cubic", "HyStart++", ""},
		{"reno", "hystart++", ""},
		{"COPA", "", ""},
		{"GEODESIC", "", ""},
		{"geodesic", "hystart++", "CongestionConfig.SlowStart"},
		{"copa", "hystart++", "CongestionConfig.SlowStart"},
		{"bbr", "hystart++", "CongestionConfig.SlowStart"},
		{"cubic", "invalid", "CongestionConfig.SlowStart"},
		{"invalid", "", "CongestionConfig.Type"},
	} {
		t.Run(tc.typ+"/"+tc.mode, func(t *testing.T) {
			c := &Config{ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, CongestionConfig: CongestionConfig{Type: tc.typ, SlowStart: tc.mode}}
			err := c.verifyAndFill()
			if tc.errorField != "" {
				require.ErrorContains(t, err, tc.errorField)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, c.CongestionConfig.SlowStart)
			}
		})
	}
}

func TestBBR3ProfileValidation(t *testing.T) {
	for _, profile := range []string{"", "STANDARD", "Conservative", "aggressive", "invalid"} {
		c := &Config{ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, CongestionConfig: CongestionConfig{Type: "bbr3", BBRProfile: profile}}
		err := c.verifyAndFill()
		if profile == "invalid" {
			require.ErrorContains(t, err, "CongestionConfig.BBRProfile")
			continue
		}
		require.NoError(t, err)
		want := strings.ToLower(profile)
		if want == "" {
			want = "standard"
		}
		require.Equal(t, want, c.CongestionConfig.BBRProfile)
	}
}
