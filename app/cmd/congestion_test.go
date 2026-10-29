// SPDX-License-Identifier: MIT-0

package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
	"github.com/zjl88858/oh-my-hysteria/core/v2/server"
)

func TestCongestionSlowStartConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, typ, mode, wantType, wantMode, errorField string
	}{
		{"default", "", "", "bbr", "legacy", ""},
		{"cubic default fallback", "CUBIC", "", "cubic", "legacy", ""},
		{"cubic hystart", "cubic", "HyStart++", "cubic", "hystart++", ""},
		{"reno hystart", "RENO", "hystart++", "reno", "hystart++", ""},
		{"explicit legacy", "cubic", "LEGACY", "cubic", "legacy", ""},
		{"unknown mode", "cubic", "unknown", "", "", "congestion.slowStart"},
		{"unsupported bbr combination", "bbr", "hystart++", "", "", "congestion.slowStart"},
		{"experimental bbr3", "BBR3", "", "bbr3", "legacy", ""},
		{"unsupported bbr3 combination", "bbr3", "hystart++", "", "", "congestion.slowStart"},
		{"experimental copa", "COPA", "", "copa", "legacy", ""},
		{"experimental geodesic", "Geodesic", "", "geodesic", "legacy", ""},
		{"unsupported geodesic combination", "geodesic", "hystart++", "", "", "congestion.slowStart"},
		{"unsupported copa combination", "copa", "hystart++", "", "", "congestion.slowStart"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc := &client.Config{}
			sc := &server.Config{}
			clientErr := (&clientConfig{Congestion: clientConfigCongestion{Type: tc.typ, SlowStart: tc.mode}}).fillCongestionConfig(cc)
			serverErr := (&serverConfig{Congestion: serverConfigCongestion{Type: tc.typ, SlowStart: tc.mode}}).fillCongestionConfig(sc)
			if tc.errorField != "" {
				require.ErrorContains(t, clientErr, tc.errorField)
				require.ErrorContains(t, serverErr, tc.errorField)
				return
			}
			require.NoError(t, clientErr)
			require.NoError(t, serverErr)
			require.Equal(t, tc.wantType, cc.CongestionConfig.Type)
			require.Equal(t, tc.wantType, sc.CongestionConfig.Type)
			require.Equal(t, tc.wantMode, cc.CongestionConfig.SlowStart)
			require.Equal(t, tc.wantMode, sc.CongestionConfig.SlowStart)
		})
	}
}

func TestBBR3Profiles(t *testing.T) {
	for _, profile := range []string{"", "STANDARD", "AGGRESSIVE", "conservative", "invalid"} {
		c, s := &client.Config{}, &server.Config{}
		ce := (&clientConfig{Congestion: clientConfigCongestion{Type: "bbr3", BBRProfile: profile}}).fillCongestionConfig(c)
		se := (&serverConfig{Congestion: serverConfigCongestion{Type: "bbr3", BBRProfile: profile}}).fillCongestionConfig(s)
		if profile != "invalid" {
			require.NoError(t, ce)
			require.NoError(t, se)
			want := strings.ToLower(profile)
			if want == "" {
				want = "standard"
			}
			require.Equal(t, want, c.CongestionConfig.BBRProfile)
			require.Equal(t, want, s.CongestionConfig.BBRProfile)
		} else {
			require.ErrorContains(t, ce, "congestion.bbrProfile")
			require.ErrorContains(t, se, "congestion.bbrProfile")
		}
	}
}

func TestCongestionSlowStartYAML(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("congestion:\n  type: cubic\n  slowStart: hystart++\n")))
	var cc clientConfig
	var sc serverConfig
	require.NoError(t, v.Unmarshal(&cc))
	require.NoError(t, v.Unmarshal(&sc))
	c, s := &client.Config{}, &server.Config{}
	require.NoError(t, cc.fillCongestionConfig(c))
	require.NoError(t, sc.fillCongestionConfig(s))
	require.Equal(t, "cubic", c.CongestionConfig.Type)
	require.Equal(t, "hystart++", c.CongestionConfig.SlowStart)
	require.Equal(t, "cubic", s.CongestionConfig.Type)
	require.Equal(t, "hystart++", s.CongestionConfig.SlowStart)
}
