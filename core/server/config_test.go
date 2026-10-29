// SPDX-License-Identifier: MIT-0

package server

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type configTestAuthenticator struct{}

func (configTestAuthenticator) Authenticate(net.Addr, string, uint64) (bool, string) {
	return true, "test"
}

func TestBBR3ProfileValidation(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()
	for _, profile := range []string{"", "STANDARD", "Conservative", "aggressive", "invalid"} {
		c := &Config{Conn: conn, TLSConfig: TLSConfig{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }}, Authenticator: configTestAuthenticator{}, CongestionConfig: CongestionConfig{Type: "bbr3", BBRProfile: profile}}
		err := c.fill()
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

func TestCongestionConfigValidation(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
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
			c := &Config{
				Conn:             conn,
				TLSConfig:        TLSConfig{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }},
				Authenticator:    configTestAuthenticator{},
				CongestionConfig: CongestionConfig{Type: tc.typ, SlowStart: tc.mode},
			}
			err := c.fill()
			if tc.errorField != "" {
				require.ErrorContains(t, err, tc.errorField)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, c.CongestionConfig.SlowStart)
			}
		})
	}
}
