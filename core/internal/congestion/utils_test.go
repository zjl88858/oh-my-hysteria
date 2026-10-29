// SPDX-License-Identifier: MIT-0

package congestion

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeTypeAndSlowStart(t *testing.T) {
	for _, tc := range []struct {
		typeIn, modeIn, typeOut, modeOut string
	}{
		{"", "", TypeBBR, SlowStartLegacy},
		{"CUBIC", "", TypeCubic, SlowStartLegacy},
		{"cubic", "HyStart++", TypeCubic, SlowStartHyStartPlusPlus},
		{"RENO", "hystart++", TypeReno, SlowStartHyStartPlusPlus},
		{"bbr", "LEGACY", TypeBBR, SlowStartLegacy},
		{"BBR3", "", TypeBBR3, SlowStartLegacy},
		{"COPA", "", TypeCopa, SlowStartLegacy},
		{"Geodesic", "", TypeGeodesic, SlowStartLegacy},
	} {
		t.Run(tc.typeIn+"/"+tc.modeIn, func(t *testing.T) {
			typ, err := NormalizeType(tc.typeIn)
			require.NoError(t, err)
			require.Equal(t, tc.typeOut, typ)
			mode, err := NormalizeSlowStart(typ, tc.modeIn)
			require.NoError(t, err)
			require.Equal(t, tc.modeOut, mode)
		})
	}
	_, err := NormalizeType("unknown")
	require.Error(t, err)
	_, err = NormalizeSlowStart(TypeBBR, SlowStartHyStartPlusPlus)
	require.ErrorContains(t, err, "only supported for cubic and reno")
	_, err = NormalizeSlowStart(TypeCubic, "hystart")
	require.ErrorContains(t, err, "unsupported slow start")
	_, err = NormalizeSlowStart(TypeCopa, SlowStartHyStartPlusPlus)
	require.ErrorContains(t, err, "only supported for cubic and reno")
	_, err = NormalizeSlowStart(TypeGeodesic, SlowStartHyStartPlusPlus)
	require.ErrorContains(t, err, "only supported for cubic and reno")
}

func TestNormalizeBBR3Profile(t *testing.T) {
	for _, profile := range []string{"", "standard", "STANDARD", "AGGRESSIVE", "conservative"} {
		normalized, err := NormalizeBBR3Profile(profile)
		require.NoError(t, err)
		want := strings.ToLower(profile)
		if want == "" {
			want = "standard"
		}
		require.Equal(t, want, normalized)
	}
	for _, profile := range []string{"unknown", " standard"} {
		_, err := NormalizeBBR3Profile(profile)
		require.Error(t, err)
	}
	_, err := NormalizeSlowStart(TypeBBR3, SlowStartHyStartPlusPlus)
	require.Error(t, err)
}
