package cmd

import (
	"fmt"
	"strings"
)

const (
	congestionTypeBBR      = "bbr"
	congestionTypeBBR3     = "bbr3"
	congestionTypeReno     = "reno"
	congestionTypeCubic    = "cubic"
	congestionTypeCopa     = "copa"
	congestionTypeGeodesic = "geodesic"
)

func normalizeCongestionType(congestionType string) (string, error) {
	switch normalized := strings.ToLower(congestionType); normalized {
	case "", congestionTypeBBR:
		return congestionTypeBBR, nil
	case congestionTypeReno, congestionTypeCubic, congestionTypeBBR3, congestionTypeCopa, congestionTypeGeodesic:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported congestion type %q", congestionType)
	}
}

func normalizeSlowStart(congestionType, slowStart string) (string, error) {
	switch normalized := strings.ToLower(slowStart); normalized {
	case "", "legacy":
		return "legacy", nil
	case "hystart++":
		if congestionType != congestionTypeCubic && congestionType != congestionTypeReno {
			return "", fmt.Errorf("slow start %q is only supported for cubic and reno", slowStart)
		}
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported slow start %q", slowStart)
	}
}

func normalizeBBRProfile(profile string) (string, error) {
	switch normalized := strings.ToLower(profile); normalized {
	case "", "standard":
		return "standard", nil
	case "conservative", "aggressive":
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported BBR profile %q", profile)
	}
}

func normalizeBBR3Profile(profile string) (string, error) {
	switch normalized := strings.ToLower(profile); normalized {
	case "", "standard":
		return "standard", nil
	case "conservative", "aggressive":
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported BBRv3 profile %q", profile)
	}
}
