package congestion

import (
	"fmt"
	"strings"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/congestion"
	"github.com/zjl88858/oh-my-hysteria/core/v2/internal/congestion/bbr"
	"github.com/zjl88858/oh-my-hysteria/core/v2/internal/congestion/bbr3"
	"github.com/zjl88858/oh-my-hysteria/core/v2/internal/congestion/brutal"
	"github.com/zjl88858/oh-my-hysteria/core/v2/internal/congestion/copa"
	"github.com/zjl88858/oh-my-hysteria/core/v2/internal/congestion/cubic"
	"github.com/zjl88858/oh-my-hysteria/core/v2/internal/congestion/geodesic"
)

const (
	TypeBBR      = "bbr"
	TypeBBR3     = "bbr3"
	TypeReno     = "reno"
	TypeCubic    = "cubic"
	TypeCopa     = "copa"
	TypeGeodesic = "geodesic"

	SlowStartLegacy          = "legacy"
	SlowStartHyStartPlusPlus = "hystart++"
)

func NormalizeType(congestionType string) (string, error) {
	switch normalized := strings.ToLower(congestionType); normalized {
	case "", TypeBBR:
		return TypeBBR, nil
	case TypeReno, TypeCubic, TypeBBR3, TypeCopa, TypeGeodesic:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported congestion type %q", congestionType)
	}
}

func NormalizeSlowStart(congestionType, slowStart string) (string, error) {
	switch normalized := strings.ToLower(slowStart); normalized {
	case "", SlowStartLegacy:
		return SlowStartLegacy, nil
	case SlowStartHyStartPlusPlus:
		if congestionType != TypeCubic && congestionType != TypeReno {
			return "", fmt.Errorf("slow start %q is only supported for cubic and reno", slowStart)
		}
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported slow start %q", slowStart)
	}
}

func NormalizeBBRProfile(profile string) (string, error) {
	normalized, err := bbr.ParseProfile(profile)
	if err != nil {
		return "", err
	}
	return string(normalized), nil
}

func NormalizeBBR3Profile(profile string) (string, error) {
	normalized, err := bbr3.ParseProfile(profile)
	return string(normalized), err
}

func UseBBR(conn *quic.Conn, profile bbr.Profile) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		seedPacketSize(conn.InitialPacketSize(), bbr.GetInitialPacketSize(conn.RemoteAddr())),
		profile,
	))
}

// seedPacketSize picks the datagram size to seed a replacement congestion
// controller with, given the size QUIC itself starts at and the guess derived
// from the remote address.
//
// The seed must not exceed what QUIC actually starts at. If it does, the first
// path MTU probe can land between the two: QUIC sees an increase and reports
// it, but the controller sees a decrease, which it cannot represent. Taking the
// smaller of the two keeps the address-based guess as a floor for connections
// whose path we can't reason about, while never seeding above QUIC.
func seedPacketSize(quicSize, byAddr congestion.ByteCount) congestion.ByteCount {
	if quicSize <= 0 {
		return byAddr
	}
	return min(quicSize, byAddr)
}

func UseBrutal(conn *quic.Conn, tx uint64, disableLossCompensation bool) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx, disableLossCompensation))
}

func UseConfigured(conn *quic.Conn, congestionType, bbrProfile, slowStart string) {
	switch congestionType {
	case TypeGeodesic:
		conn.SetCongestionControl(geodesic.NewSender(conn.InitialPacketSize()))
	case TypeCopa:
		conn.SetCongestionControl(copa.NewSender(conn.InitialPacketSize()))
	case TypeBBR3:
		conn.SetCongestionControl(bbr3.NewSenderWithProfile(conn.InitialPacketSize(), bbr3.Profile(bbrProfile)))
	case TypeReno:
		if slowStart == SlowStartHyStartPlusPlus {
			conn.SetCongestionControl(cubic.NewSender(conn.InitialPacketSize(), true, true))
		}
	case TypeCubic:
		conn.SetCongestionControl(cubic.NewSender(conn.InitialPacketSize(), false, slowStart == SlowStartHyStartPlusPlus))
	default:
		UseBBR(conn, bbr.Profile(bbrProfile))
	}
}
