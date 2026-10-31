// SPDX-License-Identifier: MIT-0

package pmtud

import (
	"net"

	"github.com/apernet/quic-go"
)

// ApplyPacketConnLimit is opt-in: raw UDP, Salamander and Gecko keep their
// existing behavior. An envelope cannot use inner QUIC PMTU success as proof
// of a larger outer UDP path MTU. Blink, Presto, Trident and Carakan expose 1200.
func ApplyPacketConnLimit(pc net.PacketConn, conf *quic.Config) bool {
	limited, ok := pc.(interface{ QUICPacketSizeLimit() int })
	if !ok {
		return false
	}
	if limited.QUICPacketSizeLimit() != 1200 {
		panic("unsupported framed PacketConn size limit")
	}
	conf.InitialPacketSize = 1200
	conf.DisablePathMTUDiscovery = true
	conf.ChromeParrot = false
	return true
}
