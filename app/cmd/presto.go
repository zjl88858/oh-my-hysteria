// SPDX-License-Identifier: MIT-0

package cmd

import "github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"

type configObfsPresto struct {
	Password string `mapstructure:"password"`
}

func (c configObfsPresto) options(server bool) obfs.PrestoOptions {
	return obfs.PrestoOptions{Password: []byte(c.Password), Server: server}
}

// Preserve the opt-in framing limit through the realm port-map cleanup layer.
// Raw paths must not gain this interface (the core deliberately rejects 0).
type limitedCleanupPacketConn struct {
	*cleanupPacketConn
	limit int
}

func (c *limitedCleanupPacketConn) QUICPacketSizeLimit() int { return c.limit }
