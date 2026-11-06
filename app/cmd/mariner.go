// SPDX-License-Identifier: MIT-0

package cmd

import (
	"net"

	"github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"
)

type configObfsMariner struct {
	Password string `mapstructure:"password"`
}

func wrapMarinerConfig(conn net.PacketConn, c configObfsMariner, server bool) (net.PacketConn, error) {
	w, err := obfs.WrapPacketConnMariner(conn, obfs.MarinerOptions{Password: []byte(c.Password), Server: server})
	if err != nil {
		return nil, configError{Field: "obfs.mariner", Err: err}
	}
	return w, nil
}
