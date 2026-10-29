// SPDX-License-Identifier: MIT-0

package cmd

import "github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"

type configObfsBlink struct {
	Password               string `mapstructure:"password"`
	MaxPacketSize          int    `mapstructure:"maxPacketSize"`
	PaddingMax             *int   `mapstructure:"paddingMax"`
	JunkPackets            *int   `mapstructure:"junkPackets"`
	Fragmentation          bool   `mapstructure:"fragmentation"`
	MaxSessions            int    `mapstructure:"maxSessions"`
	MaxReassemblyBytes     int    `mapstructure:"maxReassemblyBytes"`
	VerifyPacketsPerSecond int    `mapstructure:"verifyPacketsPerSecond"`
}

func (c configObfsBlink) options(server bool) obfs.BlinkOptions {
	return obfs.BlinkOptions{
		Password: []byte(c.Password), Server: server, MaxPacketSize: c.MaxPacketSize,
		PaddingMax: c.PaddingMax, JunkPackets: c.JunkPackets, Fragmentation: c.Fragmentation,
		MaxSessions: c.MaxSessions, MaxReassemblyBytes: c.MaxReassemblyBytes, VerifyPacketsPerSecond: c.VerifyPacketsPerSecond,
	}
}
