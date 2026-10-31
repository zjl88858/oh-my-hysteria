// SPDX-License-Identifier: MIT-0

package cmd

import "github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"

type configObfsTrident struct {
	Password string `mapstructure:"password"`
}

func (c configObfsTrident) options(server bool) obfs.TridentOptions {
	return obfs.TridentOptions{Password: []byte(c.Password), Server: server}
}
