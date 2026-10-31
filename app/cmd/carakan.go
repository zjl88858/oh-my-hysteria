// SPDX-License-Identifier: MIT-0

package cmd

import "github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"

type configObfsCarakan struct {
	Password      string   `mapstructure:"password"`
	TargetEntropy *float64 `mapstructure:"targetEntropy"`
}

func (c configObfsCarakan) options(server bool) obfs.CarakanOptions {
	return obfs.CarakanOptions{Password: []byte(c.Password), TargetEntropy: c.TargetEntropy, Server: server}
}
