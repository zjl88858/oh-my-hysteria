// SPDX-License-Identifier: MIT-0

package cmd

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"

	"github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"
)

type configObfsNetFront struct {
	Password   string        `mapstructure:"password"`
	ExtraPorts netfrontPorts `mapstructure:"extraPorts"`
}

type netfrontPorts []int

// Viper normally weakly converts booleans and fractional YAML numbers to
// integers. Do not silently bind a different port from the one specified.
func (p *netfrontPorts) UnmarshalMapstructure(input any) error {
	v := reflect.ValueOf(input)
	if v.Kind() != reflect.Slice || v.Len() < 2 || v.Len() > 3 {
		return errors.New("extraPorts must be a list of two or three UDP port numbers")
	}
	ports := make(netfrontPorts, v.Len())
	for i := range ports {
		n, err := strconv.ParseUint(fmt.Sprint(v.Index(i).Interface()), 10, 16)
		if err != nil || n == 0 {
			return fmt.Errorf("extraPorts[%d] must be an integer in 1..65535", i)
		}
		ports[i] = int(n)
	}
	*p = ports
	return nil
}

func netfrontConfigError(err error) error { return configError{Field: "obfs.netfront", Err: err} }

func (c configObfsNetFront) options() obfs.NetFrontOptions {
	return obfs.NetFrontOptions{Password: []byte(c.Password), ExtraPorts: c.ExtraPorts}
}

// Open as a group: even a failure on the last side port releases the earlier
// ports. Client opens use the same socket options as the primary connection.
func (c configObfsNetFront) open(port int, remote *net.UDPAddr, listen func(int) (net.PacketConn, error)) (net.PacketConn, error) {
	opts := c.options()
	if err := opts.Validate(port); err != nil {
		return nil, netfrontConfigError(err)
	}
	conns := make([]net.PacketConn, 0, 1+len(c.ExtraPorts))
	closeAll := func() {
		for _, pc := range conns {
			_ = pc.Close()
		}
	}
	for _, p := range append([]int{port}, c.ExtraPorts...) {
		pc, err := listen(p)
		if err != nil {
			closeAll()
			return nil, netfrontConfigError(fmt.Errorf("open UDP socket for port %d: %w", p, err))
		}
		conns = append(conns, pc)
	}
	w, err := obfs.WrapPacketConnNetFront(conns[0], conns[1:], remote, opts)
	if err != nil {
		closeAll()
		return nil, netfrontConfigError(err)
	}
	return w, nil
}

func (c configObfsNetFront) portList() string {
	ports := make([]string, len(c.ExtraPorts))
	for i, p := range c.ExtraPorts {
		ports[i] = strconv.Itoa(p)
	}
	return strings.Join(ports, ",")
}

func parseNetfrontPorts(values []string) []int {
	// An absent, duplicate or malformed URI field cannot inherit valid ports
	// from the surrounding YAML. Validate will reject an empty list.
	if len(values) != 1 {
		return nil
	}
	parts := strings.SplitN(values[0], ",", 4)
	if len(parts) < 2 || len(parts) > 3 {
		return nil
	}
	ports := make([]int, len(parts))
	for i, s := range parts {
		n, err := strconv.ParseUint(s, 10, 16)
		if err != nil || n == 0 {
			return nil
		}
		ports[i] = int(n)
	}
	return ports
}

var errNetfrontTransport = errors.New("NetFront requires a single fixed primary UDP port; port hopping, Realms and Mimic are not supported")
