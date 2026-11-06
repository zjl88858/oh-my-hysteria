// SPDX-License-Identifier: MIT-0

package cmd

import (
	"net"
	"time"

	"github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"
	"go.uber.org/zap"
)

type configObfsTasman struct {
	Password string `mapstructure:"password"`
}

func wrapTasmanConfig(conn net.PacketConn, c configObfsTasman, server bool) (net.PacketConn, error) {
	w, err := obfs.WrapPacketConnTasman(conn, obfs.TasmanOptions{Password: []byte(c.Password), Server: server})
	if err != nil {
		return nil, configError{Field: "obfs.tasman", Err: err}
	}
	log := logger
	if log == nil {
		log = zap.NewNop()
	}
	ch := w.(interface {
		TasmanErrors() <-chan obfs.TasmanError
	}).TasmanErrors()
	go func() {
		for e := range ch {
			log.Warn("Tasman asynchronous datagram failure", zap.String("remote", e.Remote.String()), zap.Uint32("message", e.MessageID), zap.String("operation", e.Operation), zap.Error(e.Err))
		}
	}()
	return w, nil
}

func (c *limitedCleanupPacketConn) QUICWireReservation() bool {
	r, ok := c.PacketConn.(interface{ QUICWireReservation() bool })
	return ok && r.QUICWireReservation()
}

func (c *limitedCleanupPacketConn) QUICOuterRecovery(addr net.Addr) uint64 {
	if r, ok := c.PacketConn.(interface{ QUICOuterRecovery(net.Addr) uint64 }); ok {
		return r.QUICOuterRecovery(addr)
	}
	return 0
}

func (c *limitedCleanupPacketConn) WriteToWithQUICBudget(p []byte, addr net.Addr, sent, notBefore time.Time, n int) (int, error) {
	if r, ok := c.PacketConn.(interface {
		WriteToWithQUICBudget([]byte, net.Addr, time.Time, time.Time, int) (int, error)
	}); ok {
		return r.WriteToWithQUICBudget(p, addr, sent, notBefore, n)
	}
	return c.PacketConn.WriteTo(p, addr)
}
