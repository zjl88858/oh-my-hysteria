// SPDX-License-Identifier: MIT-0

package cmd

import (
	"net"
	"time"

	"github.com/zjl88858/oh-my-hysteria/extras/v2/obfs"
	"go.uber.org/zap"
)

type configObfsServo struct {
	Password string `mapstructure:"password"`
}

func (c configObfsServo) options(server bool) obfs.ServoOptions {
	return obfs.ServoOptions{Password: []byte(c.Password), Server: server}
}

func wrapServoConfig(conn net.PacketConn, config configObfsServo, server bool) (net.PacketConn, error) {
	w, err := obfs.WrapPacketConnServo(conn, config.options(server))
	if err != nil {
		return nil, configError{Field: "obfs.servo", Err: err}
	}
	log := logger
	if log == nil {
		log = zap.NewNop()
	}
	// The bounded channel is mandatory application plumbing, not fire-and-forget
	// logs in WriteTo. Packet failures are counted and abandoned by Servo; QUIC
	// handles loss. Terminal errors/notification overflow fail the PacketConn.
	errors := w.(interface{ ServoErrors() <-chan obfs.ServoError }).ServoErrors()
	go func() {
		for e := range errors {
			log.Warn("Servo asynchronous datagram failure", zap.String("remote", e.Remote.String()),
				zap.Uint32("message", e.MessageID), zap.String("operation", e.Operation), zap.Error(e.Err))
		}
	}()
	return w, nil
}

// Preserve the optional send-time observation through the existing realm
// cleanup wrapper without granting OOB, GSO or ECN capabilities.
func (c *limitedCleanupPacketConn) WriteToWithQUICSendTime(p []byte, addr net.Addr, sent time.Time) (int, error) {
	if timed, ok := c.PacketConn.(interface {
		WriteToWithQUICSendTime([]byte, net.Addr, time.Time) (int, error)
	}); ok {
		return timed.WriteToWithQUICSendTime(p, addr, sent)
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *limitedCleanupPacketConn) QUICTransportMetrics(addr net.Addr, rtt, pto time.Duration, lost uint64, probe bool) {
	if observer, ok := c.PacketConn.(interface {
		QUICTransportMetrics(net.Addr, time.Duration, time.Duration, uint64, bool)
	}); ok {
		observer.QUICTransportMetrics(addr, rtt, pto, lost, probe)
	}
}
