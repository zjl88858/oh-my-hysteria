// SPDX-License-Identifier: MIT-0

package integration_tests

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/zjl88858/oh-my-hysteria/core/v2/client"
	"github.com/zjl88858/oh-my-hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/zjl88858/oh-my-hysteria/core/v2/server"
)

func TestConfiguredCongestionTransfer(t *testing.T) {
	for _, tc := range []struct {
		typ, mode             string
		ignoreClientBandwidth bool
	}{
		{"cubic", "legacy", false},
		{"cubic", "hystart++", false},
		{"cubic", "hystart++", true},
		{"reno", "hystart++", false},
		{"reno", "legacy", false},
		{"bbr3", "legacy", false},
		{"bbr3", "legacy", true},
		{"copa", "legacy", false},
		{"copa", "legacy", true},
		{"geodesic", "legacy", false},
		{"geodesic", "legacy", true},
	} {
		t.Run(fmt.Sprintf("%s/%s/ignoreBandwidth=%v", tc.typ, tc.mode, tc.ignoreClientBandwidth), func(t *testing.T) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			auth := mocks.NewMockAuthenticator(t)
			auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "test")
			s, err := server.NewServer(&server.Config{
				Conn: pc, TLSConfig: serverTLSConfig(), Authenticator: auth,
				CongestionConfig:      server.CongestionConfig{Type: tc.typ, SlowStart: tc.mode},
				IgnoreClientBandwidth: tc.ignoreClientBandwidth,
			})
			require.NoError(t, err)
			defer s.Close()
			go s.Serve()
			c, _, err := client.NewClient(&client.Config{
				ServerAddr: pc.LocalAddr(), TLSConfig: client.TLSConfig{InsecureSkipVerify: true},
				CongestionConfig: client.CongestionConfig{Type: tc.typ, SlowStart: tc.mode},
			})
			require.NoError(t, err)
			defer c.Close()

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			echo := &tcpEchoServer{Listener: listener}
			defer echo.Close()
			go echo.Serve()
			stream, err := c.TCP(listener.Addr().String())
			require.NoError(t, err)
			defer stream.Close()
			require.NoError(t, stream.SetDeadline(time.Now().Add(15*time.Second)))
			payload := bytes.Repeat([]byte("cubic-hystart++-transfer\n"), 32768)
			written := make(chan error, 1)
			go func() {
				_, err := stream.Write(payload)
				written <- err
			}()
			received := make([]byte, len(payload))
			_, err = io.ReadFull(stream, received)
			require.NoError(t, err)
			require.NoError(t, <-written)
			require.Equal(t, payload, received)

			udpEchoConn, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			udpEcho := &udpEchoServer{Conn: udpEchoConn}
			defer udpEcho.Close()
			go udpEcho.Serve()
			udp, err := c.UDP()
			require.NoError(t, err)
			defer udp.Close()
			done := make(chan error, 1)
			go func() {
				for i := range 16 {
					data := bytes.Repeat([]byte{byte(i)}, 900)
					if err := udp.Send(data, udpEchoConn.LocalAddr().String()); err != nil {
						done <- err
						return
					}
					got, _, err := udp.Receive()
					if err != nil || !bytes.Equal(got, data) {
						done <- fmt.Errorf("UDP round trip %d failed: %v", i, err)
						return
					}
				}
				done <- nil
			}()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("UDP transfer timed out")
			}
		})
	}
}
