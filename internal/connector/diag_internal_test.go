// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// ctlStream is a tunnel.Stream over one end of an in-memory connection.
type ctlStream struct{ net.Conn }

func (ctlStream) CloseWrite() error    { return nil }
func (ctlStream) SetReliableBoundary() {}
func (s ctlStream) Abort()             { _ = s.Close() }

// ctlSession is a session whose control stream is one end of a pipe, or no stream at all.
type ctlSession struct {
	tunnel.Session
	control tunnel.Stream
	err     error
}

func (s ctlSession) Control(context.Context) (tunnel.Stream, error) { return s.control, s.err }

// gatewayScript plays a gateway at the other end of the pipe: it reads the hello, answers with
// welcome unless it is false, reads the ping and answers with the pongs, each after delay.
func gatewayScript(peer net.Conn, welcome bool, delay time.Duration, pongs ...uint64) {
	defer func() { _ = peer.Close() }()
	hello := &tunnelv1.SessionMessage{}
	if tunnel.ReadMessage(peer, hello) != nil || hello.GetHello() == nil || !welcome {
		return
	}
	_ = tunnel.WriteMessage(peer, &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Welcome{Welcome: &tunnelv1.SessionWelcome{}}})
	ping := &tunnelv1.SessionMessage{}
	if tunnel.ReadMessage(peer, ping) != nil || ping.GetPing() == nil {
		return
	}
	time.Sleep(delay)
	for _, seq := range pongs {
		_ = tunnel.WriteMessage(peer, &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Pong{Pong: &tunnelv1.Pong{Seq: seq}}})
	}
}

// TestPingRTT: the round trip of one Ping is what a session without a transport RTT reports, and
// 0, which the command prints as "-", for every way the measurement can fail.
func TestPingRTT(t *testing.T) {
	const delay = 60 * time.Millisecond
	for _, tc := range []struct {
		name    string
		welcome bool
		pongs   []uint64
		timeout time.Duration
		noCtl   bool
		min     time.Duration // 0: the RTT must be 0
	}{
		{name: "pong", welcome: true, pongs: []uint64{1}, timeout: 5 * time.Second, min: delay},
		{name: "a pong of another seq first", welcome: true, pongs: []uint64{7, 1}, timeout: 5 * time.Second, min: delay},
		{name: "no welcome", welcome: false, timeout: 5 * time.Second},
		{name: "no pong, the peer closes", welcome: true, timeout: 5 * time.Second},
		{name: "only a pong of another seq", welcome: true, pongs: []uint64{7}, timeout: 5 * time.Second},
		{name: "no control stream", noCtl: true, timeout: 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ours, peer := net.Pipe()
			t.Cleanup(func() { _ = ours.Close(); _ = peer.Close() })
			s := ctlSession{control: ctlStream{ours}}
			if tc.noCtl {
				s = ctlSession{err: errors.New("no control stream")}
			} else {
				go gatewayScript(peer, tc.welcome, delay, tc.pongs...)
			}
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			got := pingRTT(ctx, s, time.Now)
			if tc.min == 0 && got != 0 || tc.min > 0 && (got < tc.min || got > 5*time.Second) {
				t.Fatalf("RTT %v, want at least %v (0 if the measurement fails)", got, tc.min)
			}
		})
	}
}

// TestPingRTT_Silent: a gateway that welcomes and then never answers the Ping costs the probe its
// context and yields no RTT, instead of hanging it.
func TestPingRTT_Silent(t *testing.T) {
	ours, peer := net.Pipe()
	t.Cleanup(func() { _ = ours.Close(); _ = peer.Close() })
	go func() {
		hello := &tunnelv1.SessionMessage{}
		_ = tunnel.ReadMessage(peer, hello)
		_ = tunnel.WriteMessage(peer, &tunnelv1.SessionMessage{Msg: &tunnelv1.SessionMessage_Welcome{Welcome: &tunnelv1.SessionWelcome{}}})
		_, _ = peer.Read(make([]byte, 1<<10)) // the ping; then silence
		<-time.After(10 * time.Second)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if got := pingRTT(ctx, ctlSession{control: ctlStream{ours}}, time.Now); got != 0 {
		t.Fatalf("RTT %v from a gateway that never answers", got)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("the measurement took %v past a 300 ms context", time.Since(start))
	}
}
