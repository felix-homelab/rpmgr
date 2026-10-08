// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// plainEcho is a TCP echo service standing in for the controller.
func plainEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// TestControlConn: a connector carries a connection to the controller through its data session,
// on QUIC by opening the stream and on HTTP/2 with an OpenRequest; without a data session, or
// with a gateway that refuses, it gets an error at once.
func TestControlConn(t *testing.T) {
	for _, tr := range []string{connector.TransportQUIC, connector.TransportH2} {
		t.Run(tr, func(t *testing.T) {
			w := newWorld(t)
			id := w.gatewayID()
			g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
			f := gateway.NewForward(plainEcho(t), nil, nil)
			t.Cleanup(f.Close)
			carried := gateway.NewControlStreams(f.Serve)
			g.sessions.Store(gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: id.ID, Assignment: w.assignment(),
				OnOpenRequest: carried.Decide}))
			m := newConnector(t, w)
			if _, err := m.ControlConn(context.Background()); !errors.Is(err, connector.ErrNoDataSession) {
				t.Fatalf("without a data session: %v", err)
			}
			readyAll(m, "rt_a")
			m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_a": tr}}})
			want := map[string]string{connector.TransportQUIC: "quic", connector.TransportH2: "h2"}[tr]
			eventually(t, "no data session", func() bool { return m.Count()[id.ID+"/"+want] >= 1 })

			c, err := m.ControlConn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Write([]byte("Hello")); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 5)
			if _, err := io.ReadFull(c, b); err != nil || string(b) != "Hello" {
				t.Fatalf("through the data session: %q %v", b, err)
			}
			if got := carried.Open(w.con.ID); got != 1 {
				t.Fatalf("the gateway carries %d control sessions", got)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			eventually(t, "the carried session stays open at the gateway", func() bool { return carried.Open(w.con.ID) == 0 })

			// A gateway that carries no control sessions refuses.
			old := g.sessions.Load()
			g.sessions.Store(w.sessions(id))
			old.Close()
			eventually(t, "no new data session", func() bool {
				return g.sessions.Load().Count()[want] >= 1 && m.Count()[id.ID+"/"+want] >= 1
			})
			var rejected *tunnel.OpenRejectedError
			if _, err := m.ControlConn(context.Background()); !errors.As(err, &rejected) || rejected.Code != tunnelv1.ResultCode_RESULT_CODE_UNAUTHORIZED {
				t.Fatalf("a gateway without a decision: %v", err)
			}
		})
	}
}
