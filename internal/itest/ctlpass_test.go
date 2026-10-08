// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/itest"
)

// attempts records the order in which a control client dials.
type attempts struct {
	mu    sync.Mutex
	order []string
	conns []net.Conn
}

func (a *attempts) add(kind string, c net.Conn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.order = append(a.order, kind)
	if c != nil {
		a.conns = append(a.conns, c)
	}
}

func (a *attempts) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.order)
}

// closeAll ends every connection made so far, as a cut path does.
func (a *attempts) closeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.conns {
		_ = c.Close()
	}
	a.conns = nil
}

// TestControlSession_DataSessionFallback: the data session is the last endpoint of a round: never
// used while a direct endpoint answers, used once every direct one failed, and left for the direct
// endpoints again when its session ends.
func TestControlSession_DataSessionFallback(t *testing.T) {
	ctl := itest.StartController(t, itest.Options{})
	id := ctl.EnrollConnector(t, filepath.Join(t.TempDir(), "identity"))
	ctlAddr := strings.TrimPrefix(ctl.URL, "https://")
	var a attempts
	direct := func(ok bool) func(ctx context.Context, addr string) (net.Conn, error) {
		return func(ctx context.Context, addr string) (net.Conn, error) {
			if !ok {
				a.add("direct", nil)
				return nil, errors.New("the direct path is cut")
			}
			c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			a.add("direct", c)
			return c, err
		}
	}
	fallback := func(ctx context.Context) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", ctlAddr) // stands in for the data session
		a.add("data-session", c)
		return c, err
	}

	c, _, stop := run(t, agent.ClientOptions{Identity: id, Endpoints: []string{ctl.URL}, Version: "0.1.0", BootID: "b1",
		Dial: direct(true), Fallback: fallback})
	waitFor(t, "a direct session", func() bool { return welcomes(c) == 1 })
	if got := a.list(); !slices.Equal(got, []string{"direct"}) {
		t.Fatalf("attempts %v, want only the direct endpoint", got)
	}
	_, _ = stop()

	a = attempts{}
	c, _, _ = run(t, agent.ClientOptions{Identity: id, Endpoints: []string{ctl.URL, ctl.URL}, Version: "0.1.0", BootID: "b2",
		Dial: direct(false), Fallback: fallback})
	waitFor(t, "a session through the data session", func() bool { return welcomes(c) == 1 })
	if _, _, ep := c.Stats(); ep != agent.DataSessionEndpoint {
		t.Fatalf("the session runs at %q", ep)
	}
	if got := a.list(); len(got) < 3 || !slices.Equal(got[:3], []string{"direct", "direct", "data-session"}) {
		t.Fatalf("attempts %v, want both direct endpoints before the data session", got)
	}
	n := len(a.list())
	a.closeAll()
	waitFor(t, "a new attempt after the session ended", func() bool { return len(a.list()) > n })
	if got := a.list()[n]; got != "direct" {
		t.Fatalf("after the data session ended the next attempt was %q, want a direct endpoint", got)
	}
	waitFor(t, "the data session again", func() bool { return welcomes(c) == 2 })
}

// cutter dials TCP until cut, which ends its connections and refuses new ones.
type cutter struct {
	mu    sync.Mutex
	cut   bool
	conns []net.Conn
}

func (c *cutter) dial(ctx context.Context, addr string) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cut {
		return nil, errors.New("the direct path to the controller is cut")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err == nil {
		c.conns = append(c.conns, conn)
	}
	return conn, err
}

func (c *cutter) cutNow() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cut = true
	for _, conn := range c.conns {
		_ = conn.Close()
	}
}

// TestControlPassthrough_EndToEnd: a connector whose direct path to the controller breaks keeps
// its control session through its data session to the gateway (CONTROL_PASSTHROUGH), with TLS end
// to end: the gateway relays the ClientHello's server name but never the session's content, here
// the agent version in Hello. The route keeps working throughout.
func TestControlPassthrough_EndToEnd(t *testing.T) {
	const marker = "0.1.0-ctlpassmarker"
	p := newDataPlane(t)
	p.dial(t)
	p.stopGateway()
	var rec relayed
	runRole(t, func(ctx context.Context, listening func()) error {
		return gateway.Run(ctx, gateway.RunOptions{Config: p.gwCfg, Version: "0.1.0", DrainPeriod: 200 * time.Millisecond,
			Listening: listening, ForwardDial: rec.dial})
	})
	p.stopConnector()
	var cut cutter
	runRole(t, func(ctx context.Context, listening func()) error {
		return connector.Run(ctx, connector.RunOptions{Config: p.conCfg, Version: marker, Getenv: func(string) string { return "" },
			Listening: listening, ControlDial: cut.dial})
	})
	conn := p.dial(t)
	waitFor(t, "a direct control session", func() bool { return slices.Contains(p.c.Sessions.Connected(), p.connector) })
	if len(rec.bytes()) != 0 {
		t.Fatal("the control session went through the gateway while the direct path worked")
	}

	cut.cutNow()
	waitFor(t, "a control session through the data session", func() bool {
		return len(rec.bytes()) > 0 && slices.Contains(p.c.Sessions.Connected(), p.connector)
	})
	seen := rec.bytes()
	if !bytes.Contains(seen, []byte("controller."+p.c.CA.TrustDomain())) {
		t.Fatal("the recording missed the ClientHello")
	}
	if bytes.Contains(seen, []byte(marker)) {
		t.Fatal("the gateway relayed the control session in clear")
	}
	if err := ping(conn, "the route still works"); err != nil {
		t.Fatal(err)
	}
}
