// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// TestChooser: the cached winner per gateway and local source address for 24 h, a race for a new
// address, and h2 without QUIC probes for an hour after a blackhole.
func TestChooser(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := connector.NewChooser(func() time.Time { return now })
	a, b := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.20")
	if got := c.Plan("gw_1", a); got != "" {
		t.Fatalf("no winner yet: %q, want a race", got)
	}
	c.Won("gw_1", a, connector.TransportH2)
	if got := c.Plan("gw_1", a); got != connector.TransportH2 {
		t.Fatalf("cached: %q", got)
	}
	if got := c.Plan("gw_1", b); got != "" {
		t.Fatalf("a new source address: %q, want a race", got)
	}
	if got := c.Plan("gw_2", a); got != "" {
		t.Fatalf("another gateway: %q, want a race", got)
	}
	now = now.Add(24*time.Hour - time.Second)
	if got := c.Plan("gw_1", a); got != connector.TransportH2 {
		t.Fatalf("just under 24 h: %q", got)
	}
	now = now.Add(time.Second)
	if got := c.Plan("gw_1", a); got != "" {
		t.Fatalf("after 24 h: %q, want a race", got)
	}
	c.Won("gw_1", a, connector.TransportQUIC)
	c.Forget("gw_1", a)
	if got := c.Plan("gw_1", a); got != "" {
		t.Fatalf("after a failed dial: %q, want a race", got)
	}

	c.Won("gw_1", a, connector.TransportQUIC)
	c.Blackholed("gw_1")
	if got := c.Plan("gw_1", a); got != connector.TransportH2 || c.MayProbe("gw_1") {
		t.Fatalf("demoted: %q, probe %v", got, c.MayProbe("gw_1"))
	}
	if !c.MayProbe("gw_2") {
		t.Fatal("another gateway is demoted too")
	}
	now = now.Add(time.Hour)
	if got := c.Plan("gw_1", a); got != "" || !c.MayProbe("gw_1") {
		t.Fatalf("after the hour: %q, probe %v; want a race", got, c.MayProbe("gw_1"))
	}
}

// TestIsBlackhole: only an idle timeout demotes QUIC.
func TestIsBlackhole(t *testing.T) {
	if !connector.IsBlackhole(fmt.Errorf("read: %w", &quic.IdleTimeoutError{})) {
		t.Fatal("an idle timeout")
	}
	for _, err := range []error{&quic.StatelessResetError{}, &quic.ApplicationError{}, errors.New("closed"), nil} {
		if connector.IsBlackhole(err) {
			t.Fatalf("%v counted as a blackhole", err)
		}
	}
}

// splitGateway is a test gateway whose QUIC and TCP sessions are separate, so that a test sees on
// which transport a route is offered.
func splitGateway(t *testing.T, w *world, blackhole bool) (*testGateway, *gateway.Sessions, *gateway.Sessions) {
	t.Helper()
	id := w.gatewayID()
	g := startGatewayWith(t, w, id, w.leaf(t, w.is, w.inter, id), blackhole)
	q := w.sessions(id)
	g.quicSessions.Store(q)
	return g, q, g.sessions.Load()
}

func readyAll(m *connector.Sessions, routes ...string) {
	for _, r := range routes {
		m.SetReady(&tunnelv1.RouteHealth{RouteId: r, Ready: true})
	}
}

// TestTransport_PinnedRouteUsesPinnedSessions: a route pinned to a transport is offered only on
// that transport's sessions, and an auto route only on the transport its race chose.
func TestTransport_PinnedRouteUsesPinnedSessions(t *testing.T) {
	w := newWorld(t)
	g, q, h := splitGateway(t, w, false)
	m := newConnector(t, w)
	readyAll(m, "rt_q", "rt_h", "rt_a")
	m.Set([]connector.Gateway{{ID: g.id.ID, Endpoints: []string{g.addr},
		Routes: map[string]string{"rt_q": connector.TransportQUIC, "rt_h": connector.TransportH2, "rt_a": connector.TransportAuto}}})
	// QUIC wins the race on loopback: the pinned and the auto link each hold a QUIC session.
	eventually(t, "sessions missing", func() bool { return q.Count()["quic"] == 2 && h.Count()["h2"] == 2 })
	for _, tc := range []struct {
		route     string
		on, notOn *gateway.Sessions
	}{{"rt_q", q, h}, {"rt_h", h, q}, {"rt_a", q, h}} {
		if err := echo(t, tc.on, tc.route); err != nil {
			t.Fatalf("%s on its transport: %v", tc.route, err)
		}
		if err := echo(t, tc.notOn, tc.route); !errors.Is(err, gateway.ErrNoSession) {
			t.Fatalf("%s on the other transport: %v", tc.route, err)
		}
	}
}

// TestTransport_PinNeverFallsBack: with UDP blocked, a route pinned to QUIC is never served over
// TCP and is not_ready(transport_unavailable: quic), while a route on auto moves to TCP; a route
// pinned to h2 whose gateway refuses TCP is unavailable too.
func TestTransport_PinNeverFallsBack(t *testing.T) {
	w := newWorld(t)
	g, _, h := splitGateway(t, w, true)
	m := newConnectorOptions(t, w, func(o *connector.Options) { o.QUIC = nil }) // no UDP: QUIC fails at once
	readyAll(m, "rt_q", "rt_h", "rt_a")
	m.Set([]connector.Gateway{
		{ID: g.id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_q": connector.TransportQUIC, "rt_a": connector.TransportAuto}},
		{ID: w.gatewayID().ID, Endpoints: []string{"127.0.0.1:1"}, Routes: map[string]string{"rt_h": connector.TransportH2}},
	})
	eventually(t, "the pins are not reported unavailable", func() bool {
		st := m.Status()
		return len(st) == 2 && st[0].GetResourceId() == "rt_h" && st[0].GetDetail() == "h2" &&
			st[1].GetResourceId() == "rt_q" && st[1].GetDetail() == "quic" &&
			st[1].GetReason() == agentv1.NotReadyReason_NOT_READY_REASON_TRANSPORT_UNAVAILABLE
	})
	eventually(t, "the auto route did not move to TCP", func() bool { return echo(t, h, "rt_a") == nil })
	if err := echo(t, h, "rt_q"); !errors.Is(err, gateway.ErrNoSession) {
		t.Fatalf("the route pinned to QUIC went over TCP: %v", err)
	}
	eventually(t, "not only the auto link's two TCP connections", func() bool {
		got := m.Count()
		return got[g.id.ID+"/quic"] == 0 && got[g.id.ID+"/h2"] == 2 && len(got) == 1
	})
}

// TestTransport_UDPBlocked: with UDP blackholed, TCP starts after 300 ms and wins; the winner is
// TestTransport_UDPBlocked: with UDP blackholed, TCP starts after 300 ms and wins.
func TestTransport_UDPBlocked(t *testing.T) {
	w := newWorld(t)
	g, _, h := splitGateway(t, w, true)
	m := newConnector(t, w)
	readyAll(m, "rt_a")
	start := time.Now()
	m.Set([]connector.Gateway{{ID: g.id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_a": connector.TransportAuto}}})
	eventually(t, "no TCP session", func() bool { return h.Count()["h2"] >= 1 })
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("TCP took %s; want 300 ms plus a loopback handshake", d)
	} else {
		t.Logf("the first TCP session after %s", d)
	}
	eventually(t, "not both TCP connections", func() bool { return h.Count()["h2"] == 2 })
	if err := echo(t, h, "rt_a"); err != nil {
		t.Fatal(err)
	}
}

// TestTransport_RaceCache: the winner of a race is used again from the same source address without
// a race, and a new source address races again. QUIC gets a 2 s head start here, so that its
// packets reach the blackhole on a slow machine before TCP wins: they are how the test sees a race.
func TestTransport_RaceCache(t *testing.T) {
	connector.SetTransportTimers(t, 2*time.Second, 10*time.Minute, time.Hour)
	w := newWorld(t)
	g, _, h := splitGateway(t, w, true)
	var local atomic.Pointer[netip.Addr]
	a, b := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.20")
	local.Store(&a)
	m := newConnectorOptions(t, w, func(o *connector.Options) {
		o.LocalAddr = func(context.Context, string) (netip.Addr, error) { return *local.Load(), nil }
	})
	readyAll(m, "rt_a")
	m.Set([]connector.Gateway{{ID: g.id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_a": connector.TransportAuto}}})
	eventually(t, "not both TCP connections", func() bool { return h.Count()["h2"] == 2 })
	if g.udpPackets.Load() == 0 {
		t.Fatal("QUIC was never tried")
	}

	// The gateway restarts: from the same source address, h2 without a race.
	reconnect := func() {
		t.Helper()
		h.Close()
		eventually(t, "no reconnection", func() bool { return h.Count()["h2"] == 2 })
	}
	time.Sleep(200 * time.Millisecond) // let the cancelled QUIC dial stop
	before := g.udpPackets.Load()
	reconnect()
	time.Sleep(200 * time.Millisecond)
	if after := g.udpPackets.Load(); after != before {
		t.Fatalf("%d QUIC packets from a cached source address", after-before)
	}
	// From a new source address, a new race.
	local.Store(&b)
	reconnect()
	eventually(t, "no race from a new source address", func() bool { return g.udpPackets.Load() > before })
}

// TestTransport_ChangeKeepsOpenConnections: when QUIC comes back, the re-probe moves the auto
// route to QUIC; and when the route is pinned to h2 later, it moves back. Each time new
// connections use the new sessions at once, and a connection already open finishes on its old
// session, which closes after it.
func TestTransport_ChangeKeepsOpenConnections(t *testing.T) {
	connector.SetTransportTimers(t, 300*time.Millisecond, 300*time.Millisecond, time.Hour)
	w := newWorld(t)
	g, q, h := splitGateway(t, w, true)
	m := newConnector(t, w)
	readyAll(m, "rt_1")
	entry := connector.Gateway{ID: g.id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_1": connector.TransportAuto}}
	m.Set([]connector.Gateway{entry})
	eventually(t, "no TCP session", func() bool { return h.Count()["h2"] == 2 })

	held := openHeld(t, h, "rt_1")
	g.enableQUIC(t)
	eventually(t, "the re-probe did not move the route to QUIC", func() bool { return echo(t, q, "rt_1") == nil })
	eventually(t, "new connections still go over TCP", func() bool { return errors.Is(echo(t, h, "rt_1"), gateway.ErrNoSession) })
	held.check(t, "after the move to QUIC")
	if h.Count()["h2"] == 0 {
		t.Fatal("the TCP session closed under an open connection")
	}
	held.close(t)
	eventually(t, "the idle TCP sessions stay open", func() bool { return len(h.Count()) == 0 })

	// A pin to h2 in a new snapshot: the same, the other way round; an unchanged route next to it
	// keeps its session and its connections.
	readyAll(m, "rt_u")
	entry.Routes = map[string]string{"rt_1": connector.TransportAuto, "rt_u": connector.TransportAuto}
	m.Set([]connector.Gateway{entry})
	eventually(t, "the added route is not offered", func() bool { return echo(t, q, "rt_u") == nil })
	unchanged := openHeld(t, q, "rt_u")
	held = openHeld(t, q, "rt_1")
	entry.Routes = map[string]string{"rt_1": connector.TransportH2, "rt_u": connector.TransportAuto}
	m.Set([]connector.Gateway{entry})
	eventually(t, "the pin did not move the route to TCP", func() bool { return echo(t, h, "rt_1") == nil })
	if err := echo(t, q, "rt_1"); !errors.Is(err, gateway.ErrNoSession) {
		t.Fatalf("a new connection over QUIC after the pin: %v", err)
	}
	held.check(t, "after the pin")
	held.close(t)
	unchanged.check(t, "on the unchanged route")
	if err := echo(t, q, "rt_u"); err != nil {
		t.Fatalf("a new connection on the unchanged route: %v", err)
	}
	unchanged.close(t)
	if q.Count()["quic"] != 1 {
		t.Fatalf("the unchanged route's QUIC session: %v", q.Count())
	}
}

// held is a connection kept open across a transport change.
type held struct {
	st interface {
		io.ReadWriter
		CloseWrite() error
		Close() error
	}
}

func openHeld(t *testing.T, s *gateway.Sessions, route string) held {
	t.Helper()
	st, code, err := s.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: route})
	if err != nil || code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Fatalf("%s %v", code, err)
	}
	h := held{st}
	h.check(t, "when opened")
	return h
}

func (h held) check(t *testing.T, when string) {
	t.Helper()
	if _, err := h.st.Write([]byte("ping")); err != nil {
		t.Fatalf("%s: %v", when, err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(h.st, b); err != nil || string(b) != "ping" {
		t.Fatalf("%s: %q %v", when, b, err)
	}
}

func (h held) close(t *testing.T) {
	t.Helper()
	_ = h.st.CloseWrite()
	_, _ = io.ReadAll(h.st)
	_ = h.st.Close()
}
