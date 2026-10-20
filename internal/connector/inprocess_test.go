// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

// inProcess reaches the test gateway g through Dial, as all-in-one's memory listener would: the
// endpoints the snapshot names are never dialled. fail makes the next dials fail.
func inProcess(g *testGateway, fail *atomic.Int64, dials *atomic.Int64) *connector.InProcess {
	return &connector.InProcess{GatewayID: g.id.ID, Dial: func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		if fail != nil && fail.Add(-1) >= 0 {
			return nil, errors.New("the gateway does not accept yet")
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", g.addr)
	}}
}

// TestInProcess_OneSessionForEveryRoute: the in-process gateway gets one h2 session in memory that
// carries its routes pinned to QUIC, pinned to h2 and on auto, and its endpoints are never dialled;
// another gateway in the same snapshot keeps its own transports.
func TestInProcess_OneSessionForEveryRoute(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	local := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	otherID := w.gatewayID()
	other := startGateway(t, w, otherID, w.leaf(t, w.is, w.inter, otherID))
	var dials atomic.Int64
	m := newConnectorOptions(t, w, func(o *connector.Options) { o.InProcess = inProcess(local, nil, &dials) })
	readyAll(m, "rt_q", "rt_h", "rt_a")
	m.Set([]connector.Gateway{
		{ID: id.ID, Endpoints: []string{"127.0.0.1:1"},
			Routes: map[string]string{"rt_q": connector.TransportQUIC, "rt_h": connector.TransportH2, "rt_a": connector.TransportAuto}},
		{ID: otherID.ID, Endpoints: []string{other.addr}, Routes: map[string]string{"rt_q": connector.TransportQUIC}},
	})
	eventually(t, "no session to each gateway", func() bool {
		got := m.Count()
		return local.sessions.Load().Count()["h2"] == 1 && got[id.ID+"/h2"] == 1 && got[otherID.ID+"/quic"] == connector.QUICSessions && len(got) == 2
	})
	for _, r := range []string{"rt_q", "rt_h", "rt_a"} {
		if err := echo(t, local.sessions.Load(), r); err != nil {
			t.Fatalf("%s through the in-process session: %v", r, err)
		}
	}
	if err := echo(t, other.sessions.Load(), "rt_q"); err != nil {
		t.Fatalf("the other gateway: %v", err)
	}
	select {
	case sni := <-local.serverName:
		if sni != id.DNSName() {
			t.Fatalf("ServerName %q, want %q", sni, id.DNSName())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no handshake reached the in-process gateway")
	}
	time.Sleep(200 * time.Millisecond)
	if local.quicConns.Load() != 0 || dials.Load() != 1 || len(m.Status()) != 0 {
		t.Fatalf("QUIC sessions %d, in-memory dials %d, status %v", local.quicConns.Load(), dials.Load(), m.Status())
	}
}

// TestInProcess_WrongGatewayRefused: the in-memory session checks the gateway's identity as a
// session over TCP does: a gateway of another organisation is refused, and the routes are
// not_ready(transport_unavailable: memory).
func TestInProcess_WrongGatewayRefused(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	stranger := pki.Identity{TrustDomain: td, Org: ids.New("org"), Kind: pki.KindGateway, ID: ids.New("gw")}
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, stranger))
	var dials atomic.Int64
	m := newConnectorOptions(t, w, func(o *connector.Options) { o.InProcess = inProcess(g, nil, &dials) })
	readyAll(m, "rt_a")
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_a": connector.TransportAuto}}})
	select {
	case err := <-g.tcpErrs:
		t.Logf("the gateway's handshake failed as expected: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no handshake failed")
	}
	eventually(t, "the route is not reported unavailable", func() bool {
		st := m.Status()
		return len(st) == 1 && st[0].GetResourceId() == "rt_a" && st[0].GetDetail() == "memory" &&
			st[0].GetReason() == agentv1.NotReadyReason_NOT_READY_REASON_TRANSPORT_UNAVAILABLE
	})
	if got := m.Count(); len(got) != 0 || len(g.sessions.Load().Count()) != 0 || g.quicConns.Load() != 0 {
		t.Fatalf("sessions %v / %v to a gateway with the wrong certificate", got, g.sessions.Load().Count())
	}
}

// TestInProcess_Retries: while the in-process gateway does not accept, the connector redials with
// its backoff, and the route is served once it does.
func TestInProcess_Retries(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	var fail, dials atomic.Int64
	fail.Store(2)
	m := newConnectorOptions(t, w, func(o *connector.Options) { o.InProcess = inProcess(g, &fail, &dials) })
	readyAll(m, "rt_h")
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{"127.0.0.1:1"}, Routes: map[string]string{"rt_h": connector.TransportH2}}})
	eventually(t, "no session after the gateway accepted", func() bool { return g.sessions.Load().Count()["h2"] == 1 })
	if err := echo(t, g.sessions.Load(), "rt_h"); err != nil {
		t.Fatal(err)
	}
	if n := dials.Load(); n != 3 {
		t.Fatalf("%d dials, want 2 failed and 1 that worked", n)
	}
	if st := m.Status(); len(st) != 0 {
		t.Fatalf("status %v once the session is up", st)
	}
}

// TestInProcess_ServedElsewhere: a route on auto that another gateway serves is not reported
// transport_unavailable while the in-memory link to the in-process gateway fails.
func TestInProcess_ServedElsewhere(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	local := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	otherID := w.gatewayID()
	other := startGateway(t, w, otherID, w.leaf(t, w.is, w.inter, otherID))
	var fail, dials atomic.Int64
	fail.Store(1 << 30) // the in-process gateway never accepts
	m := newConnectorOptions(t, w, func(o *connector.Options) { o.InProcess = inProcess(local, &fail, &dials) })
	readyAll(m, "rt_a")
	m.Set([]connector.Gateway{
		{ID: id.ID, Endpoints: []string{local.addr}, Routes: map[string]string{"rt_a": connector.TransportAuto}},
		{ID: otherID.ID, Endpoints: []string{other.addr}, Routes: map[string]string{"rt_a": connector.TransportAuto}},
	})
	eventually(t, "the other gateway does not serve the route", func() bool { return echo(t, other.sessions.Load(), "rt_a") == nil })
	eventually(t, "the in-memory link was not tried", func() bool { return dials.Load() > 0 })
	time.Sleep(200 * time.Millisecond)
	if st := m.Status(); len(st) != 0 {
		t.Fatalf("status %v for a route another gateway serves", st)
	}
	if len(local.sessions.Load().Count()) != 0 {
		t.Fatal("a session to the in-process gateway")
	}
}
