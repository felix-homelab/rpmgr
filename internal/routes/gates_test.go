// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// gate registers a gate of kind for capability that the routes ids use, until the test ends.
func gate(t *testing.T, kind pki.Kind, capability string, ids ...string) {
	t.Helper()
	t.Cleanup(routes.Register(routes.Gate{Capability: capability, Kind: kind,
		Uses: func(_ context.Context, _ *ent.Client, id string) (bool, error) { return slices.Contains(ids, id), nil }}))
}

// compileAs compiles the snapshot of an agent of the fleet's org that announces caps.
func (f *fleet) compileAs(t *testing.T, kind pki.Kind, id string, caps ...string) []*agentv1.Resource {
	t.Helper()
	c := &snapshot.Compiler{Sources: routes.Sources()}
	snap, err := c.Compile(f.sys, f.db, snapshot.Agent{Identity: pki.Identity{TrustDomain: "rpmgr-teststor", Org: f.orgA, Kind: kind, ID: id},
		Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	return snap.GetResources()
}

func ids(rs []*agentv1.Resource) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.GetId()
	}
	return out
}

// TestCompile_GatedRouteNeverReachesOldGateway (docs/12, D113): a route that uses a gated feature
// is left out of the snapshot of every gateway that does not announce the feature's capability,
// whatever the route's type, and only that route; a gateway that announces it, or announces it
// after reconnecting, gets the route as before. A gate of the other kind leaves gateways alone.
func TestCompile_GatedRouteNeverReachesOldGateway(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		c := db.Client()
		gw2 := c.Gateway.Create().SetOrgID(f.orgA).SetGatewayGroupID(f.groupA).SetName("gw2").SetSlot(2).
			SetTunnelEndpoints([]string{"gw2.example:443"}).SaveX(f.sys).ID
		f.verifiedExample(t)
		web := f.httpRoute(t, "web", true, true, nil, "www.example.com")
		c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(web).SetConnectorID(f.c1).SetKind("address").SetHost("10.0.0.80").
			SetPort(8080).SetUpstreamProtocol(routetarget.UpstreamProtocolTCP).ExecX(f.sys)
		plain := f.httpRoute(t, "plain", true, true, nil, "plain.example.com")
		c.RouteTarget.Create().SetOrgID(f.orgA).SetRouteID(plain).SetConnectorID(f.c1).SetKind("address").SetHost("10.0.0.81").
			SetPort(8080).SetUpstreamProtocol(routetarget.UpstreamProtocolTCP).ExecX(f.sys)
		before := ids(f.compileAs(t, pki.KindGateway, f.gateway))
		if !slices.Contains(before, f.r1) || !slices.Contains(before, web) || !slices.Contains(before, plain) {
			t.Fatalf("without a gate the gateway gets %v", before)
		}

		gate(t, pki.KindGateway, "test.gated", f.r1, web)
		old := ids(f.compileAs(t, pki.KindGateway, f.gateway, "tunnel.quic", "tunnel.h2"))
		if slices.Contains(old, f.r1) || slices.Contains(old, web) {
			t.Fatalf("an old gateway got a gated route: %v", old)
		}
		if want := slices.DeleteFunc(slices.Clone(before), func(id string) bool { return id == f.r1 || id == web }); !slices.Equal(old, want) {
			t.Fatalf("an old gateway gets %v, want everything else %v", old, want)
		}
		// The other gateway of the group announces it; so does the first after reconnecting.
		if got := ids(f.compileAs(t, pki.KindGateway, gw2, "test.gated")); !slices.Contains(got, f.r1) || !slices.Contains(got, web) {
			t.Fatalf("a new gateway: %v", got)
		}
		if got := ids(f.compileAs(t, pki.KindGateway, f.gateway, "tunnel.quic", "test.gated")); !slices.Equal(got, before) {
			t.Fatalf("after reconnecting with the capability: %v, want %v", got, before)
		}
		// The gate is the gateway's: connectors keep the route.
		if rs := routesOf(f.compileAs(t, pki.KindConnector, f.c1)); !slices.Contains(ids(rs), f.r1) || !slices.Contains(ids(rs), web) {
			t.Fatalf("a connector lost a gateway-gated route: %v", ids(rs))
		}
	})
}

// TestCompile_Gates: a connector gate withholds the route from connectors without the capability;
// with two gates an agent needs both; Required lists each capability once, sorted; a removed gate
// withholds nothing; an error of a gate fails the compilation; an invalid gate panics.
func TestCompile_Gates(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		gate(t, pki.KindConnector, "test.conn", f.r1)
		if rs := routesOf(f.compileAs(t, pki.KindConnector, f.c1)); slices.Contains(ids(rs), f.r1) {
			t.Fatalf("a connector without the capability got the route: %v", ids(rs))
		}
		if rs := routesOf(f.compileAs(t, pki.KindConnector, f.c1, "test.conn")); !slices.Contains(ids(rs), f.r1) {
			t.Fatalf("a connector with the capability: %v", ids(rs))
		}
		if got := ids(f.compileAs(t, pki.KindGateway, f.gateway)); !slices.Contains(got, f.r1) {
			t.Fatalf("a connector gate withheld the route from a gateway: %v", got)
		}

		gate(t, pki.KindGateway, "test.b", f.r1)
		gate(t, pki.KindGateway, "test.a", f.r1)
		gate(t, pki.KindGateway, "test.a", f.r1)
		reqs, err := routes.Required(f.sys, db.Client(), f.r1)
		if err != nil {
			t.Fatal(err)
		}
		want := []routes.Requirement{{Kind: pki.KindConnector, Capability: "test.conn"}, {Kind: pki.KindGateway, Capability: "test.a"},
			{Kind: pki.KindGateway, Capability: "test.b"}}
		if !slices.Equal(reqs, want) {
			t.Fatalf("Required: %v, want %v", reqs, want)
		}
		if got := routes.Missing(reqs, pki.KindGateway, func(c string) bool { return c == "test.a" }); !slices.Equal(got, []string{"test.b"}) {
			t.Fatalf("Missing: %v", got)
		}
		if got := ids(f.compileAs(t, pki.KindGateway, f.gateway, "test.a")); slices.Contains(got, f.r1) {
			t.Fatalf("a gateway with one of two capabilities got the route: %v", got)
		}
		if got := ids(f.compileAs(t, pki.KindGateway, f.gateway, "test.b", "test.a")); !slices.Contains(got, f.r1) {
			t.Fatalf("a gateway with both: %v", got)
		}
		if reqs, err := routes.Required(f.sys, db.Client(), "rte_unknown"); err != nil || len(reqs) != 0 {
			t.Fatalf("a route no gate uses: %v, %v", reqs, err)
		}

		remove := routes.Register(routes.Gate{Capability: "test.c", Kind: pki.KindGateway,
			Uses: func(_ context.Context, _ *ent.Client, id string) (bool, error) { return id == f.r1, nil }})
		remove()
		if got := ids(f.compileAs(t, pki.KindGateway, f.gateway, "test.a", "test.b")); !slices.Contains(got, f.r1) {
			t.Fatalf("a removed gate still withholds: %v", got)
		}

		boom := errors.New("boom")
		t.Cleanup(routes.Register(routes.Gate{Capability: "test.err", Kind: pki.KindGateway,
			Uses: func(_ context.Context, _ *ent.Client, id string) (bool, error) {
				if id == f.r1 {
					return false, boom
				}
				return false, nil
			}}))
		c := &snapshot.Compiler{Sources: routes.Sources()}
		if _, err := c.Compile(f.sys, f.db, snapshot.Agent{Identity: pki.Identity{TrustDomain: "rpmgr-teststor", Org: f.orgA,
			Kind: pki.KindGateway, ID: f.gateway}}); !errors.Is(err, boom) {
			t.Fatalf("a failing gate: %v", err)
		}
	})
	for _, g := range []routes.Gate{
		{Kind: pki.KindGateway, Uses: func(context.Context, *ent.Client, string) (bool, error) { return false, nil }},
		{Capability: "x", Kind: pki.KindGateway},
		{Capability: "x", Kind: pki.KindController, Uses: func(context.Context, *ent.Client, string) (bool, error) { return false, nil }},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%+v) did not panic", g)
				}
			}()
			routes.Register(g)
		}()
	}
}
