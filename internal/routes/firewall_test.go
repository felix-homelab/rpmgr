// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"testing"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestCompile_GatewayPortPools (D152): a gateway that announces firewall.ranges gets the pools of
// its own group, a resize shows, a deletion removes them, and a gateway without the capability, a
// disabled one and a connector get none.
func TestCompile_GatewayPortPools(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		pools := func(kind pki.Kind, id string, caps ...string) map[string]*agentv1.GatewayPortPool {
			out := map[string]*agentv1.GatewayPortPool{}
			for _, r := range f.compileAs(t, kind, id, caps...) {
				if p := r.GetGatewayPortPool(); p != nil {
					out[r.GetId()] = p
				}
			}
			return out
		}
		got := pools(pki.KindGateway, f.gateway, agentproto.CapFirewallRanges)
		if len(got) != 1 {
			t.Fatalf("pools %v, want the group's one", got)
		}
		var id string
		for k, p := range got {
			id = k
			if p.GetProtocol() != "tcp" || p.GetPortFrom() != 20000 || p.GetPortTo() != 20099 {
				t.Errorf("pool %v", p)
			}
		}
		if got := pools(pki.KindGateway, f.gateway); len(got) != 0 {
			t.Errorf("a gateway that does not announce firewall.ranges got %v: it would refuse the resource", got)
		}
		if got := pools(pki.KindConnector, f.c1, agentproto.CapFirewallRanges); len(got) != 0 {
			t.Errorf("a connector got %v", got)
		}
		// Another group's pool is not this gateway's.
		other := db.Client().GatewayGroup.Create().SetOrgID(f.orgA).SetName("eu2").SaveX(f.sys).ID
		if err := f.pool(t, f.orgA, other, routes.UDP, 30000, 30009); err != nil {
			t.Fatal(err)
		}
		if got := pools(pki.KindGateway, f.gateway, agentproto.CapFirewallRanges); len(got) != 1 {
			t.Errorf("another group's pool shows: %v", got)
		}
		// A resize shows in the resource, which changes its hash, so the gateway gets a new snapshot.
		before := hashOf(t, f.compileAs(t, pki.KindGateway, f.gateway, agentproto.CapFirewallRanges), id)
		if err := f.tx(t, func(tx *ent.Tx) error {
			_, err := routes.ResizePool(f.sys, tx, tx.PortPool.GetX(f.sys, id), 20000, 20199)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if p := pools(pki.KindGateway, f.gateway, agentproto.CapFirewallRanges)[id]; p.GetPortTo() != 20199 {
			t.Errorf("after the resize: %v", p)
		}
		if hashOf(t, f.compileAs(t, pki.KindGateway, f.gateway, agentproto.CapFirewallRanges), id) == before {
			t.Error("a resized pool has the hash it had")
		}
		// A disabled gateway drains and closes its ranges.
		db.Client().Gateway.UpdateOneID(f.gateway).SetEnabled(false).ExecX(f.sys)
		if got := pools(pki.KindGateway, f.gateway, agentproto.CapFirewallRanges); len(got) != 0 {
			t.Errorf("a disabled gateway got %v", got)
		}
		db.Client().Gateway.UpdateOneID(f.gateway).SetEnabled(true).ExecX(f.sys)
		// A deleted pool is gone.
		db.Client().PortPool.DeleteOneID(id).ExecX(f.sys)
		if got := pools(pki.KindGateway, f.gateway, agentproto.CapFirewallRanges); len(got) != 0 {
			t.Errorf("a deleted pool shows: %v", got)
		}
	})
}

// TestCompile_GatewayPortPoolsOtherOrg: a pool of another org never reaches a gateway, neither
// that of a group of the same name nor one stored in the gateway's own group.
func TestCompile_GatewayPortPoolsOtherOrg(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		f := newFleet(t, db)
		if err := f.pool(t, f.orgB, f.groupB, routes.TCP, 40000, 40009); err != nil { // groupB is named "eu" like groupA
			t.Fatal(err)
		}
		// A pool of org B in group A cannot exist: the database's foreign key holds a pool to the org
		// of its group.
		if err := db.Client().PortPool.Create().SetOrgID(f.orgB).SetGatewayGroupID(f.groupA).SetProtocol("udp").
			SetPortFrom(50000).SetPortTo(50009).Exec(f.sys); err == nil {
			t.Error("a pool of another org was stored in the group")
		}
		var ranges []string
		for _, r := range f.compileAs(t, pki.KindGateway, f.gateway, agentproto.CapFirewallRanges) {
			if p := r.GetGatewayPortPool(); p != nil {
				ranges = append(ranges, p.GetProtocol())
				if p.GetPortFrom() != 20000 || p.GetPortTo() != 20099 {
					t.Errorf("a gateway of org A got the pool %v", p)
				}
			}
		}
		if len(ranges) != 1 {
			t.Errorf("pools %v, want the group's own one", ranges)
		}
	})
}

func hashOf(t *testing.T, rs []*agentv1.Resource, id string) string {
	t.Helper()
	for _, r := range rs {
		if r.GetId() == id {
			return string(r.GetHash())
		}
	}
	t.Fatalf("no resource %s", id)
	return ""
}
