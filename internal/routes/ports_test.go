// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"context"
	"errors"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portpool"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

type env struct {
	db             *store.DB
	sys            context.Context
	orgA, orgB     string
	groupA, groupB string
}

func newEnv(t *testing.T, db *store.DB) *env {
	t.Helper()
	storetest.Init(t, db)
	e := &env{db: db, sys: storetest.SystemCtx(t), orgA: storetest.Org(t, db, "org-a"), orgB: storetest.Org(t, db, "org-b")}
	e.groupA = db.Client().GatewayGroup.Create().SetOrgID(e.orgA).SetName("eu").SaveX(e.sys).ID
	e.groupB = db.Client().GatewayGroup.Create().SetOrgID(e.orgB).SetName("eu").SaveX(e.sys).ID
	return e
}

func (e *env) tx(t *testing.T, f func(tx *ent.Tx) error) error {
	t.Helper()
	return store.WriteTx(e.sys, e.db, f)
}

func (e *env) pool(t *testing.T, org, group string, p routes.Protocol, from, to int) error {
	t.Helper()
	return e.tx(t, func(tx *ent.Tx) error { _, err := routes.AddPool(e.sys, tx, org, group, p, from, to); return err })
}

func (e *env) alloc(t *testing.T, org, group string, p routes.Protocol, port int) (int, error) {
	t.Helper()
	var got int
	err := e.tx(t, func(tx *ent.Tx) error {
		a, err := routes.Allocate(e.sys, tx, org, group, p, port)
		if err == nil {
			got = a.Port
		}
		return err
	})
	return got, err
}

func TestPools(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		if err := e.pool(t, e.orgA, e.groupA, routes.TCP, 20000, 20099); err != nil {
			t.Fatal(err)
		}
		for name, tc := range map[string]struct {
			org, group string
			p          routes.Protocol
			from, to   int
			want       error
		}{
			"overlap at the end":  {e.orgA, e.groupA, routes.TCP, 20099, 20200, routes.ErrPoolOverlap},
			"overlap inside":      {e.orgA, e.groupA, routes.TCP, 20010, 20020, routes.ErrPoolOverlap},
			"another org's group": {e.orgA, e.groupB, routes.TCP, 30000, 30010, routes.ErrNoGroup},
			"reversed":            {e.orgA, e.groupA, routes.TCP, 30010, 30000, routes.ErrPoolRange},
			"port 0":              {e.orgA, e.groupA, routes.TCP, 0, 10, routes.ErrPoolRange},
			"port 65536":          {e.orgA, e.groupA, routes.TCP, 65530, 65536, routes.ErrPoolRange},
		} {
			err := e.pool(t, tc.org, tc.group, tc.p, tc.from, tc.to)
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("%s: %v, want %v", name, err, tc.want)
			}
		}
		for name, r := range map[string][2]int{"adjacent": {20100, 20199}, "UDP on the same ports": {20000, 20099}} {
			p := routes.TCP
			if name == "UDP on the same ports" {
				p = routes.UDP
			}
			if err := e.pool(t, e.orgA, e.groupA, p, r[0], r[1]); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}

// TestResizePool: a pool grows and shrinks, but never over another pool of its group and
// protocol, never past the port bounds, and never so that an allocated port falls outside.
func TestResizePool(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		for _, r := range [][2]int{{20000, 20099}, {20200, 20299}} {
			if err := e.pool(t, e.orgA, e.groupA, routes.TCP, r[0], r[1]); err != nil {
				t.Fatal(err)
			}
		}
		if err := e.pool(t, e.orgA, e.groupA, routes.UDP, 20100, 20199); err != nil {
			t.Fatal(err)
		}
		for _, port := range []int{20010, 20090} {
			if _, err := e.alloc(t, e.orgA, e.groupA, routes.TCP, port); err != nil {
				t.Fatal(err)
			}
		}
		resize := func(from, to int) (*ent.PortPool, error) {
			var got *ent.PortPool
			err := e.tx(t, func(tx *ent.Tx) error {
				pool, err := tx.PortPool.Query().Where(portpool.GatewayGroupID(e.groupA), portpool.ProtocolEQ(portpool.ProtocolTCP),
					portpool.PortFromLTE(20010), portpool.PortToGTE(20010)).Only(e.sys)
				if err != nil {
					return err
				}
				got, err = routes.ResizePool(e.sys, tx, pool, from, to)
				return err
			})
			return got, err
		}
		for name, tc := range map[string]struct {
			from, to int
			want     error
		}{
			"onto the next pool":         {20000, 20200, routes.ErrPoolOverlap},
			"leaving out the last port":  {20000, 20089, routes.ErrPoolInUse},
			"leaving out the first port": {20011, 20099, routes.ErrPoolInUse},
			"reversed":                   {20099, 20000, routes.ErrPoolRange},
			"to port 0":                  {0, 20099, routes.ErrPoolRange},
			"past 65535":                 {20000, 65536, routes.ErrPoolRange},
		} {
			if _, err := resize(tc.from, tc.to); !errors.Is(err, tc.want) {
				t.Errorf("%s: %v, want %v", name, err, tc.want)
			}
		}
		// The UDP pool on 20100-20199 is no obstacle to a TCP pool.
		got, err := resize(19000, 20199)
		if err != nil || got.PortFrom != 19000 || got.PortTo != 20199 || got.Version != 2 {
			t.Fatalf("a growth up to the next pool: %v %v", got, err)
		}
		if got, err = resize(20010, 20090); err != nil || got.PortFrom != 20010 || got.PortTo != 20090 {
			t.Fatalf("a shrink to the allocated ports: %v %v", got, err)
		}
	})
}

func TestAllocate(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		if err := e.pool(t, e.orgA, e.groupA, routes.TCP, 20000, 20009); err != nil {
			t.Fatal(err)
		}
		if port, err := e.alloc(t, e.orgA, e.groupA, routes.TCP, 20005); err != nil || port != 20005 {
			t.Fatalf("an explicit port: %d %v", port, err)
		}
		if _, err := e.alloc(t, e.orgA, e.groupA, routes.TCP, 20005); !errors.Is(err, routes.ErrPortTaken) {
			t.Fatalf("a taken port: %v", err)
		}
		if _, err := e.alloc(t, e.orgA, e.groupA, routes.TCP, 20010); !errors.Is(err, routes.ErrNotInPool) {
			t.Fatalf("a port outside the pools: %v", err)
		}
		if _, err := e.alloc(t, e.orgA, e.groupA, routes.UDP, 20000); !errors.Is(err, routes.ErrNotInPool) {
			t.Fatalf("a UDP port in a TCP pool: %v", err)
		}
		if _, err := e.alloc(t, e.orgB, e.groupA, routes.TCP, 0); !errors.Is(err, routes.ErrNoGroup) {
			t.Fatalf("another org's group: %v", err)
		}
		seen := map[int]bool{20005: true}
		for range 9 {
			port, err := e.alloc(t, e.orgA, e.groupA, routes.TCP, 0)
			if err != nil || port < 20000 || port > 20009 || seen[port] {
				t.Fatalf("a random port: %d %v", port, err)
			}
			seen[port] = true
		}
		if _, err := e.alloc(t, e.orgA, e.groupA, routes.TCP, 0); !errors.Is(err, routes.ErrPoolExhausted) {
			t.Fatalf("an exhausted pool: %v", err)
		}
		// A released port can be allocated again.
		if err := e.tx(t, func(tx *ent.Tx) error {
			a := tx.PortAllocation.Query().FirstX(e.sys)
			return routes.Release(e.sys, tx, a.ID)
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.alloc(t, e.orgA, e.groupA, routes.TCP, 0); err != nil {
			t.Fatalf("after a release: %v", err)
		}
	})
}

// TestQuota: a quota caps an org's allocations in a group; without one only the pools do.
func TestQuota(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		for _, p := range []routes.Protocol{routes.TCP, routes.UDP} {
			if err := e.pool(t, e.orgA, e.groupA, p, 20000, 20099); err != nil {
				t.Fatal(err)
			}
		}
		db.Client().PortQuota.Create().SetOrgID(e.orgA).SetGatewayGroupID(e.groupA).SetProtocol("tcp").SetMaxPorts(2).SaveX(e.sys)
		for range 2 {
			if _, err := e.alloc(t, e.orgA, e.groupA, routes.TCP, 0); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := e.alloc(t, e.orgA, e.groupA, routes.TCP, 0); !errors.Is(err, routes.ErrQuotaReached) {
			t.Fatalf("over the quota: %v", err)
		}
		for range 5 { // no UDP quota: the pool limits
			if _, err := e.alloc(t, e.orgA, e.groupA, routes.UDP, 0); err != nil {
				t.Fatalf("UDP without a quota: %v", err)
			}
		}
		db.Client().PortQuota.Create().SetOrgID(e.orgA).SetGatewayGroupID(e.groupA).SetProtocol("udp").SetMaxPorts(0).SaveX(e.sys)
		if _, err := e.alloc(t, e.orgA, e.groupA, routes.UDP, 0); !errors.Is(err, routes.ErrQuotaReached) {
			t.Fatalf("a quota of 0: %v", err)
		}
	})
}

// TestRouteTarget_CrossOrgRefused: a route's target cannot name another org's connector; the
// composite foreign key refuses it even in the system scope.
func TestRouteTarget_CrossOrgRefused(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		c := db.Client()
		route := c.Route.Create().SetOrgID(e.orgA).SetName("db").SetType("tcp").SetGatewayGroupID(e.groupA).SaveX(e.sys)
		mine := c.Connector.Create().SetOrgID(e.orgA).SetName("c1").SetSpiffeID("spiffe://x/a").SetPubkeySha256("a").SaveX(e.sys)
		theirs := c.Connector.Create().SetOrgID(e.orgB).SetName("c1").SetSpiffeID("spiffe://x/b").SetPubkeySha256("b").SaveX(e.sys)
		if _, err := c.RouteTarget.Create().SetOrgID(e.orgA).SetRouteID(route.ID).SetConnectorID(mine.ID).SetKind("address").
			SetHost("10.0.0.5").SetPort(5432).Save(e.sys); err != nil {
			t.Fatalf("a target on the org's connector: %v", err)
		}
		if _, err := c.RouteTarget.Create().SetOrgID(e.orgA).SetRouteID(route.ID).SetConnectorID(theirs.ID).SetKind("address").
			SetHost("10.0.0.5").SetPort(5432).Save(e.sys); err == nil {
			t.Fatal("a target on another org's connector was stored")
		}
	})
}

// TestRouteTCP_Unique: a tcp route has one row, and a port allocation serves one route.
func TestRouteTCP_Unique(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		c := db.Client()
		if err := e.pool(t, e.orgA, e.groupA, routes.TCP, 6000, 6001); err != nil {
			t.Fatal(err)
		}
		var a1, a2 *ent.PortAllocation
		if err := e.tx(t, func(tx *ent.Tx) error {
			var err error
			if a1, err = routes.Allocate(e.sys, tx, e.orgA, e.groupA, routes.TCP, 6000); err != nil {
				return err
			}
			a2, err = routes.Allocate(e.sys, tx, e.orgA, e.groupA, routes.TCP, 6001)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		r1 := c.Route.Create().SetOrgID(e.orgA).SetName("one").SetType("tcp").SetGatewayGroupID(e.groupA).SaveX(e.sys)
		r2 := c.Route.Create().SetOrgID(e.orgA).SetName("two").SetType("tcp").SetGatewayGroupID(e.groupA).SaveX(e.sys)
		c.RouteTCP.Create().SetOrgID(e.orgA).SetRouteID(r1.ID).SetPortAllocationID(a1.ID).ExecX(e.sys)
		if err := c.RouteTCP.Create().SetOrgID(e.orgA).SetRouteID(r2.ID).SetPortAllocationID(a1.ID).Exec(e.sys); !store.IsUniqueViolation(err) {
			t.Fatalf("two routes on one port allocation: %v", err)
		}
		if err := c.RouteTCP.Create().SetOrgID(e.orgA).SetRouteID(r1.ID).SetPortAllocationID(a2.ID).Exec(e.sys); !store.IsUniqueViolation(err) {
			t.Fatalf("a second row for a route: %v", err)
		}
	})
}

// TestRouteUDP: a udp route holds one udp port of its group, with a 60 s flow idle timeout by
// default; the same number can be a tcp port of another route, but one allocation serves one
// route.
func TestRouteUDP(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newEnv(t, db)
		c := db.Client()
		for _, p := range []routes.Protocol{routes.UDP, routes.TCP} {
			if err := e.pool(t, e.orgA, e.groupA, p, 5300, 5300); err != nil {
				t.Fatal(err)
			}
		}
		var udp, tcp *ent.PortAllocation
		if err := e.tx(t, func(tx *ent.Tx) error {
			var err error
			if udp, err = routes.Allocate(e.sys, tx, e.orgA, e.groupA, routes.UDP, 5300); err != nil {
				return err
			}
			tcp, err = routes.Allocate(e.sys, tx, e.orgA, e.groupA, routes.TCP, 5300)
			return err
		}); err != nil {
			t.Fatalf("udp and tcp 5300 side by side: %v", err)
		}
		dns := c.Route.Create().SetOrgID(e.orgA).SetName("dns").SetType("udp").SetGatewayGroupID(e.groupA).SaveX(e.sys)
		ru := c.RouteUDP.Create().SetOrgID(e.orgA).SetRouteID(dns.ID).SetPortAllocationID(udp.ID).SaveX(e.sys)
		if ru.FlowIdleTimeoutSeconds != 60 {
			t.Fatalf("flow idle timeout %d, want 60", ru.FlowIdleTimeoutSeconds)
		}
		other := c.Route.Create().SetOrgID(e.orgA).SetName("dns2").SetType("udp").SetGatewayGroupID(e.groupA).SaveX(e.sys)
		if err := c.RouteUDP.Create().SetOrgID(e.orgA).SetRouteID(other.ID).SetPortAllocationID(udp.ID).Exec(e.sys); !store.IsUniqueViolation(err) {
			t.Fatalf("a second route on the same allocation: %v", err)
		}
		_ = tcp
	})
}
