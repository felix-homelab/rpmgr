// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/event"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestStatusEvents_Job (#958): the alert job writes agent.connect, agent.disconnect, apply.reject
// and route.status once per change of state, each in its own org only, for a built-in agent as
// for any; a pass that sees nothing new, as after a restart, writes nothing; and an ephemeral
// connector, which comes and goes by design, writes none.
func TestStatusEvents_Job(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	a, b := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
	sys := storetest.SystemCtx(t)
	c := db.Client()
	now := time.Now().UTC().Truncate(time.Second)
	group := c.GatewayGroup.Create().SetOrgID(a).SetName("eu").SaveX(sys)
	gw := c.Gateway.Create().SetOrgID(a).SetGatewayGroupID(group.ID).SetName("gw1").SetBuiltIn(true).SetTunnelEndpoints([]string{"gw1.example:443"}).SaveX(sys)
	con := func(org, name string, ephemeral bool) string {
		return c.Connector.Create().SetOrgID(org).SetName(name).SetSpiffeID("spiffe://t/org/" + org + "/connector/" + name).
			SetPubkeySha256(name).SetEphemeral(ephemeral).SaveX(sys).ID
	}
	nasA, nasB, ci := con(a, "nas", false), con(b, "nas", false), con(a, "ci", true)
	session := func(org, id string, disconnected *time.Time, seen time.Time) {
		c.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_test").SetConnectedAt(now.Add(-time.Hour)).
			SetLastSeenAt(seen).SetNillableDisconnectedAt(disconnected).ExecX(sys)
	}
	session(a, gw.ID, nil, now)
	session(a, nasA, nil, now)
	session(b, nasB, nil, now)
	session(a, ci, nil, now)
	c.Route.Create().SetOrgID(a).SetName("web").SetType("tls_passthrough").SetGatewayGroupID(group.ID).ExecX(sys)

	clock := now
	leases := lease.New(db, "ctn_test", nil)
	job := controller.AlertJob(controller.AlertOptions{DB: db, Leases: leases, Now: func() time.Time { return clock }, Logger: slog.New(slog.DiscardHandler)})
	held, ok, err := leases.TryAcquire(sys, "alerts")
	if err != nil || !ok {
		t.Fatal("no lease", err)
	}
	run := func(d time.Duration) {
		t.Helper()
		clock = now.Add(d)
		c.AgentSession.Update().SetLastSeenAt(clock).ExecX(sys) // every session is seen at every pass
		if err := job.Run(context.WithoutCancel(sys), held); err != nil {
			t.Fatal(err)
		}
	}
	subjects := func(org, typ string) []string {
		var out []string
		ctx := storetest.OrgCtx(t, org)
		for _, e := range c.Event.Query().Where(event.Type(typ)).AllX(ctx) {
			out = append(out, e.SubjectID)
		}
		slices.Sort(out)
		return out
	}

	run(0)
	if got, want := subjects(a, "agent.connect"), []string{gw.ID, nasA}; !slices.Equal(got, sorted(want)) {
		t.Fatalf("org a connects %v, want %v (built-in gateway included, ephemeral left out)", got, want)
	}
	if got := subjects(b, "agent.connect"); !slices.Equal(got, []string{nasB}) {
		t.Fatalf("org b sees %v, want only its own connector", got)
	}
	run(10 * time.Second)
	run(20 * time.Second)
	if n := c.Event.Query().Where(event.TypeHasPrefix("agent.")).CountX(sys); n != 3 {
		t.Fatalf("%d agent events after two more passes, want 3", n)
	}

	// nasA drops and its snapshot was rejected; a route has no first-sight event.
	gone := now.Add(2 * time.Minute)
	c.AgentSession.UpdateOneID(nasA).SetDisconnectedAt(gone).ExecX(sys)
	c.AgentState.Create().SetID(nasB).SetOrgID(b).SetPushedHash([]byte("h2")).SetPushedAt(now).SetRejectedHash([]byte("h2")).
		SetRejectedDbEpoch("e").SetRejectedSeq(7).ExecX(sys)
	run(3 * time.Minute)
	for typ, want := range map[string][]string{"agent.disconnect": {nasA}, "apply.reject": nil} {
		if got := subjects(a, typ); !slices.Equal(got, want) {
			t.Errorf("org a %s %v, want %v", typ, got, want)
		}
	}
	if got := subjects(b, "apply.reject"); !slices.Equal(got, []string{nasB}) {
		t.Errorf("org b apply.reject %v, want its connector", got)
	}
	if got := subjects(b, "agent.disconnect"); len(got) != 0 {
		t.Errorf("org b sees org a's disconnect: %v", got)
	}
	if got := c.Event.Query().Where(event.Type("route.status")).CountX(sys); got != 0 {
		t.Errorf("%d route.status events from a route seen for the first time", got)
	}
	// A route turns off: one route.status in org a.
	c.Route.Update().Where().SetEnabled(false).ExecX(sys)
	run(5 * time.Minute)
	run(6 * time.Minute)
	if got := subjects(a, "route.status"); len(got) != 1 {
		t.Errorf("route.status %v, want one", got)
	}
	if got := subjects(b, "route.status"); len(got) != 0 {
		t.Errorf("org b sees %v", got)
	}
}

func sorted(s []string) []string { slices.Sort(s); return s }
