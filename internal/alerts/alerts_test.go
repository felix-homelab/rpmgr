// SPDX-License-Identifier: Apache-2.0

package alerts_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/alerts"
	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/alert"
	"github.com/felix-homelab/rpmgr/internal/store/ent/event"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

var t0 = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

// apply runs one pass as the job does, in a write transaction of the system scope.
func apply(t *testing.T, db *store.DB, now time.Time, obs ...alerts.Observation) []events.Event {
	t.Helper()
	var out []events.Event
	if err := store.WriteTx(storetest.SystemCtx(t), db, func(tx *ent.Tx) error {
		var err error
		out, err = alerts.Apply(storetest.SystemCtx(t), tx, now, obs)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func types(evs []events.Event) string {
	var s []string
	for _, e := range evs {
		s = append(s, e.Type)
	}
	return strings.Join(s, ",")
}

// TestApply_ForDurationFiresOnce (#647): an alert with a duration stays pending until its
// condition held for it, fires at exactly the duration, and a later pass, as after a restart or a
// lease takeover, does not fire it again.
func TestApply_ForDurationFiresOnce(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		org := storetest.Org(t, db, "org-a")
		off := alerts.Observation{OrgID: org, Kind: alerts.AgentOffline, SubjectType: "gateway", SubjectID: "gwy_1", SubjectName: "gw1",
			Since: t0}
		if got := apply(t, db, t0.Add(5*time.Minute-time.Second), off); len(got) != 0 {
			t.Fatalf("fired before its 5 min: %v", got)
		}
		a := db.Client().Alert.Query().OnlyX(storetest.SystemCtx(t))
		if a.State != alert.StatePending || !a.Since.Equal(t0) {
			t.Fatalf("alert %+v, want pending since the disconnection", a)
		}
		got := apply(t, db, t0.Add(5*time.Minute), off)
		if types(got) != "alert.fire" || got[0].OrgID != org || got[0].SubjectID != "gwy_1" || got[0].SubjectName != "gw1" ||
			got[0].Summary != "agent_offline: Agent offline fires, gw1" {
			t.Fatalf("events %+v, want one alert.fire at exactly 5 min", got)
		}
		for range 2 {
			if got := apply(t, db, t0.Add(10*time.Minute), off, off); len(got) != 0 {
				t.Fatalf("a firing alert fired again: %v", got)
			}
		}
		if n := db.Client().Alert.Query().CountX(storetest.SystemCtx(t)); n != 1 {
			t.Fatalf("%d alerts for one condition, want 1", n)
		}
	})
}

// TestApply_ResolvesOnce (#647): a firing alert whose condition ended resolves with one event; a
// pending one that ends goes without an event; the condition coming back is a new alert.
func TestApply_ResolvesOnce(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	org := storetest.Org(t, db, "org-a")
	skew := alerts.Observation{OrgID: org, Kind: alerts.ClockSkew, SubjectType: "connector", SubjectID: "con_1", SubjectName: "nas"}
	route := alerts.Observation{OrgID: org, Kind: alerts.RouteNoReadyTarget, SubjectType: "route", SubjectID: "rte_1"}
	if got := apply(t, db, t0, skew, route); types(got) != "alert.fire" {
		t.Fatalf("events %v, want the clock skew to fire at once and the route to wait 2 min", types(got))
	}
	if got := apply(t, db, t0.Add(time.Minute)); types(got) != "alert.resolve" || got[0].SubjectID != "con_1" {
		t.Fatalf("events %+v, want one alert.resolve and none for the pending route", got)
	}
	if got := apply(t, db, t0.Add(2*time.Minute)); len(got) != 0 {
		t.Fatalf("resolved twice: %v", got)
	}
	c, sys := db.Client(), storetest.SystemCtx(t)
	if n := c.Alert.Query().Where(alert.StateEQ(alert.StateResolved)).CountX(sys); n != 1 || c.Alert.Query().CountX(sys) != 1 {
		t.Fatal("want the resolved clock skew kept and the pending route alert gone")
	}
	// The pending route alert restarts its 2 min when the condition comes back.
	if got := apply(t, db, t0.Add(3*time.Minute), skew, route); types(got) != "alert.fire" {
		t.Fatalf("events %v, want the clock skew to fire anew", types(got))
	}
	if got := apply(t, db, t0.Add(5*time.Minute-time.Second), skew, route); len(got) != 0 {
		t.Fatalf("the route alert kept its old start: %v", got)
	}
	if got := apply(t, db, t0.Add(5*time.Minute), skew, route); types(got) != "alert.fire" || got[0].Summary !=
		"route_no_ready_connector: Route has no ready connector fires, rte_1" {
		t.Fatalf("events %+v", got)
	}
	if n := c.Event.Query().Where(event.Type("alert.fire")).CountX(sys); n != 3 {
		t.Fatalf("%d alert.fire events, want 3", n)
	}
}

// TestApply_Unknown: a condition the job cannot tell now, as an offline agent's configuration,
// leaves a firing alert firing and a pending one pending, with no event, opens none, and resolves
// nothing; once known again, the alert goes on from its old state.
func TestApply_Unknown(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		org := storetest.Org(t, db, "org-a")
		cfg := alerts.Observation{OrgID: org, Kind: alerts.ConfigNotApplied, SubjectType: "connector", SubjectID: "con_1", SubjectName: "nas"}
		route := alerts.Observation{OrgID: org, Kind: alerts.RouteNoReadyTarget, SubjectType: "route", SubjectID: "rte_1"}
		unknown := func(o alerts.Observation) alerts.Observation { o.Unknown = true; return o }
		if got := apply(t, db, t0, cfg, route); types(got) != "alert.fire" {
			t.Fatalf("events %v, want the configuration alert to fire", types(got))
		}
		for i := 1; i <= 3; i++ {
			if got := apply(t, db, t0.Add(time.Duration(i)*time.Minute), unknown(cfg), unknown(route)); len(got) != 0 {
				t.Fatalf("an unknown condition wrote events: %v", types(got))
			}
		}
		c, sys := db.Client(), storetest.SystemCtx(t)
		if n := c.Alert.Query().Where(alert.StateEQ(alert.StateFiring)).CountX(sys); n != 1 {
			t.Fatalf("%d firing alerts, want the configuration alert still firing", n)
		}
		if n := c.Alert.Query().Where(alert.StateEQ(alert.StatePending)).CountX(sys); n != 1 {
			t.Fatalf("%d pending alerts, want the route alert still pending", n)
		}
		// Known again: the route alert counts from its first sighting and fires; the configuration
		// alert does not fire twice.
		if got := apply(t, db, t0.Add(4*time.Minute), cfg, route); types(got) != "alert.fire" || got[0].SubjectID != "rte_1" {
			t.Fatalf("events %+v, want only the route alert to fire", got)
		}
		// An unknown condition opens no alert.
		other := unknown(alerts.Observation{OrgID: org, Kind: alerts.ClockSkew, SubjectType: "gateway", SubjectID: "gwy_1"})
		if got := apply(t, db, t0.Add(5*time.Minute), cfg, route, other); len(got) != 0 {
			t.Fatalf("events %v", types(got))
		}
		if n := c.Alert.Query().Where(alert.SubjectID("gwy_1")).CountX(sys); n != 0 {
			t.Fatal("an unknown condition opened an alert")
		}
	})
}

// TestApply_InstanceAndOrgs (#647): an instance alert has no org and only the system scope reads
// it; an org reads only its own alerts and their events.
func TestApply_InstanceAndOrgs(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		a, b := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		apply(t, db, t0,
			alerts.Observation{Kind: alerts.CheckpointsBehind, SubjectType: "instance", SubjectID: "audit"},
			alerts.Observation{OrgID: a, Kind: alerts.ClockSkew, SubjectType: "gateway", SubjectID: "gwy_a"},
			alerts.Observation{OrgID: b, Kind: alerts.ClockSkew, SubjectType: "gateway", SubjectID: "gwy_b"})
		c := db.Client()
		inst := c.Alert.Query().Where(alert.OrgIDIsNil()).OnlyX(storetest.SystemCtx(t))
		if inst.Kind != alerts.CheckpointsBehind || inst.State != alert.StateFiring {
			t.Fatalf("instance alert %+v", inst)
		}
		if e := c.Event.Query().Where(event.OrgIDIsNil()).OnlyX(storetest.SystemCtx(t)); e.Type != "alert.fire" {
			t.Fatalf("instance event %+v", e)
		}
		for org, want := range map[string]string{a: "gwy_a", b: "gwy_b"} {
			ctx := storetest.OrgCtx(t, org)
			if got := c.Alert.Query().AllX(ctx); len(got) != 1 || got[0].SubjectID != want {
				t.Fatalf("org %s reads alerts %v, want only its own", org, got)
			}
			if got := c.Event.Query().AllX(ctx); len(got) != 1 || got[0].SubjectID != want {
				t.Fatalf("org %s reads events %v, want only its own", org, got)
			}
		}
	})
}

// TestApply_Edges (#647): a start in the future counts from now; the same subject under two kinds
// is two alerts; a rolled-back pass leaves nothing; Purge removes only resolved alerts past the
// cut.
func TestApply_Edges(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	org := storetest.Org(t, db, "org-a")
	c, sys := db.Client(), storetest.SystemCtx(t)
	future := alerts.Observation{OrgID: org, Kind: alerts.AgentOffline, SubjectType: "connector", SubjectID: "con_1", Since: t0.Add(time.Hour)}
	apply(t, db, t0, future)
	if a := c.Alert.Query().OnlyX(sys); !a.Since.Equal(t0) {
		t.Fatalf("since %v, want now for a start in the future", a.Since)
	}
	skew := alerts.Observation{OrgID: org, Kind: alerts.ClockSkew, SubjectType: "connector", SubjectID: "con_1"}
	if got := apply(t, db, t0, future, skew); types(got) != "alert.fire" || c.Alert.Query().CountX(sys) != 2 {
		t.Fatal("want one alert per kind of one subject")
	}
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
		if _, err := alerts.Apply(sys, tx, t0.Add(time.Hour), nil); err != nil {
			return err
		}
		return context.Canceled
	}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if n := c.Alert.Query().Where(alert.StateEQ(alert.StateResolved)).CountX(sys); n != 0 {
		t.Fatal("a rolled-back pass resolved alerts")
	}
	apply(t, db, t0.Add(time.Minute))
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
		if n, err := alerts.Purge(sys, tx, t0.Add(time.Minute)); err != nil || n != 0 {
			t.Errorf("purged %d at the resolution time, want 0 (%v)", n, err)
		}
		n, err := alerts.Purge(sys, tx, t0.Add(time.Minute+time.Microsecond))
		if n != 1 {
			t.Errorf("purged %d, want the one resolved alert", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if alerts.Title("unknown_kind") != "unknown_kind" || alerts.Title(alerts.ClockSkew) != "Clock skew" {
		t.Fatal("titles")
	}
}

// TestApplyChosen_TypeNotChosenWritesNoEvent (#959): an alert of a kind its org did not choose
// moves through its states without an event, so no webhook and no e-mail hears of it; another
// org, and an instance alert, still get theirs; a failing lookup fails the pass.
func TestApplyChosen_TypeNotChosenWritesNoEvent(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	a, b := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
	chosen := func(_ context.Context, org, kind string) (bool, error) {
		return org != a || kind != alerts.ClockSkew, nil
	}
	run := func(now time.Time, obs ...alerts.Observation) []events.Event {
		var out []events.Event
		if err := store.WriteTx(storetest.SystemCtx(t), db, func(tx *ent.Tx) error {
			var err error
			out, err = alerts.ApplyChosen(storetest.SystemCtx(t), tx, now, obs, chosen)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	skew := func(org string) alerts.Observation {
		return alerts.Observation{OrgID: org, Kind: alerts.ClockSkew, SubjectType: "gateway", SubjectID: "gwy_1", SubjectName: "gw1"}
	}
	inst := alerts.Observation{Kind: alerts.CheckpointsBehind, SubjectType: "instance", SubjectID: "audit"}
	got := run(t0, skew(a), skew(b), inst)
	if len(got) != 3-1 || got[0].OrgID == a || got[1].OrgID == a {
		t.Fatalf("events %+v, want org b's and the instance's only", got)
	}
	if n := db.Client().Alert.Query().Where(alert.OrgID(a), alert.StateEQ(alert.StateFiring)).CountX(storetest.SystemCtx(t)); n != 1 {
		t.Fatalf("%d firing alerts of org a, want its alert kept", n)
	}
	if got := run(t0.Add(time.Minute)); types(got) != "alert.resolve,alert.resolve" {
		t.Fatalf("resolving wrote %q, want org b's and the instance's", types(got))
	}
	chosen = func(context.Context, string, string) (bool, error) { return false, errors.New("settings unreadable") }
	err := store.WriteTx(storetest.SystemCtx(t), db, func(tx *ent.Tx) error {
		_, err := alerts.ApplyChosen(storetest.SystemCtx(t), tx, t0.Add(time.Hour), []alerts.Observation{skew(b)}, chosen)
		return err
	})
	if err == nil {
		t.Fatal("a failing lookup was ignored")
	}
}
