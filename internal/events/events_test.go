// SPDX-License-Identifier: Apache-2.0

package events_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/event"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func change(org, action string, result audit.Result) audit.Entry {
	return audit.Entry{OrgID: org, ActorType: audit.ActorUser, ActorID: "usr_ada", Action: action, TargetType: "route",
		TargetID: "rte_1", TargetName: "web", Changed: []string{"name", "enabled"}, Result: result}
}

func all(t *testing.T, ctx context.Context, db *store.DB) []*ent.Event {
	t.Helper()
	rows, err := db.Client().Event.Query().Order(ent.Asc(event.FieldID)).All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestEvents_WrittenWithTheChange (#646): an audited success writes its event in the change's
// transaction, typed by the action, with the subject and the changed fields; a failure, a refusal
// and an action that changes nothing write none, and a rolled-back change leaves no event.
func TestEvents_WrittenWithTheChange(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		org := storetest.Org(t, db, "org-a")
		ctx := context.Background()
		for _, e := range []audit.Entry{change(org, "rpmgr.v1.RouteService.UpdateRoute", audit.Success),
			change(org, "route.update", audit.Failure), change(org, "route.update", audit.Denied), change(org, "token.use", audit.Success),
			change(org, "rpmgr.v1.AuthService.Login", audit.Success)} {
			if _, err := audit.Record(ctx, db, e); err != nil {
				t.Fatal(err)
			}
		}
		boom := errors.New("the change fails")
		if err := store.WriteTx(storetest.OrgCtx(t, org), db, func(tx *ent.Tx) error {
			if _, err := audit.Append(storetest.OrgCtx(t, org), tx, change(org, "route.delete", audit.Success)); err != nil {
				return err
			}
			return boom
		}); !errors.Is(err, boom) {
			t.Fatal(err)
		}
		got := all(t, storetest.SystemCtx(t), db)
		if len(got) != 1 {
			t.Fatalf("events %v, want the one success that committed", got)
		}
		e := got[0]
		if e.Type != "route.update" || e.OrgID == nil || *e.OrgID != org || e.ActorType != "user" || e.ActorID != "usr_ada" ||
			e.SubjectType != "route" || e.SubjectID != "rte_1" || e.SubjectName != "web" || !slices.Equal(e.Changed, []string{"name", "enabled"}) ||
			e.Summary != "route.update route web" {
			t.Fatalf("event %+v", e)
		}
	})
}

// TestEvents_OrgIsolationAndInstance (#646): an org scope reads only its own org's events, not
// another org's nor the instance's; an entry of the instance chain is an instance event; the
// system scope reads every one, in the order they were written.
func TestEvents_OrgIsolationAndInstance(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		a, b := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		ctx := context.Background()
		var written []string
		for _, e := range []audit.Entry{change(a, "route.update", audit.Success), change(b, "route.update", audit.Success),
			{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "kek.rotate", Result: audit.Success},
			change(a, "route.delete", audit.Success)} {
			if _, err := audit.Record(ctx, db, e); err != nil {
				t.Fatal(err)
			}
			written = append(written, events.TypeOf(e.Action)+"/"+e.OrgID)
		}
		var seen []string
		for _, e := range all(t, storetest.SystemCtx(t), db) {
			org := ""
			if e.OrgID != nil {
				org = *e.OrgID
			}
			seen = append(seen, e.Type+"/"+org)
		}
		if !slices.Equal(seen, written) {
			t.Fatalf("the system scope reads %v, want %v in order", seen, written)
		}
		for org, want := range map[string][]string{a: {"route.update", "route.delete"}, b: {"route.update"}} {
			var types []string
			for _, e := range all(t, storetest.OrgCtx(t, org), db) {
				if e.OrgID == nil || *e.OrgID != org {
					t.Fatalf("org %s reads %+v", org, e)
				}
				types = append(types, e.Type)
			}
			if !slices.Equal(types, want) {
				t.Fatalf("org %s reads %v, want %v", org, types, want)
			}
		}
		if _, err := db.Client().Event.Query().All(context.Background()); err == nil {
			t.Fatal("events read without a scope")
		}
	})
}

// TestEvents_Purge (#646): events older than the retention go, newer ones stay.
func TestEvents_Purge(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		org := storetest.Org(t, db, "org-a")
		sys := storetest.SystemCtx(t)
		for _, action := range []string{"route.create", "route.update"} {
			if _, err := audit.Record(context.Background(), db, change(org, action, audit.Success)); err != nil {
				t.Fatal(err)
			}
		}
		rows := all(t, sys, db)
		var purged int
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			var err error
			purged, err = events.Purge(sys, tx, rows[1].Ts) // the first is older
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if left := all(t, sys, db); purged != 1 || len(left) != 1 || left[0].ID != rows[1].ID {
			t.Fatalf("purged %d, left %v", purged, left)
		}
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			var err error
			purged, err = events.Purge(sys, tx, time.Now().Add(time.Hour))
			return err
		}); err != nil || purged != 1 || len(all(t, sys, db)) != 0 {
			t.Fatalf("purge of everything: %d %v", purged, err)
		}
	})
}

// TestEvents_Add (#646): a status event of its own, with a cut name; an event without a type is
// refused.
func TestEvents_Add(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		org := storetest.Org(t, db, "org-a")
		sys := storetest.SystemCtx(t)
		long := strings.Repeat("x", 300)
		if err := store.WriteTx(sys, db, func(tx *ent.Tx) error {
			if _, err := events.Add(sys, tx, events.Event{OrgID: org, Type: ""}); err == nil {
				t.Error("an event without a type was written")
			}
			_, err := events.Add(sys, tx, events.Event{OrgID: org, Type: "agent.connect", SubjectType: "connector", SubjectID: "con_1",
				SubjectName: "ab" + long})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		got := all(t, sys, db)
		if len(got) != 1 || got[0].ActorType != "system" || len(got[0].SubjectName) != 255 || got[0].Changed != nil {
			t.Fatalf("events %+v", got)
		}
	})
}

// TestTypeOf: a service's own action is its type; an API method becomes <resource>.<verb>.
func TestTypeOf(t *testing.T) {
	for action, want := range map[string]string{
		"route.update": "route.update", "rpmgr.v1.RouteService.UpdateRoute": "route.update",
		"rpmgr.v1.RouteService.CreateRouteTarget": "route_target.create", "rpmgr.v1.AuthService.RevokeSession": "session.revoke",
		"rpmgr.v1.AuthService.Logout": "auth.logout", "rpmgr.v1.DNSService.CreateDNSZone": "dns_zone.create",
		"rpmgr.v1.GatewayService.SetPortQuota": "port_quota.set",
	} {
		if got := events.TypeOf(action); got != want {
			t.Errorf("%s: %s, want %s", action, got, want)
		}
	}
}

// TestFromAudit: a successful change is an event; a failure, and an audited action that changes no
// configuration, such as signing in, opening a live log or pruning the audit log, is none.
func TestFromAudit(t *testing.T) {
	for _, c := range []struct {
		action, result string
		want           bool
	}{
		{"rpmgr.v1.RouteService.UpdateRoute", "success", true},
		{"route.update", "success", true},
		{"rpmgr.v1.RouteService.UpdateRoute", "failure", false},
		{"rpmgr.v1.RouteService.UpdateRoute", "denied", false},
		{"rpmgr.v1.AuthService.Login", "success", false},
		{"rpmgr.v1.AuthService.Logout", "success", false},
		{"token.use", "success", false},
		{"agent.logs_open", "success", false},
		{"audit.prune", "success", false},
		{"job.run", "success", false},
	} {
		if got := events.FromAudit(c.action, c.result); got != c.want {
			t.Errorf("FromAudit(%q, %q) = %v, want %v", c.action, c.result, got, c.want)
		}
	}
}
