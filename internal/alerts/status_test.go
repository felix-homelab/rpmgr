// SPDX-License-Identifier: Apache-2.0

package alerts_test

import (
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/alerts"
	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func applyStatus(t *testing.T, db *store.DB, now time.Time, obs ...alerts.StatusObservation) []events.Event {
	t.Helper()
	var out []events.Event
	if err := store.WriteTx(storetest.SystemCtx(t), db, func(tx *ent.Tx) error {
		var err error
		out, err = alerts.ApplyStatus(storetest.SystemCtx(t), tx, now, obs)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func agent(org, state string) alerts.StatusObservation {
	return alerts.StatusObservation{OrgID: org, Kind: alerts.StatusAgent, SubjectType: "connector", SubjectID: "cnr_1", SubjectName: "nas", State: state}
}

// TestApplyStatus_AgentOncePerChange (#958): connecting and disconnecting are one event each per
// change of state, not per pass; the same state seen again, as after a restart, writes nothing.
func TestApplyStatus_AgentOncePerChange(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		org := storetest.Org(t, db, "org-a")
		if got := types(applyStatus(t, db, t0, agent(org, alerts.StateOnline))); got != "agent.connect" {
			t.Fatalf("first connection: %q", got)
		}
		for i := 1; i <= 3; i++ {
			if got := applyStatus(t, db, t0.Add(time.Duration(i)*time.Hour/2), agent(org, alerts.StateOnline)); len(got) != 0 {
				t.Fatalf("an unchanged state wrote %v", got)
			}
		}
		got := applyStatus(t, db, t0.Add(2*time.Hour), agent(org, alerts.StateOffline))
		if types(got) != "agent.disconnect" || got[0].OrgID != org || got[0].SubjectID != "cnr_1" || got[0].SubjectName != "nas" {
			t.Fatalf("disconnect: %+v", got)
		}
		if got := types(applyStatus(t, db, t0.Add(3*time.Hour), agent(org, alerts.StateOnline))); got != "agent.connect" {
			t.Fatalf("reconnect: %q", got)
		}
	})
}

// TestApplyStatus_FlappingIsBounded (#958): a reconnect storm writes at most one event per
// StatusGap, and one that ends where it began writes none.
func TestApplyStatus_FlappingIsBounded(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		org := storetest.Org(t, db, "org-a")
		applyStatus(t, db, t0, agent(org, alerts.StateOnline))
		var all []events.Event
		now := t0
		for i := 0; i < 40; i++ { // 40 passes of 1 s, alternating
			now = now.Add(time.Second)
			state := alerts.StateOffline
			if i%2 == 1 {
				state = alerts.StateOnline
			}
			all = append(all, applyStatus(t, db, now, agent(org, state))...)
		}
		if len(all) != 0 {
			t.Fatalf("a storm inside the gap wrote %v", types(all))
		}
		// Ends offline: the state is reported once the gap passed, then not again.
		got := applyStatus(t, db, t0.Add(alerts.StatusGap), agent(org, alerts.StateOffline))
		if types(got) != "agent.disconnect" {
			t.Fatalf("after the gap: %q", types(got))
		}
		if got := applyStatus(t, db, t0.Add(2*alerts.StatusGap), agent(org, alerts.StateOffline)); len(got) != 0 {
			t.Fatalf("again: %v", got)
		}
	})
}

// TestApplyStatus_FirstSightAndGone (#958): an agent first seen offline and a route's first
// status are no events; an unknown observation keeps the mark; a subject that goes loses its mark,
// so a restart neither replays nor loses a change.
func TestApplyStatus_FirstSightAndGone(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	org := storetest.Org(t, db, "org-a")
	rt := func(state string) alerts.StatusObservation {
		return alerts.StatusObservation{OrgID: org, Kind: alerts.StatusRoute, SubjectType: "route", SubjectID: "rte_1", SubjectName: "web", State: state}
	}
	if got := applyStatus(t, db, t0, agent(org, alerts.StateOffline), rt("pending")); len(got) != 0 {
		t.Fatalf("first sight wrote %v", got)
	}
	// The agent is gone (decommissioned): its mark goes, so it is first seen again, online, later.
	if got := types(applyStatus(t, db, t0.Add(time.Hour), rt("pending"))); got != "" {
		t.Fatalf("the agent's mark going wrote %q", got)
	}
	if got := types(applyStatus(t, db, t0.Add(2*time.Hour), rt("pending"), agent(org, alerts.StateOnline))); got != "agent.connect" {
		t.Fatalf("an agent seen again: %q", got)
	}
	// Unknown keeps the mark, so the same state afterwards is no change.
	unknown := agent(org, "")
	unknown.Unknown = true
	if got := applyStatus(t, db, t0.Add(3*time.Hour), rt("pending"), unknown); len(got) != 0 {
		t.Fatalf("unknown wrote %v", got)
	}
	if got := applyStatus(t, db, t0.Add(4*time.Hour), rt("pending"), agent(org, alerts.StateOnline)); len(got) != 0 {
		t.Fatalf("an unchanged state after unknown wrote %v", got)
	}
}

// TestApplyStatus_RouteStatusAndApplyReject (#958): a route's change of status is one event naming
// both states; a snapshot rejected is one event, once per snapshot, and its ending none; an
// unknown observation changes nothing; no event carries more than names and states.
func TestApplyStatus_RouteStatusAndApplyReject(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	org := storetest.Org(t, db, "org-a")
	rt := func(state string) alerts.StatusObservation {
		return alerts.StatusObservation{OrgID: org, Kind: alerts.StatusRoute, SubjectType: "route", SubjectID: "rte_1", SubjectName: "web", State: state}
	}
	ap := func(state string, unknown bool) alerts.StatusObservation {
		return alerts.StatusObservation{OrgID: org, Kind: alerts.StatusApply, SubjectType: "connector", SubjectID: "cnr_1", SubjectName: "nas", State: state, Unknown: unknown}
	}
	applyStatus(t, db, t0, rt("pending"), ap(alerts.StateOK, false))
	now := t0.Add(time.Hour)
	got := applyStatus(t, db, now, rt("ready"), ap("rejected:e:5", false))
	if types(got) != "route.status,apply.reject" && types(got) != "apply.reject,route.status" {
		t.Fatalf("events %q", types(got))
	}
	for _, e := range got {
		if e.OrgID != org || strings.Contains(e.Summary, "rejected:e") {
			t.Fatalf("event %+v", e)
		}
		if e.Type == "route.status" && e.Summary != "route.status route web: ready, was pending" {
			t.Fatalf("summary %q", e.Summary)
		}
	}
	now = now.Add(time.Hour)
	if got := applyStatus(t, db, now, rt("ready"), ap("rejected:e:5", false)); len(got) != 0 {
		t.Fatalf("the same rejection again: %v", got)
	}
	now = now.Add(time.Hour)
	if got := applyStatus(t, db, now, rt("ready"), ap("", true)); len(got) != 0 {
		t.Fatalf("unknown: %v", got)
	}
	now = now.Add(time.Hour)
	if got := applyStatus(t, db, now, rt("ready"), ap(alerts.StateOK, false)); len(got) != 0 {
		t.Fatalf("a rejection ending is no event: %v", got)
	}
	now = now.Add(time.Hour)
	if got := types(applyStatus(t, db, now, rt("ready"), ap("rejected:e:6", false))); got != "apply.reject" {
		t.Fatalf("a new rejection: %q", got)
	}
}
