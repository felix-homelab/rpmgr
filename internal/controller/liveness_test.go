// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestSessionLiveness: a session is recorded as live while it runs and marked seen periodically;
// its end is recorded, and a new session clears it; a superseded session's end does not mark the
// agent disconnected; at start a node ends the sessions a stopped run of it left open, not other
// nodes'.
func TestSessionLiveness(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		sys := storetest.SystemCtx(t)
		stale := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
		e := startSessionsWith(t, db, func(o *controller.SessionsOptions) {
			o.SeenEvery = 50 * time.Millisecond
			org := db.Client().Org.Query().OnlyIDX(sys)
			for id, node := range map[string]string{"con_left": "ctn_test", "con_other": "ctn_other"} {
				db.Client().AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(3).SetControllerNode(node).
					SetConnectedAt(stale).SetLastSeenAt(stale).ExecX(sys)
			}
		})
		row := func(id string) *ent.AgentSession { return db.Client().AgentSession.GetX(sys, id) }
		waitRow := func(what, id string, ok func(*ent.AgentSession) bool) *ent.AgentSession {
			t.Helper()
			deadline := time.Now().Add(10 * time.Second)
			for {
				if r := row(id); ok(r) {
					return r
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s: %+v", what, row(id))
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		waitRow("the left session", "con_left", func(r *ent.AgentSession) bool { return r.DisconnectedAt != nil })
		if row("con_other").DisconnectedAt != nil {
			t.Fatal("another node's session was ended")
		}

		cert, id := e.agentCert(t)
		ctx, cancel := context.WithCancel(testCtx(t))
		st := e.open(t, ctx, cert, hello("0.1.0"))
		if recv(t, st).GetWelcome() == nil {
			t.Fatal("no Welcome")
		}
		first := row(id.ID)
		if first.DisconnectedAt != nil {
			t.Fatalf("a live session: %+v", first)
		}
		waitRow("marked seen", id.ID, func(r *ent.AgentSession) bool { return r.LastSeenAt.After(first.LastSeenAt) })
		cancel()
		waitRow("the end of the session", id.ID, func(r *ent.AgentSession) bool { return r.DisconnectedAt != nil })

		ctx2, cancel2 := context.WithCancel(testCtx(t))
		defer cancel2()
		st2 := e.open(t, ctx2, cert, hello("0.1.0"))
		if recv(t, st2).GetWelcome() == nil {
			t.Fatal("no Welcome")
		}
		if r := row(id.ID); r.DisconnectedAt != nil || r.SessionEpoch != 2 {
			t.Fatalf("a new session: %+v", r)
		}
		st3 := e.open(t, testCtx(t), cert, hello("0.1.0"))
		if recv(t, st3).GetWelcome() == nil {
			t.Fatal("no Welcome")
		}
		for { // the superseded session ends
			if _, err := st2.Recv(); err != nil {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
		if r := row(id.ID); r.DisconnectedAt != nil || r.SessionEpoch != 3 {
			t.Fatalf("after a superseded session ended: %+v", r)
		}
	})
}

// TestSessionLiveness_StoppedAtStart (#514): a controller that stops before it ends the sessions
// its last run left open logs nothing, as its next start ends them; a database that fails while it
// runs is still an error.
func TestSessionLiveness_StoppedAtStart(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	w := &warnings{}
	sys, stop := context.WithCancel(storetest.SystemCtx(t))
	defer stop()
	e := startSessionsWith(t, db, func(o *controller.SessionsOptions) {
		o.Sys = sys
		o.Logger = slog.New(w)
	})
	stop()
	e.sessions.EndLeftOpen()
	if got := w.all(); len(got) != 0 {
		t.Fatalf("a stop at the start logged:\n%s", strings.Join(got, "\n"))
	}

	db2 := storetest.Migrated(t, store.SQLite)
	w2 := &warnings{}
	e2 := startSessionsWith(t, db2, func(o *controller.SessionsOptions) { o.Logger = slog.New(w2) })
	if err := db2.Close(); err != nil {
		t.Fatal(err)
	}
	e2.sessions.EndLeftOpen() // Run's own first pass may fail on the closed database too
	got := w2.all()
	if len(got) == 0 || slices.ContainsFunc(got, func(l string) bool {
		return !strings.Contains(l, "cannot end the sessions a stopped controller left open")
	}) {
		t.Fatalf("a failing database logged %q", got)
	}
}

// TestSessionLiveness_StopDrain (docs/03-connections.md, "Service sketch"): a stop cancels the
// system scope first, then drains the sessions; their ends are still recorded, with no error.
func TestSessionLiveness_StopDrain(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	w := &warnings{}
	sys, stop := context.WithCancel(storetest.SystemCtx(t))
	defer stop()
	e := startSessionsWith(t, db, func(o *controller.SessionsOptions) {
		o.Sys = sys
		o.Logger = slog.New(w)
	})
	cert, id := e.agentCert(t)
	ctx, cancel := context.WithCancel(testCtx(t))
	defer cancel()
	st := e.open(t, ctx, cert, hello("0.1.0"))
	if recv(t, st).GetWelcome() == nil {
		t.Fatal("no Welcome")
	}
	stop()
	cancel()
	read := storetest.SystemCtx(t)
	waitUntil(t, func() bool { return db.Client().AgentSession.GetX(read, id.ID).DisconnectedAt != nil })
	if got := w.all(); len(got) != 0 {
		t.Errorf("the drain logged:\n%s", strings.Join(got, "\n"))
	}
}
