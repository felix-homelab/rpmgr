// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/alerts"
	"github.com/felix-homelab/rpmgr/internal/auditsink"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/alert"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// TestAuditSink_KEKRotation (#654): after the KEK rotated, `rpmgr kek rotate` having re-wrapped
// the sink's secret, a controller that holds only the new KEK ships, signed with the same secret.
func TestAuditSink_KEKRotation(t *testing.T) {
	e := newSinkEnv(t, storetest.Migrated(t, store.SQLite))
	s := e.sink("hook", "/hook", false)
	e.checkpoint("", e.appendTo(""))

	next, err := secret.NewKEK([]byte("fedcba9876543210fedcba9876543210"))
	if err != nil {
		t.Fatal(err)
	}
	old, _ := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
	rotating, _ := secret.NewSealer(next, old)
	ctx := secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: s.ID}
	rewrapped, err := rotating.Rewrap(ctx, *s.SecretEnc)
	if err != nil || string(rewrapped) == string(*s.SecretEnc) {
		t.Fatalf("rewrap: %v", err)
	}
	e.db.Client().AuditSink.UpdateOne(s).SetSecretEnc(rewrapped).ExecX(e.sys)

	e.sealer, _ = secret.NewSealer(next)
	e.job = e.newJob()
	e.mustRun()
	got := e.requests("/hook")
	if len(got) != 1 || webhook.Verify(got[0].sig, got[0].body, sinkSecret, e.clock) != nil || e.status(s).LastError != "" {
		t.Fatalf("after the rotation: %d requests, last error %q", len(got), e.status(s).LastError)
	}

	// A controller that holds only the old KEK cannot open it, and says so without the secret.
	e.sealer, _ = secret.NewSealer(old)
	e.job = e.newJob()
	e.checkpoint("", e.appendTo(""))
	e.mustRun()
	if len(e.requests("/hook")) != 1 {
		t.Error("a sink whose secret cannot be opened was delivered to")
	}
	if le := e.status(s).LastError; !strings.Contains(le, "cannot be opened") || strings.Contains(le, sinkSecret) || strings.Contains(le, "example.com") {
		t.Errorf("last error %q", le)
	}
}

// TestAuditSink_ReceiverAnswers (#654): a 4xx other than 408 and 429 is a permanent refusal, which
// the status names at once and which is retried only at the slowest pace; 408, 429 and 5xx are
// transient and retried on the normal schedule; a sink that recovers clears the error and ships
// what waited.
func TestAuditSink_ReceiverAnswers(t *testing.T) {
	for _, c := range []struct {
		status    int
		permanent bool
	}{
		{http.StatusBadRequest, true}, {http.StatusUnauthorized, true}, {http.StatusNotFound, true}, {http.StatusGone, true},
		{http.StatusRequestTimeout, false}, {http.StatusTooManyRequests, false}, {http.StatusInternalServerError, false},
		{http.StatusServiceUnavailable, false}, {http.StatusMovedPermanently, false},
	} {
		t.Run(http.StatusText(c.status), func(t *testing.T) {
			e := newSinkEnv(t, storetest.Migrated(t, store.SQLite))
			s := e.sink("hook", "/hook", false)
			en := e.appendTo("")
			e.checkpoint("", en)
			e.answer = func(int) int { return c.status }
			e.mustRun()
			le := e.status(s).LastError
			if got := strings.Contains(le, "until the receiver accepts it"); got != c.permanent {
				t.Fatalf("%d: last error %q, permanent %v", c.status, le, got)
			}
			if c.permanent && !strings.Contains(le, "refused an item with") {
				t.Errorf("last error %q", le)
			}
			if strings.Contains(le, "example.com") || strings.Contains(le, sinkSecret) {
				t.Errorf("last error %q names the URL or the secret", le)
			}
			if b := e.backlog("hook"); b.Items != 1 || b.Oldest.IsZero() {
				t.Errorf("backlog %+v: the cursor moved past a refused item", b)
			}
			// The retry pace: BackoffMin for a transient failure, BackoffMax for a permanent one.
			n := func() int { return len(e.requests("/hook")) }
			e.clock = e.clock.Add(auditsink.BackoffMin)
			e.mustRun()
			if (n() == 1) != c.permanent {
				t.Errorf("%d requests after %v, permanent %v", n(), auditsink.BackoffMin, c.permanent)
			}
			e.clock = e.clock.Add(auditsink.BackoffMax)
			e.mustRun()
			if n() < 2 {
				t.Errorf("no retry after %v", auditsink.BackoffMax)
			}
			e.answer = func(int) int { return http.StatusNoContent }
			e.clock = e.clock.Add(auditsink.BackoffMax)
			e.mustRun()
			if got := e.status(s); got.LastError != "" || e.backlog("hook").Items != 0 {
				t.Errorf("after the receiver recovered: %q, backlog %d", got.LastError, e.backlog("hook").Items)
			}
		})
	}
}

// TestAuditSink_BacklogFromData (#654): the backlog is counted from the audit tables and the cursors
// in one pass over every sink and chain, so it is right for sinks of different positions and
// kinds; and it ages while no replica ships, because none holds the lease, so the alert still fires.
func TestAuditSink_BacklogFromData(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newSinkEnv(t, db)
		a, b := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		cps := e.sink("cps", "/cps", false)
		both := e.sink("both", "/both", true)
		off := e.sink("off", "/off", true)
		db.Client().AuditSink.UpdateOne(off).SetEnabled(false).ExecX(e.sys)
		for range 2 {
			e.checkpoint("", e.appendTo(""))
		}
		first := e.appendTo(a)
		e.checkpoint(a, first)
		e.checkpoint(a, e.appendTo(a))
		e.mustRun() // the two caught-up sinks hold everything so far
		for _, n := range []string{"cps", "both"} {
			if bl := e.backlog(n); bl.Items != 0 || !bl.Oldest.IsZero() {
				t.Fatalf("%s: %+v after catching up", n, bl)
			}
		}
		if bl := e.backlog("off"); bl.Enabled || bl.Items != 8 {
			// The disabled sink got nothing: 4 checkpoints and entries on each of two chains.
			t.Fatalf("off: %+v", bl)
		}

		// New items on three chains, none of them shipped: the job does not run again.
		en := e.appendTo("")
		e.checkpoint("", en)
		e.appendTo(b)
		e.appendTo(b)
		e.appendTo(a)
		if bl := e.backlog("cps"); bl.Items != 1 || bl.Oldest.IsZero() || len(bl.Chains) != 3 {
			t.Fatalf("cps: %+v", bl)
		}
		bl := e.backlog("both")
		per := map[string]int64{}
		for _, c := range bl.Chains {
			per[c.Chain] = c.Items
		}
		if bl.Items != 5 || per[b] != 2 || per[a] != 1 || per["instance"] != 2 || bl.Oldest.After(en.Time) {
			t.Fatalf("both: %+v", bl)
		}

		// No lease holder ships; the alert reader still sees the backlog age.
		leases := lease.New(db, "ctn_alerts", nil)
		job := controller.AlertJob(controller.AlertOptions{DB: db, Leases: leases, Now: func() time.Time { return e.clock }, Logger: slog.New(slog.DiscardHandler)})
		held, _, err := leases.TryAcquire(e.sys, "alerts")
		if err != nil || held.Token == 0 {
			t.Fatal("no lease", err)
		}
		firing := func(id string) int {
			return db.Client().Alert.Query().Where(alert.Kind(alerts.AuditSinkBacklog), alert.StateEQ(alert.StateFiring), alert.SubjectID(id)).CountX(e.sys)
		}
		pass := func() {
			t.Helper()
			if err := job.Run(context.WithoutCancel(e.sys), held); err != nil {
				t.Fatal(err)
			}
		}
		e.clock = bl.Oldest.Add(alerts.AuditSinkBacklogFor - time.Second)
		pass()
		if firing(both.ID) != 0 {
			t.Fatal("the alert fires before 15 min")
		}
		e.clock = bl.Oldest.Add(alerts.AuditSinkBacklogFor + time.Second)
		pass()
		if firing(both.ID) != 1 || firing(cps.ID) != 1 || firing(off.ID) != 0 {
			t.Fatalf("alerts: both %d, cps %d, off %d", firing(both.ID), firing(cps.ID), firing(off.ID))
		}
	})
}
