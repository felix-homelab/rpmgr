// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/alerts"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/auditsink"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/alert"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditsinkcursor"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

const sinkSecret = "rpmgr_whs_sinksinksinksinksinksinksinksinksink01" //nolint:gosec // G101: a test secret

// sinkEnv is a database, a TLS receiver on loopback that records what it gets, and the audit sink
// job with its clock.
type sinkEnv struct {
	t      *testing.T
	db     *store.DB
	sys    context.Context
	sealer *secret.Sealer
	url    string
	clock  time.Time
	leases *lease.Leases
	held   lease.Lease
	job    lease.Job
	sender *webhook.Sender

	mu     sync.Mutex
	got    []received
	answer func(n int) int // the status for the n-th request, counted from 1
	block  chan struct{}   // while set, requests wait for it to close
}

func newSinkEnv(t *testing.T, db *store.DB) *sinkEnv {
	t.Helper()
	storetest.Init(t, db)
	kek, err := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := secret.NewSealer(kek)
	e := &sinkEnv{t: t, db: db, sys: storetest.SystemCtx(t), sealer: sealer, clock: time.Now().UTC(),
		answer: func(int) int { return http.StatusNoContent }}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.got = append(e.got, received{r.URL.Path, r.Header.Get(webhook.HeaderEventID), r.Header.Get(webhook.HeaderEventType),
			r.Header.Get(webhook.HeaderSignature), b})
		code, block := e.answer(len(e.got)), e.block
		e.mu.Unlock()
		if block != nil {
			select {
			case <-block:
			case <-r.Context().Done():
			}
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	e.url = "https://example.com:" + port
	e.sender = &webhook.Sender{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		Now: func() time.Time { return e.clock }}
	e.leases = lease.New(db, "ctn_test", nil)
	e.job = e.newJob()
	if e.held, _, err = e.leases.TryAcquire(e.sys, "audit-sinks"); err != nil || e.held.Token == 0 {
		t.Fatal("no lease", err)
	}
	return e
}

// newJob is a job as a freshly started controller makes it: with no memory of earlier failures.
func (e *sinkEnv) newJob() lease.Job {
	return controller.AuditSinkJob(controller.AuditSinkOptions{DB: e.db, Leases: e.leases, Sealer: e.sealer, Sender: e.sender,
		Now: func() time.Time { return e.clock }, Logger: slog.New(slog.DiscardHandler)})
}

// sink makes a webhook sink that posts to path.
func (e *sinkEnv) sink(name, path string, entries bool) *ent.AuditSink {
	e.t.Helper()
	id := ids.New("ask")
	sealed, err := e.sealer.Seal(secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: id}, secret.New(sinkSecret))
	if err != nil {
		e.t.Fatal(err)
	}
	return e.db.Client().AuditSink.Create().SetID(id).SetKind("webhook").SetName(name).SetSettings(map[string]string{"url": e.url + path}).
		SetSecretEnc(sealed).SetEntries(entries).SaveX(e.sys)
}

// appendTo records an entry in the chain of org ("" for the instance chain) and returns it.
func (e *sinkEnv) appendTo(org string) audit.Entry {
	e.t.Helper()
	en, err := audit.Record(context.Background(), e.db, audit.Entry{OrgID: org, ActorType: audit.ActorUser, ActorID: "usr_ada",
		Action: "route.update", TargetType: "route", TargetID: "rte_1", Result: audit.Success})
	if err != nil {
		e.t.Fatal(err)
	}
	return en
}

// checkpoint stores a checkpoint of the chain of org at the entry's seq, with a signature that no
// sink verifies: the sinks ship it as it is.
func (e *sinkEnv) checkpoint(org string, en audit.Entry) string {
	e.t.Helper()
	id := ids.New("acp")
	var o any
	if org != "" {
		o = org
	}
	if _, err := e.db.Client().ExecContext(e.sys, "INSERT INTO audit_checkpoints (id, org_id, seq, head_hash, ts, key_id, signature) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		id, o, en.Seq, en.Hash, time.Now().UTC(), "key", []byte("sig")); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *sinkEnv) run() error { return e.job.Run(context.WithoutCancel(e.sys), e.held) }

func (e *sinkEnv) mustRun() {
	e.t.Helper()
	if err := e.run(); err != nil {
		e.t.Fatal(err)
	}
}

func (e *sinkEnv) requests(path string) []received {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []received
	for _, g := range e.got {
		if g.path == path {
			out = append(out, g)
		}
	}
	return out
}

func (e *sinkEnv) ids(path string) []string {
	var out []string
	for _, g := range e.requests(path) {
		out = append(out, g.id)
	}
	return out
}

func (e *sinkEnv) backlog(name string) auditsink.Backlog {
	e.t.Helper()
	bs, err := auditsink.Backlogs(e.sys, e.db)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, b := range bs {
		if b.Sink == name {
			return b
		}
	}
	e.t.Fatalf("no backlog of %s in %v", name, bs)
	return auditsink.Backlog{}
}

func (e *sinkEnv) status(s *ent.AuditSink) *ent.AuditSink {
	return e.db.Client().AuditSink.GetX(e.sys, s.ID)
}

// TestAuditSink_BacklogNeverBlocksAppend (#654): while a sink is blackholed, appends commit as
// fast as without one; the backlog grows, and once the sink is back it ships every item from its
// cursor and the backlog is 0.
func TestAuditSink_BacklogNeverBlocksAppend(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newSinkEnv(t, db)
		org := storetest.Org(t, db, "org-a")
		s := e.sink("blackhole", "/bh", true)
		en := e.appendTo(org)
		e.checkpoint(org, en)

		e.mu.Lock()
		e.answer, e.block = func(int) int { return http.StatusServiceUnavailable }, make(chan struct{})
		e.mu.Unlock()
		var wg sync.WaitGroup
		wg.Go(func() {
			if err := e.run(); err != nil {
				t.Errorf("pass: %v", err)
			}
		})
		waitUntil(t, func() bool { return len(e.requests("/bh")) > 0 }) // the sink holds the pass
		var worst time.Duration
		for range 25 {
			start := time.Now()
			e.appendTo(org)
			e.appendTo("")
			worst = max(worst, time.Since(start))
		}
		if worst > time.Second {
			t.Errorf("an append took %v while a sink hung", worst)
		}
		close(e.block)
		wg.Wait()

		if b := e.backlog("blackhole"); b.Items == 0 || b.Oldest.IsZero() {
			t.Fatalf("backlog %+v, want items waiting", b)
		}
		if got := e.status(s); got.LastError == "" || got.LastSuccessAt != nil {
			t.Fatalf("status: error %q, last success %v", got.LastError, got.LastSuccessAt)
		}

		e.mu.Lock()
		e.answer, e.block = func(int) int { return http.StatusNoContent }, nil
		e.mu.Unlock()
		e.clock = e.clock.Add(auditsink.BackoffMin)
		e.mustRun()
		if b := e.backlog("blackhole"); b.Items != 0 || !b.Oldest.IsZero() {
			t.Fatalf("backlog %+v after the sink came back, want none", b)
		}
		if got := e.status(s); got.LastError != "" || got.LastSuccessAt == nil {
			t.Fatalf("status: error %q, last success %v", got.LastError, got.LastSuccessAt)
		}
	})
}

// TestAuditSink_ShipsPerChain (#654): every enabled sink gets every chain's checkpoints, a sink set
// to get entries also the entries, each item signed with the sink's secret, once, from a cursor
// of its own per chain; a disabled sink gets nothing.
func TestAuditSink_ShipsPerChain(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newSinkEnv(t, db)
		a, b := storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b")
		cps := e.sink("cps", "/cps", false)
		both := e.sink("both", "/both", true)
		off := e.sink("off", "/off", true)
		db.Client().AuditSink.UpdateOne(off).SetEnabled(false).ExecX(e.sys)
		want := map[string]audit.Entry{}
		var wantCP []string
		for _, org := range []string{a, b, ""} {
			en := e.appendTo(org)
			want[en.ID] = en
			wantCP = append(wantCP, e.checkpoint(org, en))
		}
		e.mustRun()
		e.mustRun() // nothing twice

		got := e.ids("/cps")
		slices.Sort(got)
		slices.Sort(wantCP)
		if !slices.Equal(got, wantCP) {
			t.Errorf("checkpoint sink received %v, want %v", got, wantCP)
		}
		for _, r := range e.requests("/cps") {
			if r.typ != "audit.checkpoint" {
				t.Errorf("checkpoint sink received a %s", r.typ)
			}
		}
		var entries []string
		for _, r := range e.requests("/both") {
			if err := webhook.Verify(r.sig, r.body, sinkSecret, e.clock); err != nil {
				t.Errorf("signature: %v", err)
			}
			if strings.Contains(string(r.body), sinkSecret) {
				t.Error("a delivery holds the sink's secret")
			}
			var m map[string]any
			if err := json.Unmarshal(r.body, &m); err != nil {
				t.Fatal(err)
			}
			if m["type"] != r.typ {
				t.Errorf("body type %v, header %s", m["type"], r.typ)
			}
			if r.typ == "audit.entry" {
				entries = append(entries, r.id)
				en := want[r.id]
				if org, _ := m["org_id"].(string); org != en.OrgID || m["chain"] != en.Chain() || m["action"] != "route.update" {
					t.Errorf("entry body %v for %+v", m, en)
				}
			}
		}
		if len(e.requests("/both")) != 6 || len(entries) != 3 {
			t.Errorf("entry sink received %d items, %d entries; want 6 and 3", len(e.requests("/both")), len(entries))
		}
		if len(e.requests("/off")) != 0 {
			t.Error("a disabled sink received items")
		}
		if n := db.Client().AuditSinkCursor.Query().Where(auditsinkcursor.SinkID(both.ID)).CountX(e.sys); n != 3 {
			t.Errorf("%d cursors for a sink of 3 chains", n)
		}
		for _, c := range db.Client().AuditSinkCursor.Query().Where(auditsinkcursor.SinkID(cps.ID)).AllX(e.sys) {
			if c.CheckpointSeq != 1 || c.EntrySeq != 0 || c.OldestUnshippedAt != nil {
				t.Errorf("cursor of %s: %+v", c.Chain, c)
			}
		}

		// New items follow, and only they.
		en := e.appendTo(a)
		id := e.checkpoint(a, en)
		e.mustRun()
		if got := e.ids("/cps"); len(got) != 4 || got[3] != id {
			t.Errorf("checkpoint sink received %v, want %s as the fourth", got, id)
		}
		if len(e.requests("/off")) != 0 {
			t.Error("a disabled sink received items")
		}
	})
}

// TestAuditSink_AtLeastOnceAndCursorSurvivesRestart (#654): a replica that lost the lease moves no
// cursor, so its successor ships the item again; a restarted controller continues from the cursors
// and a failure in the middle of a batch resumes after the last acknowledged item.
func TestAuditSink_AtLeastOnceAndCursorSurvivesRestart(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newSinkEnv(t, db)
		e.sink("hook", "/h", true)
		first := e.appendTo("")
		stale := lease.Lease{Name: "audit-sinks", Token: e.held.Token + 1}
		if err := e.job.Run(context.WithoutCancel(e.sys), stale); !errors.Is(err, lease.ErrLost) {
			t.Fatalf("lost lease: %v", err)
		}
		if db.Client().AuditSinkCursor.Query().CountX(e.sys) != 0 {
			t.Fatal("a replica without the lease moved a cursor")
		}
		e.mustRun()
		if got := e.ids("/h"); !slices.Equal(got, []string{first.ID, first.ID}) {
			t.Fatalf("received %v, want the entry twice, at least once", got)
		}

		e.job = e.newJob() // a restart
		e.mustRun()
		if len(e.requests("/h")) != 2 {
			t.Fatalf("a restart shipped %d items again", len(e.requests("/h"))-2)
		}

		// The second request of the next pass fails: the first item is acknowledged, the second
		// is sent again by the pass after.
		second, third := e.appendTo(""), e.appendTo("")
		before := len(e.requests("/h"))
		e.mu.Lock()
		e.answer = func(n int) int {
			if n == before+2 {
				return http.StatusServiceUnavailable
			}
			return http.StatusNoContent
		}
		e.mu.Unlock()
		e.mustRun()
		e.clock = e.clock.Add(auditsink.BackoffMin)
		e.mustRun()
		if got := e.ids("/h")[before:]; !slices.Equal(got, []string{second.ID, third.ID, third.ID}) {
			t.Fatalf("received %v, want %s, %s (failed), %s", got, second.ID, third.ID, third.ID)
		}
	})
}

// TestAuditSink_BackoffAndStatus (#654): a failing sink is tried again after 10 s, then 20 s and so
// on up to 5 min; its status holds the failure, without the URL or the secret, until a success.
func TestAuditSink_BackoffAndStatus(t *testing.T) {
	e := newSinkEnv(t, storetest.Migrated(t, store.SQLite))
	s := e.sink("hook", "/token-in-path", false)
	e.checkpoint("", e.appendTo(""))
	e.answer = func(int) int { return http.StatusInternalServerError }
	e.mustRun()
	n := func() int { return len(e.requests("/token-in-path")) }
	if n() != 1 {
		t.Fatalf("%d requests", n())
	}
	if got := e.status(s).LastError; !strings.Contains(got, "500") || strings.Contains(got, "token-in-path") || strings.Contains(got, sinkSecret) {
		t.Fatalf("last error %q", got)
	}
	wait := auditsink.BackoffMin
	for step := range 7 {
		e.clock = e.clock.Add(wait - time.Second)
		e.mustRun()
		if n() != 1+step {
			t.Fatalf("step %d: retried %v early", step, time.Second)
		}
		e.clock = e.clock.Add(time.Second)
		e.mustRun()
		if n() != 2+step {
			t.Fatalf("step %d: not retried after %v", step, wait)
		}
		wait = min(2*wait, auditsink.BackoffMax)
	}
	if wait != auditsink.BackoffMax {
		t.Fatalf("backoff ended at %v", wait)
	}
	e.answer = func(int) int { return http.StatusNoContent }
	e.clock = e.clock.Add(auditsink.BackoffMax)
	e.mustRun()
	if got := e.status(s); got.LastError != "" || got.LastSuccessAt == nil {
		t.Fatalf("status after a success: %q, %v", got.LastError, got.LastSuccessAt)
	}
}

// TestAuditSink_UnusableSinks (#654): a sink that cannot work (no URL, no secret, a secret sealed
// for another row, a kind that is not available yet, a plain http:// URL) fails visibly and
// blocks nothing else; an entry too large for a delivery is shipped without its diff; deleting a
// sink deletes its cursors.
func TestAuditSink_UnusableSinks(t *testing.T) {
	e := newSinkEnv(t, storetest.Migrated(t, store.SQLite))
	c := e.db.Client()
	good := e.sink("good", "/good", true)
	noURL := c.AuditSink.Create().SetKind("webhook").SetName("no-url").SetSecretEnc([]byte("x")).SaveX(e.sys)
	noSecret := c.AuditSink.Create().SetKind("webhook").SetName("no-secret").SetSettings(map[string]string{"url": e.url}).SaveX(e.sys)
	foreign := c.AuditSink.Create().SetKind("webhook").SetName("foreign").SetSettings(map[string]string{"url": e.url}).SetSecretEnc([]byte("not sealed")).SaveX(e.sys)
	syslog := c.AuditSink.Create().SetKind("syslog").SetName("syslog").SaveX(e.sys)
	plain := e.sink("plain", "/plain", false)
	c.AuditSink.UpdateOne(plain).SetSettings(map[string]string{"url": "http://example.com/plain"}).ExecX(e.sys)
	big, err := audit.Record(context.Background(), e.db, audit.Entry{ActorType: audit.ActorUser, ActorID: "usr_ada", Action: "route.update",
		Result: audit.Success, Diff: strings.Repeat("d", 2*webhook.MaxBody)})
	if err != nil {
		t.Fatal(err)
	}
	e.checkpoint("", big)
	e.mustRun()
	for _, s := range []*ent.AuditSink{noURL, noSecret, foreign, syslog, plain} {
		if got := e.status(s).LastError; got == "" || strings.Contains(got, "example.com") {
			t.Errorf("%s: last error %q", s.Name, got)
		}
	}
	if len(e.requests("/plain")) != 0 {
		t.Error("an http:// sink was delivered to")
	}
	got := e.requests("/good")
	if len(got) != 2 || !slices.ContainsFunc(got, func(r received) bool { return r.id == big.ID }) {
		t.Fatalf("the good sink received %d items", len(got))
	}
	for _, r := range got {
		var m map[string]any
		if err := json.Unmarshal(r.body, &m); err != nil || len(r.body) > webhook.MaxBody {
			t.Fatalf("body of %d bytes: %v", len(r.body), err)
		}
		if r.id == big.ID && (m["truncated"] != true || m["diff"] != "") {
			t.Fatalf("large entry: truncated %v, diff of %d bytes", m["truncated"], len(m["diff"].(string)))
		}
	}
	if e.status(good).LastError != "" {
		t.Error("the good sink shows an error")
	}

	if c.AuditSinkCursor.Query().Where(auditsinkcursor.SinkID(good.ID)).CountX(e.sys) != 1 {
		t.Fatal("no cursor of the good sink")
	}
	c.AuditSink.DeleteOne(good).ExecX(e.sys)
	if n := c.AuditSinkCursor.Query().Where(auditsinkcursor.SinkID(good.ID)).CountX(e.sys); n != 0 {
		t.Fatalf("%d cursors left after the sink was deleted", n)
	}
	// A secret is never part of what the store prints.
	if s := fmt.Sprintf("%v", e.status(foreign)); strings.Contains(s, "not sealed") || !strings.Contains(s, "secret_enc=<sensitive>") {
		t.Errorf("the sink prints its secret: %s", s)
	}
}

// TestAuditSink_BacklogAlertAndMetrics (#654): the backlog and the oldest unshipped time are metrics
// per sink, the alert fires when the oldest item has waited 15 min and resolves when the sink has
// caught up.
func TestAuditSink_BacklogAlertAndMetrics(t *testing.T) {
	e := newSinkEnv(t, storetest.Migrated(t, store.SQLite))
	s := e.sink("down", "/down", true)
	e.answer = func(int) int { return http.StatusBadGateway }
	reg := prometheus.NewRegistry()
	if _, err := controller.NewMetrics(reg, e.db, e.sys, func() time.Time { return e.clock }); err != nil {
		t.Fatal(err)
	}
	if v := families(t, reg)["rpmgr_audit_sink_backlog"].GetMetric()[0].GetGauge().GetValue(); v != 0 {
		t.Fatalf("a backlog of %v without a chain", v)
	}
	en := e.appendTo("")
	e.checkpoint("", en)
	e.mustRun()
	f := families(t, reg)
	if v := f["rpmgr_audit_sink_backlog"].GetMetric()[0]; v.GetGauge().GetValue() != 2 || v.GetLabel()[0].GetValue() != "down" {
		t.Fatalf("backlog metric: %v", v)
	}
	if v := f["rpmgr_audit_sink_oldest_unshipped_timestamp_seconds"].GetMetric()[0].GetGauge().GetValue(); v != float64(en.Time.Unix()) {
		t.Fatalf("oldest metric %v, want %d", v, en.Time.Unix())
	}

	leases := lease.New(e.db, "ctn_test", nil)
	job := controller.AlertJob(controller.AlertOptions{DB: e.db, Leases: leases, Now: func() time.Time { return e.clock }, Logger: slog.New(slog.DiscardHandler)})
	held, _, err := leases.TryAcquire(e.sys, "alerts")
	if err != nil || held.Token == 0 {
		t.Fatal("no lease", err)
	}
	firing := func() int {
		return e.db.Client().Alert.Query().Where(alert.Kind(alerts.AuditSinkBacklog), alert.StateEQ(alert.StateFiring), alert.SubjectID(s.ID)).CountX(e.sys)
	}
	alertPass := func() {
		t.Helper()
		if err := job.Run(context.WithoutCancel(e.sys), held); err != nil {
			t.Fatal(err)
		}
	}
	e.clock = en.Time.Add(alerts.AuditSinkBacklogFor - time.Second)
	alertPass()
	if firing() != 0 {
		t.Fatal("the alert fires before 15 min")
	}
	e.clock = en.Time.Add(alerts.AuditSinkBacklogFor + time.Second)
	alertPass()
	if firing() != 1 {
		t.Fatal("the alert does not fire after 15 min")
	}
	e.answer = func(int) int { return http.StatusNoContent }
	e.clock = e.clock.Add(auditsink.BackoffMax)
	e.mustRun()
	alertPass()
	if firing() != 0 || e.db.Client().Alert.Query().Where(alert.Kind(alerts.AuditSinkBacklog), alert.StateEQ(alert.StateResolved)).CountX(e.sys) != 1 {
		t.Fatal("the alert did not resolve")
	}
	if v := families(t, reg)["rpmgr_audit_sink_backlog"].GetMetric()[0].GetGauge().GetValue(); v != 0 {
		t.Fatalf("backlog metric %v after catching up", v)
	}
}
