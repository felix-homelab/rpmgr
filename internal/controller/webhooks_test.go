// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/event"
	ewebhook "github.com/felix-homelab/rpmgr/internal/store/ent/webhook"
	"github.com/felix-homelab/rpmgr/internal/store/ent/webhookdelivery"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// hookEnv is a database, a TLS receiver on loopback that records what it gets, and the delivery
// job with its clock.
type hookEnv struct {
	t      *testing.T
	db     *store.DB
	sys    context.Context
	sealer *secret.Sealer
	url    string
	clock  time.Time
	leases *lease.Leases
	held   lease.Lease
	job    lease.Job

	logs *bytes.Buffer // what the job logs

	mu     sync.Mutex
	got    []received
	answer func(path string, n int) int // the status for the n-th request to path
}

type received struct {
	path, id, typ, sig string
	body               []byte
}

func newHookEnv(t *testing.T, guarded bool) *hookEnv {
	t.Helper()
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	kek, err := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := secret.NewSealer(kek)
	e := &hookEnv{t: t, db: db, sys: storetest.SystemCtx(t), sealer: sealer, clock: time.Now().UTC(),
		logs: &bytes.Buffer{}, answer: func(string, int) int { return http.StatusNoContent }}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		n := 0
		for _, g := range e.got {
			if g.path == r.URL.Path {
				n++
			}
		}
		e.got = append(e.got, received{r.URL.Path, r.Header.Get(webhook.HeaderEventID), r.Header.Get(webhook.HeaderEventType),
			r.Header.Get(webhook.HeaderSignature), b})
		code := e.answer(r.URL.Path, n)
		e.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	e.url = "https://example.com:" + port
	sender := &webhook.Sender{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		Now: func() time.Time { return e.clock }}
	e.leases = lease.New(db, "ctn_test", nil)
	o := controller.WebhookOptions{DB: db, Leases: e.leases, Sealer: sealer, Sender: sender, Now: func() time.Time { return e.clock },
		Logger: slog.New(slog.NewTextHandler(e.logs, nil))}
	if !guarded {
		o = controller.LoopbackWebhooks(o)
	}
	e.job = controller.WebhookJob(o)
	var ok bool
	if e.held, ok, err = e.leases.TryAcquire(e.sys, "webhooks"); err != nil || !ok {
		t.Fatal("no lease", err)
	}
	return e
}

const hookSecret = "rpmgr_whs_hookhookhookhookhookhookhookhookhook01" //nolint:gosec // G101: a test secret

// hook makes an endpoint of org ("" for the instance) at path, enabled at the job's clock.
func (e *hookEnv) hook(org, path string, types ...string) *ent.Webhook {
	e.t.Helper()
	id := ids.New("whk")
	sealed, err := e.sealer.Seal(secret.Context{Table: "webhooks", Column: "secret_enc", RowID: id}, secret.New(hookSecret))
	if err != nil {
		e.t.Fatal(err)
	}
	c := e.db.Client().Webhook.Create().SetID(id).SetURL(e.url + path).SetSecretEnc(sealed).SetEventTypes(types).SetEnabledAt(e.clock)
	if org != "" {
		c.SetOrgID(org)
	}
	return c.SaveX(e.sys)
}

// change records an audited change of org ("" for the instance) and returns its event.
func (e *hookEnv) change(org, action string) *ent.Event {
	e.t.Helper()
	if _, err := audit.Record(context.Background(), e.db, audit.Entry{OrgID: org, ActorType: audit.ActorUser, ActorID: "usr_ada",
		Action: action, TargetType: "route", TargetID: "rte_1", Result: audit.Success}); err != nil {
		e.t.Fatal(err)
	}
	return e.db.Client().Event.Query().Order(ent.Desc(event.FieldTs), ent.Desc(event.FieldID)).FirstX(e.sys)
}

func (e *hookEnv) run() error {
	return e.job.Run(context.WithoutCancel(e.sys), e.held)
}

func (e *hookEnv) mustRun() {
	e.t.Helper()
	if err := e.run(); err != nil {
		e.t.Fatal(err)
	}
}

// ids are the event IDs path received, in order.
func (e *hookEnv) ids(path string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, g := range e.got {
		if g.path == path {
			out = append(out, g.id)
		}
	}
	return out
}

// TestWebhook_EventsScopedToOrg (#649): an org's endpoint receives only that org's events, of the
// types it names, an instance endpoint only instance events, a disabled endpoint nothing, and no
// endpoint the events from before it was enabled; every envelope is signed and holds no resource
// body and no secret.
func TestWebhook_EventsScopedToOrg(t *testing.T) {
	e := newHookEnv(t, false)
	a, b := storetest.Org(t, e.db, "org-a"), storetest.Org(t, e.db, "org-b")
	before := e.change(a, "route.update")
	e.clock = time.Now().UTC().Add(time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	e.hook(a, "/a")
	e.hook(a, "/routes", "route.*", "token.revoke")
	e.hook(b, "/b")
	e.hook("", "/inst")
	off := e.hook(a, "/off")
	e.db.Client().Webhook.UpdateOne(off).SetEnabled(false).SetDisabledReason(ewebhook.DisabledReasonPerson).ExecX(e.sys)
	time.Sleep(2 * time.Millisecond)
	ra := e.change(a, "rpmgr.v1.RouteService.UpdateRoute")
	ta := e.change(a, "token.revoke")
	ua := e.change(a, "user.update")
	rb := e.change(b, "route.delete")
	inst := e.change("", "release.create")
	e.mustRun()
	e.mustRun() // nothing twice
	for path, want := range map[string][]string{"/a": {ra.ID, ta.ID, ua.ID}, "/routes": {ra.ID, ta.ID}, "/b": {rb.ID}, "/inst": {inst.ID}, "/off": nil} {
		got := e.ids(path)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s received %v, want %v", path, got, want)
		}
		if slices.Contains(got, before.ID) {
			t.Errorf("%s received an event from before it was enabled", path)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, g := range e.got {
		var env map[string]any
		if err := json.Unmarshal(g.body, &env); err != nil {
			t.Fatal(err)
		}
		org, _ := env["org_id"].(string)
		want := map[string]string{"/a": a, "/routes": a, "/b": b, "/inst": ""}[g.path]
		if org != want || env["id"] != g.id || env["type"] != g.typ || len(env) != 8 || strings.Contains(string(g.body), "rpmgr_whs_") {
			t.Errorf("%s got envelope %s", g.path, g.body)
		}
		if err := webhook.Verify(g.sig, g.body, hookSecret, e.clock); err != nil {
			t.Errorf("%s: %v", g.path, err)
		}
	}
	if n := e.db.Client().WebhookDelivery.Query().Where(webhookdelivery.StatusCode(http.StatusNoContent)).CountX(e.sys); n != 7 {
		t.Errorf("%d deliveries recorded, want 7", n)
	}
	// An org reads only its own deliveries.
	if n := e.db.Client().WebhookDelivery.Query().CountX(storetest.OrgCtx(t, b)); n != 1 {
		t.Errorf("org b reads %d deliveries, want its 1", n)
	}
}

// TestWebhookJob_Retries (#649): a failed delivery is retried after 10 s with the same event ID
// and attempt numbers rising, a 2xx ends it and records the endpoint's success; a receiver that
// keeps failing makes the endpoint failing, and after 3 days of it disabled with the event
// webhook.disable, after which it gets nothing.
func TestWebhookJob_Retries(t *testing.T) {
	e := newHookEnv(t, false)
	org := storetest.Org(t, e.db, "org-a")
	h := e.hook(org, "/flaky")
	e.answer = func(_ string, n int) int {
		if n < 2 {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	}
	time.Sleep(2 * time.Millisecond)
	ev := e.change(org, "route.update")
	c := e.db.Client()
	e.mustRun()
	first := c.WebhookDelivery.Query().OnlyX(e.sys)
	if first.Attempt != 1 || first.StatusCode != 503 || first.NextAttemptAt == nil || first.NextAttemptAt.Sub(first.SentAt) != webhook.RetryFirst ||
		!strings.Contains(first.Error, "503") {
		t.Fatalf("first attempt %+v", first)
	}
	if hk := c.Webhook.GetX(e.sys, h.ID); hk.FailingSince == nil || hk.LastSuccessAt != nil {
		t.Fatalf("endpoint %+v, want failing", hk)
	}
	e.clock = e.clock.Add(9 * time.Second)
	e.mustRun()
	if len(e.ids("/flaky")) != 1 {
		t.Fatal("retried before 10 s")
	}
	e.clock = e.clock.Add(time.Second)
	e.mustRun() // the second attempt fails, the third is due 20 s later
	e.clock = e.clock.Add(20 * time.Second)
	e.mustRun()
	if got := e.ids("/flaky"); !slices.Equal(got, []string{ev.ID, ev.ID, ev.ID}) {
		t.Fatalf("received %v, want the same event three times", got)
	}
	rows := c.WebhookDelivery.Query().Order(ent.Asc(webhookdelivery.FieldAttempt)).AllX(e.sys)
	if len(rows) != 3 || rows[2].Attempt != 3 || rows[2].StatusCode != 200 || rows[2].Error != "" || rows[0].NextAttemptAt != nil ||
		rows[1].NextAttemptAt != nil || rows[2].NextAttemptAt != nil {
		t.Fatalf("attempts %+v", rows)
	}
	if hk := c.Webhook.GetX(e.sys, h.ID); hk.FailingSince != nil || hk.LastSuccessAt == nil {
		t.Fatalf("endpoint %+v, want its success recorded", hk)
	}
	e.clock = e.clock.Add(time.Hour)
	e.mustRun()
	if len(e.ids("/flaky")) != 3 {
		t.Fatal("delivered again after a success")
	}

	// Failing for 3 days: disabled with an event.
	e.answer = func(string, int) int { return http.StatusInternalServerError }
	e.clock = time.Now().UTC()
	e.change(org, "route.update")
	e.mustRun()
	since := c.Webhook.GetX(e.sys, h.ID).FailingSince
	if since == nil || c.Webhook.GetX(e.sys, h.ID).Enabled == false {
		t.Fatal("want failing and still enabled")
	}
	// Three days later, by its failing_since, another failed delivery disables it.
	c.Webhook.UpdateOneID(h.ID).SetFailingSince(since.Add(-webhook.DisableAfter + time.Second)).ExecX(e.sys)
	e.change(org, "route.update")
	e.mustRun()
	if !c.Webhook.GetX(e.sys, h.ID).Enabled {
		t.Fatal("disabled a second before 3 days")
	}
	c.Webhook.UpdateOneID(h.ID).SetFailingSince(since.Add(-webhook.DisableAfter)).ExecX(e.sys)
	e.change(org, "route.update")
	e.mustRun()
	hk := c.Webhook.GetX(e.sys, h.ID)
	if hk.Enabled || hk.DisabledReason == nil || *hk.DisabledReason != ewebhook.DisabledReasonFailing {
		t.Fatalf("endpoint %+v, want disabled as failing", hk)
	}
	dis := c.Event.Query().Where(event.Type("webhook.disable")).OnlyX(e.sys)
	if dis.SubjectID != h.ID || dis.OrgID == nil || *dis.OrgID != org {
		t.Fatalf("event %+v", dis)
	}
	n := len(e.ids("/flaky"))
	e.clock = e.clock.Add(time.Hour)
	e.mustRun()
	if len(e.ids("/flaky")) != n {
		t.Fatal("a disabled endpoint got a delivery")
	}
}

// TestWebhookJob_LeaseTakeoverAndGuard (#649): a replica that lost the lease records nothing, so
// the next holder sends the event again with the same Rpmgr-Event-Id; with the egress guard in
// force an org endpoint on loopback is refused, recorded without the address, and retried.
func TestWebhookJob_LeaseTakeoverAndGuard(t *testing.T) {
	e := newHookEnv(t, false)
	org := storetest.Org(t, e.db, "org-a")
	e.hook(org, "/dup")
	time.Sleep(2 * time.Millisecond)
	ev := e.change(org, "route.update")
	stale := lease.Lease{Name: "webhooks", Token: e.held.Token + 1}
	if err := e.job.Run(context.WithoutCancel(e.sys), stale); !errors.Is(err, lease.ErrLost) {
		t.Fatalf("lost lease: %v", err)
	}
	if e.db.Client().WebhookDelivery.Query().CountX(e.sys) != 0 {
		t.Fatal("a replica without the lease recorded a delivery")
	}
	e.mustRun()
	if got := e.ids("/dup"); !slices.Equal(got, []string{ev.ID, ev.ID}) {
		t.Fatalf("received %v, want the event twice, at least once", got)
	}
	if n := e.db.Client().WebhookDelivery.Query().CountX(e.sys); n != 1 {
		t.Fatalf("%d deliveries recorded, want 1", n)
	}

	g := newHookEnv(t, true)
	org = storetest.Org(t, g.db, "org-a")
	g.hook(org, "/guarded")
	inst := g.hook("", "/inst")
	time.Sleep(2 * time.Millisecond)
	g.change(org, "route.update")
	g.change("", "release.create")
	g.mustRun()
	if len(g.ids("/guarded")) != 0 || len(g.ids("/inst")) != 1 {
		t.Fatalf("guarded %v, instance %v: want the org endpoint refused and the instance one reached", g.ids("/guarded"), g.ids("/inst"))
	}
	d := g.db.Client().WebhookDelivery.Query().Where(webhookdelivery.WebhookIDNEQ(inst.ID)).OnlyX(g.sys)
	if !strings.Contains(d.Error, "loopback") || strings.Contains(d.Error, "127.0.0.1") || d.NextAttemptAt == nil || d.StatusCode != 0 {
		t.Fatalf("refused delivery %+v", d)
	}
}

// TestPurgeDeliveries (#649): deliveries go after 30 days, and an endpoint keeps at most 1 000,
// but never one a retry waits on nor one within the give-up window.
func TestPurgeDeliveries(t *testing.T) {
	e := newHookEnv(t, false)
	org := storetest.Org(t, e.db, "org-a")
	h := e.hook(org, "/many")
	c := e.db.Client()
	now := time.Now().UTC()
	var rows []*ent.WebhookDeliveryCreate
	for i := range 1005 {
		cr := c.WebhookDelivery.Create().SetWebhookID(h.ID).SetOrgID(org).SetEventID("evt_" + string(rune('a'+i%26)) + strings.Repeat("x", i/26)).
			SetAttempt(1).SetSentAt(now.Add(-48*time.Hour - time.Duration(i)*time.Second))
		if i == 1004 {
			cr.SetNextAttemptAt(now) // the oldest still waits on a retry
		}
		rows = append(rows, cr)
	}
	c.WebhookDelivery.CreateBulk(rows...).ExecX(e.sys)
	recent := c.WebhookDelivery.Create().SetWebhookID(h.ID).SetOrgID(org).SetEventID("evt_recent").SetAttempt(1).SetSentAt(now).SaveX(e.sys)
	old := c.WebhookDelivery.Create().SetWebhookID(h.ID).SetOrgID(org).SetEventID("evt_old").SetAttempt(1).
		SetSentAt(now.Add(-webhook.KeepFor - time.Second)).SaveX(e.sys)
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error { return controller.PurgeDeliveries(e.sys, tx, now) }); err != nil {
		t.Fatal(err)
	}
	if n := c.WebhookDelivery.Query().CountX(e.sys); n != webhook.KeepAtMost+1 {
		t.Fatalf("%d deliveries left, want 1 000 and the one a retry waits on", n)
	}
	if !c.WebhookDelivery.Query().Where(webhookdelivery.ID(recent.ID)).ExistX(e.sys) ||
		c.WebhookDelivery.Query().Where(webhookdelivery.ID(old.ID)).ExistX(e.sys) ||
		!c.WebhookDelivery.Query().Where(webhookdelivery.NextAttemptAtNotNil()).ExistX(e.sys) {
		t.Fatal("kept the wrong deliveries")
	}
}

// TestWebhookJob_DeliveryDuringRotation: while the previous secret still signs, the job signs each
// delivery with both, so a receiver that has either verifies it; afterwards with the new one only.
func TestWebhookJob_DeliveryDuringRotation(t *testing.T) {
	e := newHookEnv(t, false)
	org := storetest.Org(t, e.db, "org-a")
	h := e.hook(org, "/rot")
	const next = "rpmgr_whs_nextnextnextnextnextnextnextnextnext02" //nolint:gosec // G101: a test secret
	cur, _ := e.sealer.Seal(secret.Context{Table: "webhooks", Column: "secret_enc", RowID: h.ID}, secret.New(next))
	prev, _ := e.sealer.Seal(secret.Context{Table: "webhooks", Column: "previous_secret_enc", RowID: h.ID}, secret.New(hookSecret))
	e.db.Client().Webhook.UpdateOneID(h.ID).SetSecretEnc(cur).SetPreviousSecretEnc(prev).SetPreviousUntil(e.clock.Add(time.Hour)).ExecX(e.sys)
	time.Sleep(2 * time.Millisecond)
	e.change(org, "route.update")
	e.mustRun()
	e.mu.Lock()
	first := e.got[0]
	e.mu.Unlock()
	if strings.Count(first.sig, "v1=") != 2 {
		t.Fatalf("during the rotation: %s", first.sig)
	}
	for _, k := range []string{next, hookSecret} {
		if err := webhook.Verify(first.sig, first.body, k, e.clock); err != nil {
			t.Errorf("the signature does not verify with %s...: %v", k[:14], err)
		}
	}
	// Past previous_until the old secret has stopped signing.
	e.clock = e.clock.Add(2 * time.Hour)
	e.change(org, "route.update")
	e.mustRun()
	e.mu.Lock()
	last := e.got[len(e.got)-1]
	e.mu.Unlock()
	if len(e.got) != 2 || strings.Count(last.sig, "v1=") != 1 || webhook.Verify(last.sig, last.body, hookSecret, e.clock) == nil ||
		webhook.Verify(last.sig, last.body, next, e.clock) != nil {
		t.Fatalf("after the rotation: %d requests, %s", len(e.got), last.sig)
	}
}

// TestWebhookJob_UnsealFailure: an endpoint whose secret cannot be opened gets a failed attempt,
// with a retry, an error that tells the owners nothing of the cause, and a log line that names
// the endpoint and not the secret; the other endpoints are delivered to.
func TestWebhookJob_UnsealFailure(t *testing.T) {
	e := newHookEnv(t, false)
	org := storetest.Org(t, e.db, "org-a")
	bad := e.hook(org, "/bad")
	e.hook(org, "/good")
	e.db.Client().Webhook.UpdateOneID(bad.ID).SetSecretEnc([]byte("not sealed at all")).ExecX(e.sys)
	time.Sleep(2 * time.Millisecond)
	e.change(org, "route.update")
	e.mustRun()
	if len(e.ids("/bad")) != 0 || len(e.ids("/good")) != 1 {
		t.Fatalf("bad %v, good %v", e.ids("/bad"), e.ids("/good"))
	}
	d := e.db.Client().WebhookDelivery.Query().Where(webhookdelivery.WebhookID(bad.ID)).OnlyX(e.sys)
	if d.Error == "" || d.StatusCode != 0 || d.NextAttemptAt == nil || d.Attempt != 1 {
		t.Fatalf("the failed attempt: %+v", d)
	}
	for _, text := range []string{d.Error, e.logs.String()} {
		if strings.Contains(text, hookSecret) || strings.Contains(text, strings.TrimPrefix(hookSecret, webhook.SecretPrefix)) ||
			strings.Contains(text, "not sealed at all") {
			t.Fatalf("a secret is in %q", text)
		}
	}
	if !strings.Contains(e.logs.String(), bad.ID) {
		t.Errorf("the log does not name the endpoint: %q", e.logs.String())
	}
}

// TestWebhookJob_RetryOfPurgedEvent: a retry whose event has left the outbox is dropped: no
// request, no new attempt, and the schedule of the old one ends.
func TestWebhookJob_RetryOfPurgedEvent(t *testing.T) {
	e := newHookEnv(t, false)
	org := storetest.Org(t, e.db, "org-a")
	h := e.hook(org, "/gone")
	e.answer = func(string, int) int { return http.StatusInternalServerError }
	time.Sleep(2 * time.Millisecond)
	ev := e.change(org, "route.update")
	e.mustRun()
	if len(e.ids("/gone")) != 1 {
		t.Fatalf("first attempt: %v", e.ids("/gone"))
	}
	e.db.Client().Event.DeleteOneID(ev.ID).ExecX(e.sys)
	e.clock = e.clock.Add(time.Minute)
	e.mustRun()
	if len(e.ids("/gone")) != 1 {
		t.Fatalf("a request for an event that is gone: %v", e.ids("/gone"))
	}
	ds := e.db.Client().WebhookDelivery.Query().Where(webhookdelivery.WebhookID(h.ID)).AllX(e.sys)
	if len(ds) != 1 || ds[0].NextAttemptAt != nil {
		t.Fatalf("the deliveries: %+v", ds)
	}
	e.clock = e.clock.Add(time.Hour)
	e.mustRun()
	if len(e.ids("/gone")) != 1 {
		t.Fatal("the dropped retry came back")
	}
}

// TestWebhookJob_OwnAddressesPerPass: the controller's addresses are read at each pass, so an
// interface that appears after the start (a VPN, a Docker bridge) is excluded at once, even
// inside a listed private range.
func TestWebhookJob_OwnAddressesPerPass(t *testing.T) {
	e := newHookEnv(t, true)
	org := storetest.Org(t, e.db, "org-a")
	h := e.hook(org, "/own")
	var own []netip.Addr
	sender := &webhook.Sender{Now: func() time.Time { return e.clock },
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.9.9.9")}, nil
		}}
	e.job = controller.WebhookJob(controller.WebhookOptions{DB: e.db, Leases: e.leases, Sealer: e.sealer, Sender: sender,
		Now: func() time.Time { return e.clock }, Logger: slog.New(slog.DiscardHandler),
		Own: func() []netip.Addr { return own },
		Private: func(context.Context) ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil
		}})
	time.Sleep(2 * time.Millisecond)
	e.change(org, "route.update")
	e.mustRun()
	d := e.db.Client().WebhookDelivery.Query().Where(webhookdelivery.WebhookID(h.ID)).OnlyX(e.sys)
	if strings.Contains(d.Error, "egress guard") {
		t.Fatalf("the listed range was refused: %s", d.Error)
	}
	own = []netip.Addr{netip.MustParseAddr("10.9.9.9")} // the interface appears
	e.clock = e.clock.Add(time.Minute)
	e.mustRun()
	d = e.db.Client().WebhookDelivery.Query().Where(webhookdelivery.WebhookID(h.ID), webhookdelivery.Attempt(2)).OnlyX(e.sys)
	if !strings.Contains(d.Error, "an address of the controller") || strings.Contains(d.Error, "10.9.9.9") {
		t.Fatalf("after the interface appeared: %s", d.Error)
	}
}
