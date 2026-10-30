// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/mail"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/mailjob"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// fakeMailer records what is sent; down makes every send fail, failFor one recipient's.
type fakeMailer struct {
	mu         sync.Mutex
	configured bool
	down       bool
	failFor    string
	sent       []mail.Message
	// before, if set, runs at the start of every send with the number of this send (from 1); an
	// error fails the send.
	before func(n int) error
	calls  int
}

func (f *fakeMailer) Configured(context.Context) (bool, error) { return f.configured, nil }

func (f *fakeMailer) Send(_ context.Context, m mail.Message) error {
	f.mu.Lock()
	f.calls++
	n, hook := f.calls, f.before
	f.mu.Unlock()
	if hook != nil {
		if err := hook(n); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down || m.To == f.failFor {
		return errors.New("relay down")
	}
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeMailer) to() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, m := range f.sent {
		out = append(out, m.To)
	}
	slices.Sort(out)
	return out
}

type mailEnv struct {
	t      *testing.T
	db     *store.DB
	sys    context.Context
	mailer *fakeMailer
	clock  time.Time
	run    func()
	// runErr is run, returning the job's error; release gives up the lease; reacquire takes it again.
	runErr    func() error
	release   func()
	reacquire func()
}

func newMailEnv(t *testing.T) *mailEnv {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	e := &mailEnv{t: t, db: db, sys: storetest.SystemCtx(t), mailer: &fakeMailer{configured: true}, clock: time.Now().UTC().Truncate(time.Second)}
	leases := lease.New(db, "ctn_test", nil)
	job := controller.MailJob(controller.MailOptions{DB: db, Leases: leases, Mailer: e.mailer, PublicURL: "https://rpmgr.example.com/",
		Now: func() time.Time { return e.clock }, Logger: slog.New(slog.DiscardHandler)})
	held, ok, err := leases.TryAcquire(e.sys, "mail")
	if err != nil || !ok {
		t.Fatal("no lease", err)
	}
	e.runErr = func() error { return job.Run(context.WithoutCancel(e.sys), held) }
	e.run = func() {
		t.Helper()
		if err := e.runErr(); err != nil {
			t.Fatal(err)
		}
	}
	e.release = func() {
		if err := leases.Release(context.WithoutCancel(e.sys), held); err != nil {
			t.Error(err)
		}
	}
	e.reacquire = func() {
		var ok bool
		var err error
		if held, ok, err = leases.TryAcquire(e.sys, "mail"); err != nil || !ok {
			t.Fatal("no lease again", err)
		}
	}
	return e
}

// member adds a user with role to org; role "" makes a user of no org.
func (e *mailEnv) member(org, email, role string, instanceAdmin, disabled bool) {
	c := e.db.Client()
	cr := c.User.Create().SetEmail(email).SetDisplayName(email).SetInstanceAdmin(instanceAdmin)
	if disabled {
		cr.SetStatus("disabled")
	}
	u := cr.SaveX(e.sys)
	if role != "" {
		c.Membership.Create().SetOrgID(org).SetUserID(u.ID).SetRole(membershipRole(role)).SetCreatedBy("test").ExecX(e.sys)
	}
}

func (e *mailEnv) event(org, typ, summary string) events.Event {
	var ev events.Event
	err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		var err error
		ev, err = events.Add(e.sys, tx, events.Event{OrgID: org, Type: typ, SubjectType: "gateway", SubjectID: "gwy_1", SubjectName: "gw1", Summary: summary})
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return ev
}

func (e *mailEnv) orgSetting(org string, upd *rpmgrv1.OrgSettings, paths ...string) {
	if _, err := settings.UpdateOrg(storetest.OrgCtx(e.t, org), e.db, org, upd, &fieldmaskpb.FieldMask{Paths: paths}, 0); err != nil {
		e.t.Fatal(err)
	}
}

func (e *mailEnv) jobState(id string) mailjob.State {
	return e.db.Client().MailJob.Query().Where(mailjob.EventID(id)).OnlyX(e.sys).State
}

// TestMailJob_Recipients (#959): an org's alert is mailed once to its active Owners and Admins
// only, firing and resolved each once; the mail holds the envelope's facts and a link, and nothing
// of another org or an instance admin; another pass sends nothing again.
func TestMailJob_Recipients(t *testing.T) {
	e := newMailEnv(t)
	a, b := storetest.Org(t, e.db, "org-a"), storetest.Org(t, e.db, "org-b")
	e.member(a, "owner@a.example", "owner", false, false)
	e.member(a, "admin@a.example", "admin", false, false)
	e.member(a, "op@a.example", "operator", false, false)
	e.member(a, "viewer@a.example", "viewer", false, false)
	e.member(a, "gone@a.example", "admin", false, true)
	e.member(b, "owner@b.example", "owner", false, false)
	e.member("", "root@example.com", "", true, false)
	fire := e.event(a, "alert.fire", "agent_offline: Agent offline fires, gw1")
	e.run()
	e.run()
	if got, want := e.mailer.to(), []string{"admin@a.example", "owner@a.example"}; !slices.Equal(got, want) {
		t.Fatalf("mailed %v, want %v", got, want)
	}
	m := e.mailer.sent[0]
	if m.Subject != "[rpmgr] Agent offline firing" || !strings.Contains(m.Body, "agent_offline: Agent offline fires, gw1") ||
		!strings.Contains(m.Body, "https://rpmgr.example.com/") || strings.Contains(m.Body, "org-b") {
		t.Fatalf("mail %+v", m)
	}
	e.event(a, "alert.resolve", "agent_offline: Agent offline resolved, gw1")
	e.run()
	e.run()
	if n := len(e.mailer.sent); n != 4 {
		t.Fatalf("%d mails after firing and resolving, want 2 each", n)
	}
	if st := e.jobState(fire.ID); st != mailjob.StateSent {
		t.Fatalf("job %s", st)
	}
	if got := e.mailer.sent[3].Subject; got != "[rpmgr] Agent offline resolved" {
		t.Fatalf("subject %q", got)
	}
}

// TestMailJob_InstanceAndWebhookDisable (#959): an instance alert goes to the Instance Admins
// only; the e-mail of a webhook endpoint disabled for failing goes to the org's Owners and Admins
// even when alert e-mails are off, names the endpoint by ID and no URL.
func TestMailJob_InstanceAndWebhookDisable(t *testing.T) {
	e := newMailEnv(t)
	a := storetest.Org(t, e.db, "org-a")
	e.member(a, "owner@a.example", "owner", true, false)
	e.member("", "root@example.com", "", true, false)
	e.member("", "off@example.com", "", true, true)
	e.member("", "plain@example.com", "", false, false)
	e.event("", "alert.fire", "audit_checkpoints_behind: Audit checkpoints behind fires, audit checkpoints")
	e.run()
	if got, want := e.mailer.to(), []string{"owner@a.example", "root@example.com"}; !slices.Equal(got, want) {
		t.Fatalf("instance alert mailed %v, want the active Instance Admins %v", got, want)
	}
	e.orgSetting(a, &rpmgrv1.OrgSettings{AlertEmail: proto.Bool(false)}, "alert_email")
	e.mailer.sent = nil
	e.event(a, "webhook.disable", "webhook.disable: no successful delivery for 3 days")
	e.run()
	if got := e.mailer.to(); !slices.Equal(got, []string{"owner@a.example"}) {
		t.Fatalf("webhook.disable mailed %v", got)
	}
	m := e.mailer.sent[0]
	if m.Subject != "[rpmgr] Webhook endpoint disabled" || !strings.Contains(m.Body, "gwy_1") || strings.Contains(m.Body, "http://") {
		t.Fatalf("mail %+v", m)
	}
}

// TestMailJob_NotWanted (#959): without SMTP, with alert_email off, or without recipients no mail
// is sent and the job is skipped, not retried.
func TestMailJob_NotWanted(t *testing.T) {
	e := newMailEnv(t)
	a := storetest.Org(t, e.db, "org-a")
	e.member(a, "owner@a.example", "owner", false, false)
	e.mailer.configured = false
	noSMTP := e.event(a, "alert.fire", "clock_skew: Clock skew fires, gw1")
	e.run()
	e.mailer.configured = true
	e.orgSetting(a, &rpmgrv1.OrgSettings{AlertEmail: proto.Bool(false)}, "alert_email")
	off := e.event(a, "alert.fire", "clock_skew: Clock skew fires, gw2")
	e.run()
	b := storetest.Org(t, e.db, "org-b")
	e.orgSetting(b, &rpmgrv1.OrgSettings{AlertEmail: proto.Bool(true)}, "alert_email")
	none := e.event(b, "alert.fire", "clock_skew: Clock skew fires, gw3")
	e.run()
	e.clock = e.clock.Add(time.Hour)
	e.run()
	if len(e.mailer.sent) != 0 {
		t.Fatalf("sent %v", e.mailer.to())
	}
	for name, id := range map[string]string{"no SMTP": noSMTP.ID, "alert_email off": off.ID, "no recipients": none.ID} {
		if st := e.jobState(id); st != mailjob.StateSkipped {
			t.Errorf("%s: job %s, want skipped", name, st)
		}
	}
}

// TestMailJob_RetriesThenGivesUp (#959): a relay that is down is retried with a doubling delay and
// the mail is given up after MailGiveUp, with no mail sent; a recipient that failed is retried
// alone once the relay answers; the alert and its event are never touched.
func TestMailJob_RetriesThenGivesUp(t *testing.T) {
	e := newMailEnv(t)
	a := storetest.Org(t, e.db, "org-a")
	e.member(a, "owner@a.example", "owner", false, false)
	e.member(a, "admin@a.example", "admin", false, false)
	ev := e.event(a, "alert.fire", "clock_skew: Clock skew fires, gw1")
	e.mailer.down = true
	start := e.clock
	e.run()
	j := e.db.Client().MailJob.Query().OnlyX(e.sys)
	if j.State != mailjob.StatePending || j.Attempts != 1 || !j.NextAttemptAt.Equal(start.Add(controller.MailRetryFrom)) {
		t.Fatalf("after a failure: %+v", j)
	}
	e.clock = start.Add(30 * time.Second)
	e.run() // not due yet
	if j := e.db.Client().MailJob.Query().OnlyX(e.sys); j.Attempts != 1 {
		t.Fatalf("retried before it was due: %d attempts", j.Attempts)
	}
	e.clock = start.Add(time.Minute)
	e.run()
	if j := e.db.Client().MailJob.Query().OnlyX(e.sys); j.Attempts != 2 || !j.NextAttemptAt.Equal(e.clock.Add(2*controller.MailRetryFrom)) {
		t.Fatalf("second attempt: %+v", j)
	}
	// The relay answers for one of the two; the other still fails.
	e.mailer.down, e.mailer.failFor = false, "admin@a.example"
	e.clock = start.Add(10 * time.Minute)
	e.run()
	if got := e.mailer.to(); !slices.Equal(got, []string{"owner@a.example"}) {
		t.Fatalf("mailed %v", got)
	}
	e.mailer.failFor = ""
	e.clock = start.Add(time.Hour)
	e.run()
	if got := e.mailer.to(); !slices.Equal(got, []string{"admin@a.example", "owner@a.example"}) {
		t.Fatalf("after the retry %v: the first recipient got it twice or the second never", got)
	}
	if st := e.jobState(ev.ID); st != mailjob.StateSent {
		t.Fatalf("job %s", st)
	}

	// A second mail finds the relay down for good.
	e.mailer.sent, e.mailer.down = nil, true
	second := e.event(a, "alert.resolve", "clock_skew: Clock skew resolved, gw1")
	t0 := e.clock
	for d := time.Duration(0); d < controller.MailGiveUp+time.Hour; d += 30 * time.Minute {
		e.clock = t0.Add(d)
		e.run()
	}
	if st := e.jobState(second.ID); st != mailjob.StateGivenUp || len(e.mailer.sent) != 0 {
		t.Fatalf("job %s, %d mails; want given up with none sent", st, len(e.mailer.sent))
	}
}

// TestMailJob_AlertTypesChoosesMails (#959, D139, D142): alert_types selects which alerts are
// mailed, never which are events: an alert of an unchosen kind is not mailed, its resolving is not
// mailed either (also once the kind is chosen later), a change of alert_types between firing and
// resolving applies to the resolving's mail, and an instance alert ignores the setting.
func TestMailJob_AlertTypesChoosesMails(t *testing.T) {
	e := newMailEnv(t)
	a := storetest.Org(t, e.db, "org-a")
	e.member(a, "owner@a.example", "owner", false, false)
	e.member("", "root@x.example", "", true, false)
	e.orgSetting(a, &rpmgrv1.OrgSettings{AlertTypes: []string{"clock_skew"}}, "alert_types")
	fireOther := e.event(a, "alert.fire", "agent_offline: Agent offline fires, gw1")
	fireSkew := e.event(a, "alert.fire", "clock_skew: Clock skew fires, gw1")
	inst := e.event("", "alert.fire", "audit_checkpoints_behind: Audit checkpoints behind fires, audit")
	e.run()
	if got := e.mailer.to(); !slices.Equal(got, []string{"owner@a.example", "root@x.example"}) {
		t.Fatalf("mailed %v, want the chosen kind and the instance alert", got)
	}
	if st := e.jobState(fireOther.ID); st != mailjob.StateSkipped {
		t.Fatalf("unchosen firing: job %s", st)
	}
	if st := e.jobState(inst.ID); st != mailjob.StateSent {
		t.Fatalf("instance alert: job %s", st)
	}
	if st := e.jobState(fireSkew.ID); st != mailjob.StateSent {
		t.Fatalf("chosen firing: job %s", st)
	}
	if n := e.db.Client().Event.Query().CountX(e.sys); n != 3 {
		t.Fatalf("%d events, want all 3 kept whatever alert_types says", n)
	}

	// alert_types changes between the firing and the resolving: the resolving follows the new
	// setting, so the clock-skew resolving is not mailed.
	e.mailer.sent = nil
	e.orgSetting(a, &rpmgrv1.OrgSettings{AlertTypes: []string{"agent_offline"}}, "alert_types")
	e.clock = e.clock.Add(time.Minute)
	resSkew := e.event(a, "alert.resolve", "clock_skew: Clock skew resolved, gw1")
	e.run()
	if st := e.jobState(resSkew.ID); st != mailjob.StateSkipped || len(e.mailer.sent) != 0 {
		t.Fatalf("resolving of a kind no longer chosen: job %s, %d mails", st, len(e.mailer.sent))
	}

	// No orphan resolving: the firing of agent_offline was not mailed, so its resolving is not,
	// even though the kind is chosen when it resolves.
	e.clock = e.clock.Add(time.Minute)
	resOther := e.event(a, "alert.resolve", "agent_offline: Agent offline resolved, gw1")
	e.run()
	if st := e.jobState(resOther.ID); st != mailjob.StateSkipped || len(e.mailer.sent) != 0 {
		t.Fatalf("orphan resolving: job %s, %d mails", st, len(e.mailer.sent))
	}

	// A firing that was mailed is followed by its resolving.
	e.orgSetting(a, &rpmgrv1.OrgSettings{AlertTypes: nil}, "alert_types")
	fire := e.event(a, "alert.fire", "route_no_ready_connector: Route has no ready connector fires, r1")
	e.run()
	res := e.event(a, "alert.resolve", "route_no_ready_connector: Route has no ready connector resolved, r1")
	e.run()
	if st := e.jobState(res.ID); st != mailjob.StateSent || e.jobState(fire.ID) != mailjob.StateSent || len(e.mailer.sent) != 2 {
		t.Fatalf("resolving after a mailed firing: job %s, %d mails", st, len(e.mailer.sent))
	}
}

// TestMailJob_MoreThanOnePassOfEvents (#959): when more events than one pass reads already have a
// mail job, a newer event still gets its job and is not starved by the older ones.
func TestMailJob_MoreThanOnePassOfEvents(t *testing.T) {
	e := newMailEnv(t)
	a := storetest.Org(t, e.db, "org-a")
	e.mailer.configured = false // jobs are made and skipped quickly; nobody is mailed
	for i := range 600 {
		e.event(a, "alert.fire", fmt.Sprintf("clock_skew: Clock skew fires, gw%d", i))
	}
	e.run()
	if n := e.db.Client().MailJob.Query().CountX(e.sys); n != 500 {
		t.Fatalf("%d jobs after the first pass, want 500", n)
	}
	e.run()
	if n := e.db.Client().MailJob.Query().CountX(e.sys); n != 600 {
		t.Fatalf("%d jobs after the second pass, want 600", n)
	}
	newest := e.event(a, "alert.fire", "clock_skew: Clock skew fires, newest")
	e.run()
	if !e.db.Client().MailJob.Query().Where(mailjob.EventID(newest.ID)).ExistX(e.sys) {
		t.Fatal("the newest event has no job: the older ones starved it")
	}
}

// TestMailJob_LeaseLostDoesNotResend (#959): what was sent is recorded at once, and a replica that
// lost the lease sends nothing more, as it checks before each send; the next holder sends only to who has not got the mail.
func TestMailJob_LeaseLostDoesNotResend(t *testing.T) {
	e := newMailEnv(t)
	a := storetest.Org(t, e.db, "org-a")
	e.member(a, "owner@a.example", "owner", false, false)
	e.member(a, "admin@a.example", "admin", false, false)
	e.member(a, "zed@a.example", "admin", false, false)
	ev := e.event(a, "alert.fire", "clock_skew: Clock skew fires, gw1")
	// The lease is lost while the third send is under way, and that send fails: the two before it
	// are recorded.
	e.mailer.before = func(n int) error {
		if n == 3 {
			e.release()
			return errors.New("relay down")
		}
		return nil
	}
	if err := e.runErr(); err == nil {
		t.Fatal("a pass that lost its lease reported success")
	}
	if len(e.mailer.sent) != 2 {
		t.Fatalf("%d mails sent, want 2", len(e.mailer.sent))
	}
	if j := e.db.Client().MailJob.Query().OnlyX(e.sys); len(j.Done) != 2 || j.State != mailjob.StatePending {
		t.Fatalf("job %+v, want the first two mails recorded and the job pending", j)
	}
	e.mailer.before = nil
	e.reacquire()
	e.run()
	got := e.mailer.to()
	if len(got) != 3 || got[0] != "admin@a.example" || got[1] != "owner@a.example" || got[2] != "zed@a.example" {
		t.Fatalf("mailed %v", got)
	}
	count := map[string]int{}
	for _, m := range e.mailer.sent {
		count[m.To]++
	}
	if count["admin@a.example"] != 1 || count["owner@a.example"] != 1 || count["zed@a.example"] != 1 {
		t.Fatalf("mails per recipient %v, want 1 each", count)
	}
	if st := e.jobState(ev.ID); st != mailjob.StateSent {
		t.Fatalf("job %s", st)
	}
}

func membershipRole(r string) membership.Role { return membership.Role(r) }
