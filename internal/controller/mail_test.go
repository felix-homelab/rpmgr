// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
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
}

func (f *fakeMailer) Configured(context.Context) (bool, error) { return f.configured, nil }

func (f *fakeMailer) Send(_ context.Context, m mail.Message) error {
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
	e.run = func() {
		t.Helper()
		if err := job.Run(context.WithoutCancel(e.sys), held); err != nil {
			t.Fatal(err)
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

func membershipRole(r string) membership.Role { return membership.Role(r) }
