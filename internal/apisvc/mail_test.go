// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/mail"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func testSealer(t *testing.T) *secret.Sealer {
	t.Helper()
	k, err := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := secret.NewSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// outbox is a Mailer that keeps what it sends.
type outbox struct {
	configured bool
	fail       error

	mu   sync.Mutex
	sent []mail.Message
}

func (o *outbox) Configured(context.Context) (bool, error) { return o.configured, nil }

func (o *outbox) Send(_ context.Context, m mail.Message) error {
	if o.fail != nil {
		return o.fail
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sent = append(o.sent, m)
	return nil
}

func (o *outbox) messages() []mail.Message {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]mail.Message(nil), o.sent...)
}

// TestRequestPasswordReset: without a relay the request is UNAVAILABLE; with one, the answer is the
// same for a known and an unknown address and only the known one gets a link, which works; a relay
// that fails changes nothing in the answer; an address gets three links at once.
func TestRequestPasswordReset(t *testing.T) {
	e := newEnv(t)
	box := &outbox{}
	e.auth.Mail = box
	done := make(chan error, 1)
	apisvc.SetSent(e.auth, func(err error) { done <- err })
	b := e.browser()
	request := func(addr string) error {
		_, err := b.auth.RequestPasswordReset(context.Background(), connect.NewRequest(&rpmgrv1.RequestPasswordResetRequest{Email: addr}))
		return err
	}
	wait := func() error {
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("the background e-mail never finished")
			return nil
		}
	}
	if err := request("ada@example.com"); code(err) != connect.CodeUnavailable {
		t.Fatalf("without a relay: %v", err)
	}
	box.configured = true
	if err := request("nobody@example.com"); err != nil {
		t.Fatalf("an unknown address: %v", err)
	}
	if err := wait(); err == nil || len(box.messages()) != 0 {
		t.Fatalf("an unknown address got mail: %v", box.messages())
	}
	if err := request("ADA@example.com"); err != nil {
		t.Fatalf("a known address: %v", err)
	}
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	got := box.messages()
	if len(got) != 1 || got[0].To != "ada@example.com" || !strings.Contains(got[0].Body, "https://panel.example.com/reset#rpmgr_prs_") {
		t.Fatalf("the reset mail: %+v", got)
	}
	tok := got[0].Body[strings.Index(got[0].Body, "rpmgr_prs_"):]
	tok = tok[:strings.IndexAny(tok, "\n ")]
	if _, err := b.auth.CompletePasswordReset(context.Background(), connect.NewRequest(&rpmgrv1.CompletePasswordResetRequest{
		Token: tok, NewPassword: "an entirely new passphrase"})); err != nil {
		t.Fatalf("the mailed link: %v", err)
	}
	box.fail = errors.New("the relay is down")
	if err := request("ada@example.com"); err != nil {
		t.Fatalf("a failing relay changed the answer: %v", err)
	}
	if err := wait(); err == nil {
		t.Fatal("the relay's failure was not seen")
	}
	if err := request("ada@example.com"); err != nil {
		t.Fatalf("a third request for one address: %v", err)
	}
	_ = wait()
	if err := request("ada@example.com"); code(err) != connect.CodeResourceExhausted {
		t.Fatalf("a fourth request for one address: %v", err)
	}
	if err := request("not an address"); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a malformed address: %v", err)
	}
}

// TestInvitationMail: with a relay the invitee gets the link; a relay that fails or none leaves
// the link in the answer, marked as not e-mailed.
func TestInvitationMail(t *testing.T) {
	e := newEnv(t)
	box := &outbox{configured: true}
	e.orgs.Mail = box
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	s, _ := ada.session()
	org := s.GetMemberships()[0].GetOrgId()
	invite := func(email string) *rpmgrv1.CreateInvitationResponse {
		t.Helper()
		r, err := ada.org.CreateInvitation(context.Background(), connect.NewRequest(&rpmgrv1.CreateInvitationRequest{OrgId: org,
			Email: email, Role: "viewer"}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg
	}
	r := invite("Op@Example.com")
	got := box.messages()
	if !r.GetEmailSent() || len(got) != 1 || got[0].To != "op@example.com" || !strings.Contains(got[0].Body, r.GetUrl()) ||
		!strings.Contains(got[0].Subject, "Default") {
		t.Fatalf("the invitation mail: %v %+v", r, got)
	}
	box.fail = errors.New("the relay is down")
	if r := invite("two@example.com"); r.GetEmailSent() || r.GetUrl() == "" {
		t.Fatalf("a failing relay: %v", r)
	}
	box.configured, box.fail = false, nil
	if r := invite("three@example.com"); r.GetEmailSent() || len(box.messages()) != 1 {
		t.Fatalf("no relay: %v", r)
	}
}

// TestRelay: the relay of the instance settings counts once it has a server, and a send goes to
// that server.
func TestRelay(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	r := &apisvc.Relay{DB: db, Sys: sys, Sealer: testSealer(t)}
	if ok, err := r.Configured(context.Background()); err != nil || ok {
		t.Fatalf("no relay: %v %v", ok, err)
	}
	smtp := &rpmgrv1.SmtpSettings{Server: "127.0.0.1:1", From: "rpmgr@example.com", Security: rpmgrv1.SmtpSecurity_SMTP_SECURITY_TLS}
	if _, err := settings.UpdateInstance(sys, db, &rpmgrv1.InstanceSettings{Smtp: smtp}, &fieldmaskpb.FieldMask{Paths: []string{"smtp"}}, 0); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.Configured(context.Background()); err != nil || !ok {
		t.Fatalf("a relay: %v %v", ok, err)
	}
	if err := r.Send(context.Background(), mail.Message{To: "ada@example.com", Subject: "x", Body: "x"}); err == nil ||
		!strings.Contains(err.Error(), "cannot reach the relay") {
		t.Fatalf("a send to a closed port: %v", err)
	}
}
