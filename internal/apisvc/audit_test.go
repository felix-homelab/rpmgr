// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/totp"
)

// TestAudit_OncePerChange (docs/04-security.md, "Audit log"): a change a service records itself
// gets one entry, the service's, with the request's IP, user agent, session and request ID, which
// the response returns; a change no service records gets the request's own entry, also once.
func TestAudit_OncePerChange(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	s, _ := ada.session()
	org := s.GetMemberships()[0].GetOrgId()
	entries := func(action string) []*ent.AuditEntry {
		return e.db.Client().AuditEntry.Query().Where(auditentry.Action(action)).AllX(e.sys)
	}
	once := func(action, requestID string) *ent.AuditEntry {
		t.Helper()
		got := entries(action)
		if len(got) != 1 {
			t.Fatalf("%d entries %s, want 1", len(got), action)
		}
		a := got[0]
		if a.RequestID != requestID || !strings.HasPrefix(requestID, "req_") || a.IP == "" || a.ActorID != e.ada || a.CredentialID == "" ||
			a.AuthMethod == "" {
			t.Fatalf("entry %s: %+v, want request %s, an IP, the actor and the session", action, a, requestID)
		}
		return a
	}

	created, err := ada.token.CreateAPIToken(ctx, connect.NewRequest(&rpmgrv1.CreateAPITokenRequest{OrgId: org, Name: "ci", Scopes: []string{"org.read"}}))
	if err != nil {
		t.Fatal(err)
	}
	once("token.create", created.Header().Get(api.RequestIDHeader))
	revoked, err := ada.token.RevokeAPIToken(ctx, connect.NewRequest(&rpmgrv1.RevokeAPITokenRequest{OrgId: org, TokenId: created.Msg.GetApiToken().GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	once("token.revoke", revoked.Header().Get(api.RequestIDHeader))

	enrolled, err := ada.user.EnrollTOTP(ctx, connect.NewRequest(&rpmgrv1.EnrollTOTPRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	once("rpmgr.v1.UserService.EnrollTOTP", enrolled.Header().Get(api.RequestIDHeader))
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrolled.Msg.GetSecret())
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := ada.user.ConfirmTOTP(ctx, connect.NewRequest(&rpmgrv1.ConfirmTOTPRequest{Code: totp.Code(seed, totp.StepOf(e.clock))}))
	if err != nil {
		t.Fatal(err)
	}
	once("user.mfa_enroll", confirmed.Header().Get(api.RequestIDHeader))

	for _, generic := range []string{"rpmgr.v1.TokenService.CreateAPIToken", "rpmgr.v1.TokenService.RevokeAPIToken", "rpmgr.v1.UserService.ConfirmTOTP"} {
		if n := len(entries(generic)); n != 0 {
			t.Errorf("%d entries %s besides the service's", n, generic)
		}
	}

	// A refused request gets its entry and its request ID too.
	_, err = ada.token.RevokeAPIToken(ctx, connect.NewRequest(&rpmgrv1.RevokeAPITokenRequest{OrgId: org, TokenId: "atk_nothing"}))
	var cerr *connect.Error
	if !errors.As(err, &cerr) || code(err) != connect.CodeNotFound {
		t.Fatalf("revoking a missing token: %v", err)
	}
	refused := entries("rpmgr.v1.TokenService.RevokeAPIToken")
	if len(refused) != 1 || string(refused[0].Result) != "denied" || refused[0].RequestID != cerr.Meta().Get(api.RequestIDHeader) {
		t.Fatalf("the refused request: %+v, header %q", refused, cerr.Meta().Get(api.RequestIDHeader))
	}
}

// TestAudit_Logins (docs/04-security.md, "Audit log"): a login is recorded once with the user who
// signed in, the session they got and the factors they used; a failed login is recorded in the
// instance chain alike for an unknown address and a wrong password, without the password, so the
// log tells no more than the answer; a step-up names its factor, a failed one its user; a logout
// names the session it ends.
func TestAudit_Logins(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	logins := func() []*ent.AuditEntry {
		return e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.AuthService.Login")).Order(ent.Asc(auditentry.FieldTs)).AllX(e.sys)
	}

	ada := e.browser()
	in, err := ada.auth.Login(ctx, connect.NewRequest(&rpmgrv1.LoginRequest{Email: "ada@example.com", Password: pw}))
	if err != nil {
		t.Fatal(err)
	}
	got := logins()
	if len(got) != 1 || got[0].ActorID != e.ada || got[0].TargetType != "user" || got[0].TargetID != e.ada || got[0].AuthMethod != "pwd" ||
		got[0].CredentialID != in.Msg.GetSession().GetId() || got[0].CredentialID == "" || string(got[0].Result) != "success" ||
		got[0].OrgID != nil || got[0].RequestID != in.Header().Get(api.RequestIDHeader) {
		t.Fatalf("a login: %+v", got)
	}

	for _, try := range []struct{ email, password string }{{"nobody@example.com", "a guessed password"}, {"ada@example.com", "a guessed password"}} {
		if err := e.browser().login(try.email, try.password); code(err) != connect.CodeUnauthenticated {
			t.Fatalf("a failed login as %s: %v", try.email, err)
		}
	}
	got = logins()
	if len(got) != 3 {
		t.Fatalf("%d login entries, want 3", len(got))
	}
	unknown, wrong := got[1], got[2]
	for _, f := range []*ent.AuditEntry{unknown, wrong} {
		if string(f.ActorType) != "anonymous" || f.ActorID != "" || f.TargetID != "" || f.CredentialID != "" || string(f.Result) != "denied" ||
			f.OrgID != nil || strings.Contains(f.Diff, "guessed") {
			t.Fatalf("a failed login: %+v", f)
		}
	}
	if unknown.Reason != wrong.Reason || unknown.AuthMethod != wrong.AuthMethod || !strings.Contains(unknown.Diff, "nobody@example.com") {
		t.Fatalf("an unknown address and a wrong password differ: %+v %+v", unknown, wrong)
	}

	// Once the address's limit refuses logins, the refusals are not recorded one by one.
	tried := 2
	for i := 0; ; i++ {
		err := e.browser().login(fmt.Sprintf("guess%d@example.com", i), "a guessed password")
		if code(err) == connect.CodeResourceExhausted {
			break
		}
		if i > 100 {
			t.Fatal("no rate limit")
		}
		tried++
	}
	for range 5 {
		if err := e.browser().login("guess@example.com", "a guessed password"); code(err) != connect.CodeResourceExhausted {
			t.Fatalf("after the limit: %v", err)
		}
	}
	if n := len(logins()); n != 1+tried {
		t.Fatalf("%d login entries after %d failed logins and the limit's refusals, want %d", n, tried, 1+tried)
	}

	stepUps := func() []*ent.AuditEntry {
		return e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.AuthService.StepUp")).Order(ent.Asc(auditentry.FieldTs)).AllX(e.sys)
	}
	if err := ada.stepUp("a guessed password", ""); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("a failed step-up: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if su := stepUps(); len(su) != 2 || su[0].ActorID != e.ada || string(su[0].Result) != "denied" || su[1].ActorID != e.ada ||
		string(su[1].Result) != "success" || su[1].Reason != "step-up with pwd" {
		t.Fatalf("step-ups: %+v", su)
	}

	s, _ := ada.session()
	if _, err := ada.auth.Logout(ctx, connect.NewRequest(&rpmgrv1.LogoutRequest{})); err != nil {
		t.Fatal(err)
	}
	out := e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.AuthService.Logout")).AllX(e.sys)
	if len(out) != 1 || out[0].ActorID != e.ada || out[0].CredentialID != s.GetSession().GetId() || string(out[0].Result) != "success" {
		t.Fatalf("a logout: %+v", out)
	}
}

// TestAuditService (docs/07-api.md, "Services"; docs/04-security.md, "Audit log"): an org's
// Owners and Admins page through its chain, newest first, filter it and verify it with its
// checkpoints; a tampered entry shows as where the chain broke; Viewers read nothing; the
// instance chain is the Instance Admin's alone.
func TestAuditService(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		return pki.InitCA(e.sys, tx, e.sealer, "rpmgr-teststor", e.clock.Add(-time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadCA(e.sys, e.db, e.sealer, func() time.Time { return e.clock })
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"audit-eu", "audit-us"} {
		if _, err := ada.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org,
			GatewayGroup: &rpmgrv1.GatewayGroup{Name: name}})); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		_, err := audit.WriteCheckpoints(e.sys, tx, ca.AuditSigner(), time.Now(), audit.Pending)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	var seqs []int64
	for page := ""; ; {
		r, err := ada.aud.ListAuditEntries(ctx, connect.NewRequest(&rpmgrv1.ListAuditEntriesRequest{OrgId: org, PageSize: 2, PageToken: page}))
		if err != nil {
			t.Fatal(err)
		}
		for _, en := range r.Msg.GetEntries() {
			seqs = append(seqs, en.GetSeq())
		}
		if page = r.Msg.GetNextPageToken(); page == "" {
			break
		}
	}
	if len(seqs) < 3 || seqs[len(seqs)-1] != 1 || !slices.IsSortedFunc(seqs, func(a, b int64) int { return int(b - a) }) {
		t.Fatalf("the org's entries by page: %v", seqs)
	}
	groups, err := ada.aud.ListAuditEntries(ctx, connect.NewRequest(&rpmgrv1.ListAuditEntriesRequest{OrgId: org,
		Action: "rpmgr.v1.GatewayService.CreateGatewayGroup", ActorId: e.ada}))
	if err != nil || len(groups.Msg.GetEntries()) < 2 || groups.Msg.GetEntries()[0].GetIp() == "" {
		t.Fatalf("filtered: %v %v", groups, err)
	}
	if _, err := ada.aud.ListAuditEntries(ctx, connect.NewRequest(&rpmgrv1.ListAuditEntriesRequest{OrgId: org, PageToken: "forged"})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a forged page token: %v", err)
	}

	v, err := ada.aud.VerifyAuditChain(ctx, connect.NewRequest(&rpmgrv1.VerifyAuditChainRequest{OrgId: org}))
	if got := v.Msg.GetVerification(); err != nil || !got.GetIntact() || got.GetHeadSeq() < seqs[0] || got.GetLastCheckpoint().GetSeq() == 0 ||
		got.GetLastCheckpoint().GetKeyId() != pki.KeyID(ca.AuditSigner().Cert) {
		t.Fatalf("verify: %v %v", v, err)
	}
	if iv, err := ada.aud.VerifyInstanceAuditChain(ctx, connect.NewRequest(&rpmgrv1.VerifyInstanceAuditChainRequest{})); err != nil ||
		!iv.Msg.GetVerification().GetIntact() {
		t.Fatalf("verify the instance chain: %v %v", iv, err)
	}
	if il, err := ada.aud.ListInstanceAuditEntries(ctx, connect.NewRequest(&rpmgrv1.ListInstanceAuditEntriesRequest{})); err != nil ||
		len(il.Msg.GetEntries()) == 0 {
		t.Fatalf("the instance chain's entries: %v %v", il, err)
	}

	if _, err := e.db.Writer.ExecContext(ctx, "UPDATE audit_log SET ip = '198.51.100.9' WHERE org_id = $1 AND seq = 2", org); err != nil {
		t.Fatal(err)
	}
	v, err = ada.aud.VerifyAuditChain(ctx, connect.NewRequest(&rpmgrv1.VerifyAuditChainRequest{OrgId: org}))
	if got := v.Msg.GetVerification(); err != nil || got.GetIntact() || got.GetBrokenAt() != 2 || got.GetProblem() == "" {
		t.Fatalf("verify a tampered chain: %v %v", v, err)
	}

	if err := ada.stepUp(pw, ""); err != nil { // inviting an Admin
		t.Fatal(err)
	}
	adm, _ := e.join(t, ada, org, "adm@example.com", "admin")
	if _, err := adm.aud.ListAuditEntries(ctx, connect.NewRequest(&rpmgrv1.ListAuditEntriesRequest{OrgId: org})); err != nil {
		t.Fatalf("an Admin reads the org's chain: %v", err)
	}
	if _, err := adm.aud.ListInstanceAuditEntries(ctx, connect.NewRequest(&rpmgrv1.ListInstanceAuditEntriesRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Admin reads the instance chain: %v", err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := vwr.aud.ListAuditEntries(ctx, connect.NewRequest(&rpmgrv1.ListAuditEntriesRequest{OrgId: org})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer reads the org's chain: %v", err)
	}
	if _, err := vwr.aud.VerifyAuditChain(ctx, connect.NewRequest(&rpmgrv1.VerifyAuditChainRequest{OrgId: org})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer verifies the org's chain: %v", err)
	}
}
