// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"encoding/base32"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
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
