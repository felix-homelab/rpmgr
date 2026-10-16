// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"encoding/base32"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/totp"
)

func reason(err error) string {
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		return ""
	}
	for _, d := range cerr.Details() {
		if v, derr := d.Value(); derr == nil {
			if ei, ok := v.(*errdetails.ErrorInfo); ok {
				return ei.GetReason()
			}
		}
	}
	return ""
}

func (b *browser) stepUp(password, second string) error {
	_, err := b.auth.StepUp(context.Background(), connect.NewRequest(&rpmgrv1.StepUpRequest{Password: password, SecondFactor: second}))
	return err
}

func (b *browser) loginWith(email, password, second string) error {
	_, err := b.auth.Login(context.Background(), connect.NewRequest(&rpmgrv1.LoginRequest{Email: email, Password: password,
		SecondFactor: second}))
	return err
}

// TestAuth_MFA: setting up an authenticator needs a step-up, with the password while there is none;
// confirming it ends the user's other sessions and returns recovery codes; from then on a login
// needs a second factor (MFA_REQUIRED, which counts no failure) and a step-up needs one too; a
// recovery code works once; the step-up lasts 10 minutes to the second and rotates the cookie.
func TestAuth_MFA(t *testing.T) {
	e := newEnv(t)
	b, other := e.browser(), e.browser()
	if err := b.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	if err := other.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := b.user.EnrollTOTP(ctx, connect.NewRequest(&rpmgrv1.EnrollTOTPRequest{})); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("enroll without a step-up: %v", err)
	}
	if err := b.stepUp("wrong password", ""); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("a step-up with a wrong password: %v", err)
	}
	before := b.cookie
	if err := b.stepUp(pw, ""); err != nil || b.cookie == before {
		t.Fatalf("a step-up with the password: %v (cookie rotated: %v)", err, b.cookie != before)
	}
	enrolled, err := b.user.EnrollTOTP(ctx, connect.NewRequest(&rpmgrv1.EnrollTOTPRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrolled.Msg.GetSecret())
	if err != nil {
		t.Fatal(err)
	}
	code6 := func() string { return totp.Code(seed, totp.StepOf(e.clock)) }
	if _, err := b.user.ConfirmTOTP(ctx, connect.NewRequest(&rpmgrv1.ConfirmTOTPRequest{Code: "000000"})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a wrong first code: %v", err)
	}
	confirmed, err := b.user.ConfirmTOTP(ctx, connect.NewRequest(&rpmgrv1.ConfirmTOTPRequest{Code: code6()}))
	if err != nil || len(confirmed.Msg.GetRecoveryCodes()) != 10 {
		t.Fatalf("confirm: %v %v", confirmed, err)
	}
	if _, err := other.session(); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("the other session after MFA was set up: %v", err)
	}

	// Signing in now takes a second factor; asking for it is no failure.
	fresh := e.browser()
	for range 6 {
		if err := fresh.login("ada@example.com", pw); reason(err) != api.ReasonMFARequired {
			t.Fatalf("a login without a second factor: %v", err)
		}
	}
	e.clock = e.clock.Add(totp.Step)
	if err := fresh.loginWith("ada@example.com", pw, "000000"); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("a wrong second factor: %v", err)
	}
	if err := fresh.loginWith("ada@example.com", pw, code6()); err != nil {
		t.Fatalf("a login with a code: %v", err)
	}
	recovery := confirmed.Msg.GetRecoveryCodes()[0]
	if err := e.browser().loginWith("ada@example.com", pw, recovery); err != nil {
		t.Fatalf("a login with a recovery code: %v", err)
	}
	if err := e.browser().loginWith("ada@example.com", pw, recovery); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("a recovery code twice: %v", err)
	}

	// A step-up now needs the second factor, and lasts 10 minutes to the second.
	if err := fresh.stepUp(pw, ""); reason(err) != api.ReasonMFARequired {
		t.Fatalf("a step-up with the password only: %v", err)
	}
	e.clock = e.clock.Add(totp.Step)
	if err := fresh.stepUp("", code6()); err != nil {
		t.Fatalf("a step-up with a code: %v", err)
	}
	regenerate := func() error {
		_, err := fresh.user.RegenerateRecoveryCodes(ctx, connect.NewRequest(&rpmgrv1.RegenerateRecoveryCodesRequest{}))
		return err
	}
	e.clock = e.clock.Add(api.StepUpWindow)
	if err := regenerate(); err != nil {
		t.Fatalf("at the end of the step-up: %v", err)
	}
	e.clock = e.clock.Add(time.Second)
	if err := regenerate(); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("a second after the step-up: %v", err)
	}
}

// TestUser_RecoveryCodesEndSessions (D96): new recovery codes end the user's other sessions, each
// in the revocation log before the superseded codes, and the audit entry, the service's own, says
// how many; the session that made them stays signed in, and so do the user's personal API token
// and another user's sessions. A request that fails ends no session; with no other session the
// entry says none ended.
func TestUser_RecoveryCodesEndSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	s, err := ada.session()
	if err != nil {
		t.Fatal(err)
	}
	org, current := s.GetMemberships()[0].GetOrgId(), s.GetSession().GetId()
	bob, bobID := e.join(t, ada, org, "bob@example.com", "viewer")
	bobOther := e.browser()
	if err := bobOther.login("bob@example.com", pw); err != nil {
		t.Fatal(err)
	}
	regenerate := func(b *browser) ([]string, error) {
		r, err := b.user.RegenerateRecoveryCodes(ctx, connect.NewRequest(&rpmgrv1.RegenerateRecoveryCodesRequest{}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetRecoveryCodes(), nil
	}

	// Without an authenticator the request fails, and the user's other session stays.
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := regenerate(bob); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("new recovery codes without an authenticator: %v", err)
	}
	if _, err := bobOther.session(); err != nil {
		t.Fatalf("a failed request ended a session: %v", err)
	}

	// Ada sets up an authenticator, signs in twice more with recovery codes and makes a token.
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	enrolled, err := ada.user.EnrollTOTP(ctx, connect.NewRequest(&rpmgrv1.EnrollTOTPRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrolled.Msg.GetSecret())
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := ada.user.ConfirmTOTP(ctx, connect.NewRequest(&rpmgrv1.ConfirmTOTPRequest{Code: totp.Code(seed, totp.StepOf(e.clock))}))
	if err != nil {
		t.Fatal(err)
	}
	old := confirmed.Msg.GetRecoveryCodes()
	e.clock = e.clock.Add(totp.Step)
	if err := ada.stepUp("", totp.Code(seed, totp.StepOf(e.clock))); err != nil {
		t.Fatal(err)
	}
	others := []*browser{e.browser(), e.browser()}
	for i, b := range others {
		if err := b.loginWith("ada@example.com", pw, old[i]); err != nil {
			t.Fatal(err)
		}
	}
	tok, err := ada.token.CreateAPIToken(ctx, connect.NewRequest(&rpmgrv1.CreateAPITokenRequest{OrgId: org, Name: "cli",
		Scopes: []string{"org.read"}}))
	if err != nil {
		t.Fatal(err)
	}
	cli := e.browser()
	cli.bearer = tok.Msg.GetToken()
	before, err := revlog.Read(e.log)
	if err != nil {
		t.Fatal(err)
	}

	fresh, err := regenerate(ada)
	if err != nil || len(fresh) != 10 {
		t.Fatalf("new recovery codes: %v %v", fresh, err)
	}
	if _, err := ada.session(); err != nil {
		t.Fatalf("the session that made the codes: %v", err)
	}
	for i, b := range others {
		if _, err := b.session(); code(err) != connect.CodeUnauthenticated {
			t.Errorf("Ada's other session %d after new recovery codes: %v", i, err)
		}
	}
	for _, b := range []*browser{bob, bobOther} {
		if _, err := b.session(); err != nil {
			t.Errorf("Bob's session after Ada's new recovery codes: %v", err)
		}
	}
	if _, err := cli.org.GetOrg(ctx, connect.NewRequest(&rpmgrv1.GetOrgRequest{OrgId: org})); err != nil {
		t.Errorf("Ada's API token after new recovery codes: %v", err)
	}
	if err := e.browser().loginWith("ada@example.com", pw, old[2]); code(err) != connect.CodeUnauthenticated {
		t.Errorf("an old recovery code: %v", err)
	}

	after, err := revlog.Read(e.log)
	if err != nil {
		t.Fatal(err)
	}
	added := after[len(before):]
	if len(added) != 3 {
		t.Fatalf("revocation log entries: %+v", added)
	}
	for _, en := range added[:2] {
		if en.Kind != revlog.SessionRevoked || en.Subject == current || en.Detail != "recovery codes replaced" || en.Actor != e.ada {
			t.Errorf("a session's entry: %+v", en)
		}
	}
	if en := added[2]; en.Kind != revlog.CredentialSuperseded || en.Subject != e.ada || en.Detail != revlog.RecoveryCodes {
		t.Errorf("the codes' entry: %+v", en)
	}

	audited := func() []*ent.AuditEntry {
		return e.db.Client().AuditEntry.Query().Where(auditentry.Action("user.recovery_codes")).Order(ent.Asc(auditentry.FieldSeq)).
			AllX(e.sys)
	}
	if got := audited(); len(got) != 1 || got[0].Reason != "recovery codes replaced; 2 other sessions ended" ||
		got[0].ActorID != e.ada || got[0].CredentialID != current || got[0].Result != auditentry.ResultSuccess {
		t.Fatalf("the audit entry: %+v", got)
	}
	// The request's own entry is only Bob's refusal: the service recorded Ada's change.
	own := e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.UserService.RegenerateRecoveryCodes")).AllX(e.sys)
	if len(own) != 1 || own[0].ActorID != bobID || own[0].Result == auditentry.ResultSuccess {
		t.Fatalf("the requests' own entries: %+v", own)
	}

	// Again, with no other session left.
	if _, err := regenerate(ada); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.session(); err != nil {
		t.Fatalf("the session after new codes again: %v", err)
	}
	if got := audited(); len(got) != 2 || got[1].Reason != "recovery codes replaced; 0 other sessions ended" {
		t.Fatalf("the second audit entry: %+v", got)
	}
}

// TestStepUpActions: every method that makes one of the changes for which docs/04-security.md
// asks a step-up is annotated with it. A new such method joins this list.
func TestStepUpActions(t *testing.T) {
	for _, name := range []string{
		"rpmgr.v1.UserService.EnrollTOTP", "rpmgr.v1.UserService.ConfirmTOTP", "rpmgr.v1.UserService.RemoveTOTP",
		"rpmgr.v1.UserService.RegenerateRecoveryCodes", "rpmgr.v1.TokenService.CreateAPIToken",
		"rpmgr.v1.EnrollmentService.CreateEnrollmentToken", "rpmgr.v1.EnrollmentService.CreateGatewayEnrollmentToken",
		"rpmgr.v1.PkiService.RotateIntermediate",
	} {
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		md, ok := d.(protoreflect.MethodDescriptor)
		if !ok {
			t.Errorf("%s is not a method", name)
			continue
		}
		a, _ := proto.GetExtension(md.Options(), rpmgrv1.E_Authz).(*rpmgrv1.Authz)
		if !a.GetStepUp() {
			t.Errorf("%s does not ask for a step-up", name)
		}
	}
}
