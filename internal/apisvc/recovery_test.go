// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"encoding/base32"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/totp"
)

// setUpTOTP sets up an authenticator for b's user and returns its seed.
func (e *env) setUpTOTP(t *testing.T, b *browser) []byte {
	t.Helper()
	ctx := context.Background()
	if err := b.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	r, err := b.user.EnrollTOTP(ctx, connect.NewRequest(&rpmgrv1.EnrollTOTPRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(r.Msg.GetSecret())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.user.ConfirmTOTP(ctx, connect.NewRequest(&rpmgrv1.ConfirmTOTPRequest{Code: totp.Code(seed, totp.StepOf(e.clock))})); err != nil {
		t.Fatal(err)
	}
	return seed
}

// recoveryEnv is an instance with org A, where Ada is Owner and Instance Admin, own an Owner, adm
// an Admin, vwr a Viewer and ia2 a Viewer who is Instance Admin too; org B, owned by Bob; and Sam,
// a Viewer of both. Everyone but ia2 has stepped up.
type recoveryEnv struct {
	*env
	orgA, orgB                 string
	ada, own, adm, vwr, bob    *browser
	ownID, admID, vwrID, samID string
	ia2ID, bobID               string
}

func newRecoveryEnv(t *testing.T) *recoveryEnv {
	t.Helper()
	r := &recoveryEnv{env: newEnv(t)}
	r.ada = r.browser()
	if err := r.ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	s, _ := r.ada.session()
	r.orgA = s.GetMemberships()[0].GetOrgId()
	if err := r.ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	r.own, r.ownID = r.join(t, r.ada, r.orgA, "own@example.com", "owner")
	r.adm, r.admID = r.join(t, r.ada, r.orgA, "adm@example.com", "admin")
	r.vwr, r.vwrID = r.join(t, r.ada, r.orgA, "vwr@example.com", "viewer")
	_, r.samID = r.join(t, r.ada, r.orgA, "sam@example.com", "viewer")
	_, r.ia2ID = r.join(t, r.ada, r.orgA, "ia2@example.com", "viewer")
	r.db.Client().User.UpdateOneID(r.ia2ID).SetInstanceAdmin(true).ExecX(r.sys)
	r.orgB = storetest.Org(t, r.db, "org-b")
	r.bob, r.bobID = r.addOwner(t, r.orgB, "bob@example.com")
	r.db.Client().Membership.Create().SetOrgID(r.orgB).SetUserID(r.samID).SetRole("viewer").SetCreatedBy("test").ExecX(r.sys)
	for _, b := range []*browser{r.own, r.adm, r.vwr, r.bob} {
		if err := b.stepUp(pw, ""); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func resetLink(b *browser, user string) error {
	_, err := b.user.CreatePasswordResetLink(context.Background(), connect.NewRequest(&rpmgrv1.CreatePasswordResetLinkRequest{UserId: user}))
	return err
}

func removeTOTP(b *browser, user string) error {
	_, err := b.user.RemoveUserTOTP(context.Background(), connect.NewRequest(&rpmgrv1.RemoveUserTOTPRequest{UserId: user}))
	return err
}

// TestRecovery_ResetLinks (D95; docs/04-security.md, "Account recovery"): the Instance Admin makes
// a reset link for anyone; an Owner or Admin only for a user all of whose orgs they hold, as Owner,
// or as Admin for one who is no Owner, and never for an Instance Admin; anyone else finds no user.
func TestRecovery_ResetLinks(t *testing.T) {
	r := newRecoveryEnv(t)
	for name, c := range map[string]struct {
		b    *browser
		user string
		want connect.Code
	}{
		"an Owner for a Viewer":                    {r.own, r.vwrID, 0},
		"an Owner for an Admin":                    {r.own, r.admID, 0},
		"an Admin for a Viewer":                    {r.adm, r.vwrID, 0},
		"an Admin for an Owner":                    {r.adm, r.ownID, connect.CodeNotFound},
		"a Viewer for an Admin":                    {r.vwr, r.admID, connect.CodeNotFound},
		"an Owner for a member of another org too": {r.own, r.samID, connect.CodeNotFound},
		"the other org's Owner for that member":    {r.bob, r.samID, connect.CodeNotFound},
		"another org's Owner for a Viewer":         {r.bob, r.vwrID, connect.CodeNotFound},
		"an Owner for an Instance Admin":           {r.own, r.ia2ID, connect.CodeNotFound},
		"the Instance Admin for the shared member": {r.ada, r.samID, 0},
		"the Instance Admin for an Instance Admin": {r.ada, r.ia2ID, 0},
		"the Instance Admin for nobody":            {r.ada, "usr_nobody", connect.CodeNotFound},
	} {
		if err := resetLink(c.b, c.user); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestRecovery_RemoveTOTP (D95): an Owner removes the authenticator of a user all of whose orgs they
// own, after a step-up; that ends the user's sessions, who then signs in with the password alone.
// An Admin, another org's Owner, the user's own call and a user without one are refused.
func TestRecovery_RemoveTOTP(t *testing.T) {
	r := newRecoveryEnv(t)
	r.setUpTOTP(t, r.vwr)
	if err := r.vwr.loginWith("vwr@example.com", pw, ""); reason(err) != api.ReasonMFARequired {
		t.Fatalf("the Viewer signs in without the second factor: %v", err)
	}
	for name, c := range map[string]struct {
		b    *browser
		user string
		want connect.Code
	}{
		"an Admin":                    {r.adm, r.vwrID, connect.CodeNotFound},
		"another org's Owner":         {r.bob, r.vwrID, connect.CodeNotFound},
		"an Owner for a shared user":  {r.own, r.samID, connect.CodeNotFound},
		"an Owner for themselves":     {r.own, r.ownID, connect.CodeInvalidArgument},
		"the Instance Admin, no TOTP": {r.ada, r.samID, connect.CodeFailedPrecondition},
	} {
		if err := removeTOTP(c.b, c.user); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	fresh := r.browser()
	if err := fresh.login("own@example.com", pw); err != nil {
		t.Fatal(err)
	}
	if err := removeTOTP(fresh, r.vwrID); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("without a step-up: %v", err)
	}
	signedIn := r.browser()
	r.setUpTOTP(t, r.adm) // an unrelated authenticator, which stays
	if err := removeTOTP(r.own, r.vwrID); err != nil {
		t.Fatalf("an Owner for a Viewer: %v", err)
	}
	if _, err := r.vwr.session(); code(err) != connect.CodeUnauthenticated {
		t.Errorf("the Viewer's session after the removal: %v", err)
	}
	if err := signedIn.login("vwr@example.com", pw); err != nil {
		t.Fatalf("the Viewer signs in with the password alone: %v", err)
	}
	if err := removeTOTP(r.own, r.vwrID); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a second removal: %v", err)
	}
	if n := r.db.Client().AuditEntry.Query().Where(auditentry.Action("user.mfa_remove"), auditentry.ActorID(r.ownID),
		auditentry.TargetID(r.vwrID)).CountX(r.sys); n != 1 {
		t.Errorf("%d audit entries of the removal by the Owner", n)
	}
	log, err := os.ReadFile(r.log)
	if err != nil || !strings.Contains(string(log), `"subject":"`+r.vwrID+`"`) {
		t.Errorf("the revocation log: %v", err)
	}
	if err := r.adm.loginWith("adm@example.com", pw, ""); reason(err) != api.ReasonMFARequired {
		t.Errorf("the Admin's authenticator went too: %v", err)
	}
}

// TestRecovery_MFAPolicy (D95): an Owner signed in without a second factor recovers no member of an
// org that requires one, as they act in it for nothing else; the Instance Admin still can.
func TestRecovery_MFAPolicy(t *testing.T) {
	r := newRecoveryEnv(t)
	if _, err := r.ada.set.UpdateOrgSettings(context.Background(), connect.NewRequest(&rpmgrv1.UpdateOrgSettingsRequest{OrgId: r.orgA,
		Settings: &rpmgrv1.OrgSettings{RequireMfa: proto.Bool(true)}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"require_mfa"}}})); err != nil {
		t.Fatal(err)
	}
	if err := resetLink(r.own, r.vwrID); reason(err) != api.ReasonMFARequired {
		t.Errorf("an Owner without a second factor: %v", err)
	}
	if err := resetLink(r.ada, r.vwrID); err != nil {
		t.Errorf("the Instance Admin: %v", err)
	}
}

// TestRecovery_Tokens (D95, D63): a personal API token recovers accounts with the scope
// members.write, or instance.admin, and a step-up of its own, and within its own org only.
func TestRecovery_Tokens(t *testing.T) {
	r := newRecoveryEnv(t)
	ctx := context.Background()
	token := func(owner *browser, scopes ...string) *browser {
		t.Helper()
		res, err := owner.token.CreateAPIToken(ctx, connect.NewRequest(&rpmgrv1.CreateAPITokenRequest{OrgId: r.orgA, Name: "cli", Scopes: scopes}))
		if err != nil {
			t.Fatal(err)
		}
		b := r.browser()
		b.bearer = res.Msg.GetToken()
		return b
	}
	members, readOnly, admin := token(r.own, "org.read", "members.write"), token(r.own, "org.read"), token(r.ada, "instance.admin")
	if err := resetLink(members, r.vwrID); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("a token without its step-up: %v", err)
	}
	for _, b := range []*browser{members, readOnly, admin} {
		if err := b.stepUp(pw, ""); err != nil {
			t.Fatal(err)
		}
	}
	for name, c := range map[string]struct {
		b    *browser
		user string
		want connect.Code
	}{
		"members.write for a Viewer":         {members, r.vwrID, 0},
		"org.read only":                      {readOnly, r.vwrID, connect.CodeNotFound},
		"members.write for a shared member":  {members, r.samID, connect.CodeNotFound},
		"instance.admin for a shared member": {admin, r.samID, 0},
	} {
		if err := resetLink(c.b, c.user); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	r.setUpTOTP(t, r.vwr)
	if err := removeTOTP(members, r.vwrID); err != nil {
		t.Errorf("a token removes a Viewer's authenticator: %v", err)
	}
	// A token still reaches nothing else of its owner's account.
	if _, err := members.user.GetMe(ctx, connect.NewRequest(&rpmgrv1.GetMeRequest{})); code(err) != connect.CodePermissionDenied {
		t.Errorf("a token reads its owner's account: %v", err)
	}
}

// TestRecovery_InstanceAdmin (D95): only an Instance Admin grants and revokes the role, after a
// step-up, audited, a revocation in the revocation log; the last active Instance Admin keeps it.
func TestRecovery_InstanceAdmin(t *testing.T) {
	r := newRecoveryEnv(t)
	ctx := context.Background()
	set := func(b *browser, user string, on bool) (*rpmgrv1.User, error) {
		res, err := b.user.SetInstanceAdmin(ctx, connect.NewRequest(&rpmgrv1.SetInstanceAdminRequest{UserId: user, InstanceAdmin: on}))
		if err != nil {
			return nil, err
		}
		return res.Msg.GetUser(), nil
	}
	if _, err := set(r.own, r.ownID, true); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Owner makes themselves Instance Admin: %v", err)
	}
	if u, err := set(r.ada, r.ownID, true); err != nil || !u.GetInstanceAdmin() {
		t.Fatalf("grant: %v %v", u, err)
	}
	if s, err := r.own.session(); err != nil || !s.GetInstanceAdmin() {
		t.Fatalf("the new Instance Admin's session: %v %v", s, err)
	}
	if u, err := set(r.ada, r.ownID, true); err != nil || !u.GetInstanceAdmin() {
		t.Fatalf("a second grant: %v %v", u, err)
	}
	if u, err := set(r.own, r.ownID, false); err != nil || u.GetInstanceAdmin() {
		t.Fatalf("an Instance Admin gives the role up: %v %v", u, err)
	}
	if s, err := r.own.session(); err != nil || s.GetInstanceAdmin() {
		t.Fatalf("the former Instance Admin's session: %v %v", s, err)
	}
	if _, err := set(r.ada, "usr_nobody", true); code(err) != connect.CodeNotFound {
		t.Errorf("nobody: %v", err)
	}
	// ia2 is disabled: Ada is the last active Instance Admin.
	r.db.Client().User.UpdateOneID(r.ia2ID).SetStatus("disabled").ExecX(r.sys)
	if _, err := set(r.ada, r.env.ada, false); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("the last active Instance Admin: %v", err)
	}
	r.clock = r.clock.Add(api.StepUpWindow + 1)
	if _, err := set(r.ada, r.ownID, true); reason(err) != api.ReasonStepUpRequired {
		t.Errorf("after the step-up window: %v", err)
	}
	for action, n := range map[string]int{"user.instance_admin_grant": 1, "user.instance_admin_revoke": 1} {
		if got := r.db.Client().AuditEntry.Query().Where(auditentry.Action(action), auditentry.TargetID(r.ownID)).CountX(r.sys); got != n {
			t.Errorf("%d audit entries %s, want %d", got, action, n)
		}
	}
	log, err := os.ReadFile(r.log)
	if err != nil || !strings.Contains(string(log), `"kind":"instance_admin_revoked","subject":"`+r.ownID+`"`) {
		t.Errorf("the revocation log %q: %v", log, err)
	}
}
