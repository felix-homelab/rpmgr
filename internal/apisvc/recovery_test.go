// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"encoding/base32"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
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
	if _, err := b.user.ConfirmTOTP(ctx, connect.NewRequest(&rpmgrv1.ConfirmTOTPRequest{Code: e.code(seed)})); err != nil {
		t.Fatal(err)
	}
	return seed
}

// code is the authenticator's code at the next 30 s step, so that no code is used twice.
func (e *env) code(seed []byte) string {
	e.clock = e.clock.Add(30 * time.Second)
	return totp.Code(seed, totp.StepOf(e.clock))
}

// withMFA sets up an authenticator for b's user, who signs in with email, and leaves b signed in
// and stepped up with it, as an administrator must be to remove another's; it returns the seed.
func (e *env) withMFA(t *testing.T, b *browser, email string) []byte {
	t.Helper()
	seed := e.setUpTOTP(t, b)
	if err := b.loginWith(email, pw, e.code(seed)); err != nil {
		t.Fatal(err)
	}
	if err := b.stepUp("", e.code(seed)); err != nil {
		t.Fatal(err)
	}
	return seed
}

// recoveryEnv is an instance with org A, where Ada is Owner and Instance Admin, own an Owner, adm
// an Admin, vwr a Viewer and ia2 a Viewer who is Instance Admin too; org B, owned by Bob; Sam, a
// Viewer of both; and Nemo, who belongs to no org. Everyone but ia2 has stepped up.
type recoveryEnv struct {
	*env
	orgA, orgB                        string
	ada, own, adm, vwr, bob           *browser
	ownID, admID, vwrID, samID, ia2ID string
	nemoID                            string
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
	r.bob, _ = r.addOwner(t, r.orgB, "bob@example.com")
	r.db.Client().Membership.Create().SetOrgID(r.orgB).SetUserID(r.samID).SetRole("viewer").SetCreatedBy("test").ExecX(r.sys)
	h, err := password.Hash(context.Background(), pw, password.LowMemory)
	if err != nil {
		t.Fatal(err)
	}
	r.nemoID = r.db.Client().User.Create().SetEmail("nemo@example.com").SetDisplayName("Nemo").SetPasswordHash(h).SaveX(r.sys).ID
	for _, b := range []*browser{r.own, r.adm, r.vwr, r.bob} {
		if err := b.stepUp(pw, ""); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func resetLink(b *browser, user string) (string, error) {
	r, err := b.user.CreatePasswordResetLink(context.Background(), connect.NewRequest(&rpmgrv1.CreatePasswordResetLinkRequest{UserId: user}))
	if err != nil {
		return "", err
	}
	_, tok, _ := strings.Cut(r.Msg.GetUrl(), "#")
	return tok, nil
}

func removeTOTP(b *browser, user string) error {
	_, err := b.user.RemoveUserTOTP(context.Background(), connect.NewRequest(&rpmgrv1.RemoveUserTOTPRequest{UserId: user}))
	return err
}

func (r *recoveryEnv) complete(tok string) error {
	_, err := r.browser().auth.CompletePasswordReset(context.Background(), connect.NewRequest(&rpmgrv1.CompletePasswordResetRequest{
		Token: tok, NewPassword: "a new long password"}))
	return err
}

func (r *recoveryEnv) orgEntries(org, action, actor, target string) int {
	q := r.db.Client().AuditEntry.Query().Where(auditentry.OrgID(org), auditentry.Action(action), auditentry.TargetID(target))
	if actor != "" {
		q.Where(auditentry.ActorID(actor))
	}
	return q.CountX(r.sys)
}

// TestRecovery_ResetLinks (D95; docs/04-security.md, "Account recovery"): the Instance Admin makes
// a reset link for anyone else; an Owner or Admin only for a user all of whose orgs they hold, as
// Owner, or as Admin for one who is no Owner, and never for an Instance Admin or a user in no org;
// anyone else finds no user; nobody makes one for themselves. Each org of the user logs it.
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
		"an Owner for a user in no org":            {r.own, r.nemoID, connect.CodeNotFound},
		"an Owner for themselves":                  {r.own, r.ownID, connect.CodeInvalidArgument},
		"the Instance Admin for themselves":        {r.ada, r.env.ada, connect.CodeInvalidArgument},
		"the Instance Admin for the shared member": {r.ada, r.samID, 0},
		"the Instance Admin for an Instance Admin": {r.ada, r.ia2ID, 0},
		"the Instance Admin for a user in no org":  {r.ada, r.nemoID, 0},
		"the Instance Admin for nobody":            {r.ada, "usr_nobody", connect.CodeNotFound},
	} {
		if _, err := resetLink(c.b, c.user); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Each org's log shows the links made for its members, and by whom.
	for _, c := range []struct {
		org, actor, user string
		n                int
	}{
		{r.orgA, r.ownID, r.vwrID, 1}, {r.orgA, r.admID, r.vwrID, 1}, {r.orgA, r.ownID, r.admID, 1},
		{r.orgA, r.env.ada, r.samID, 1}, {r.orgB, r.env.ada, r.samID, 1}, {r.orgA, r.env.ada, r.ia2ID, 1},
	} {
		if got := r.orgEntries(c.org, "member.reset_link", c.actor, c.user); got != c.n {
			t.Errorf("org %s logs %d links by %s for %s, want %d", c.org, got, c.actor, c.user, c.n)
		}
	}
}

// TestRecovery_LinksCheckedAgain (D95): a link an Owner or Admin made works while they may still
// recover the user, but not once the user became Instance Admin or the maker lost the role. A link
// the Instance Admin made needs no such check.
func TestRecovery_LinksCheckedAgain(t *testing.T) {
	r := newRecoveryEnv(t)
	ctx := context.Background()
	for name, b := range map[string]*browser{"an Owner's": r.own, "an Admin's": r.adm} {
		tok, err := resetLink(b, r.vwrID)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.complete(tok); err != nil {
			t.Errorf("%s link, nothing changed: %v", name, err)
		}
	}
	byAdmin, err := resetLink(r.adm, r.vwrID)
	if err != nil {
		t.Fatal(err)
	}
	byInstanceAdmin, err := resetLink(r.ada, r.vwrID)
	if err != nil {
		t.Fatal(err)
	}
	r.db.Client().User.UpdateOneID(r.vwrID).SetInstanceAdmin(true).ExecX(r.sys)
	if err := r.complete(byAdmin); code(err) == 0 {
		t.Error("an Admin's link set the password of a user who became Instance Admin since")
	}
	if err := r.complete(byInstanceAdmin); err != nil {
		t.Errorf("the Instance Admin's link: %v", err)
	}
	r.db.Client().User.UpdateOneID(r.vwrID).SetInstanceAdmin(false).ExecX(r.sys)

	byRemoved, err := resetLink(r.adm, r.vwrID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.own.org.RemoveMember(ctx, connect.NewRequest(&rpmgrv1.RemoveMemberRequest{OrgId: r.orgA, UserId: r.admID})); err != nil {
		t.Fatal(err)
	}
	if err := r.complete(byRemoved); code(err) == 0 {
		t.Error("the link of an Admin removed since set a password")
	}
}

// TestRecovery_RemoveTOTP (D95): an Owner signed in with a second factor removes the authenticator
// of a user all of whose orgs they own, after a step-up; that ends the user's sessions, who then
// signs in with the password alone. An Owner or the Instance Admin without a second factor, an
// Admin, another org's Owner, the user's own call and a user without one are refused.
func TestRecovery_RemoveTOTP(t *testing.T) {
	r := newRecoveryEnv(t)
	r.setUpTOTP(t, r.vwr)
	if err := r.vwr.loginWith("vwr@example.com", pw, ""); reason(err) != api.ReasonMFARequired {
		t.Fatalf("the Viewer signs in without the second factor: %v", err)
	}
	if err := removeTOTP(r.own, r.vwrID); reason(err) != api.ReasonMFARequired {
		t.Errorf("an Owner signed in without a second factor: %v", err)
	}
	r.withMFA(t, r.own, "own@example.com")
	for name, c := range map[string]struct {
		b    *browser
		user string
		want connect.Code
	}{
		"an Admin":                   {r.adm, r.vwrID, connect.CodeNotFound},
		"another org's Owner":        {r.bob, r.vwrID, connect.CodeNotFound},
		"an Owner for a shared user": {r.own, r.samID, connect.CodeNotFound},
		"an Owner for themselves":    {r.own, r.ownID, connect.CodeInvalidArgument},
		"an Owner, no TOTP":          {r.own, r.admID, connect.CodeFailedPrecondition},
		"an Owner, a user in no org": {r.own, r.nemoID, connect.CodeNotFound},
		"the Instance Admin, no MFA": {r.ada, r.samID, connect.CodePermissionDenied},
	} {
		if err := removeTOTP(c.b, c.user); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	r.withMFA(t, r.adm, "adm@example.com") // an unrelated authenticator, which stays
	signedIn := r.browser()
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
	if n := r.orgEntries(r.orgA, "member.mfa_remove", r.ownID, r.vwrID); n != 1 {
		t.Errorf("%d entries of the removal in the org's log", n)
	}
	log, err := os.ReadFile(r.log)
	if err != nil || !strings.Contains(string(log), `"subject":"`+r.vwrID+`"`) {
		t.Errorf("the revocation log: %v", err)
	}
	if err := r.browser().loginWith("adm@example.com", pw, ""); reason(err) != api.ReasonMFARequired {
		t.Errorf("the Admin's authenticator went too: %v", err)
	}
}

// TestRecovery_MFAPolicy (D95): an Owner signed in without a second factor recovers no member of an
// org that requires one, also when it is the member's second org; signed in with one, they do. The
// Instance Admin is not bound by an org's policy.
func TestRecovery_MFAPolicy(t *testing.T) {
	r := newRecoveryEnv(t)
	ctx := context.Background()
	// Duo owns both orgs; Tri is a Viewer of both.
	duo, duoID := r.join(t, r.ada, r.orgA, "duo@example.com", "owner")
	_, triID := r.join(t, r.ada, r.orgA, "tri@example.com", "viewer")
	for _, m := range []struct{ user, role string }{{duoID, "owner"}, {triID, "viewer"}} {
		r.db.Client().Membership.Create().SetOrgID(r.orgB).SetUserID(m.user).SetRole(membership.Role(m.role)).SetCreatedBy("test").ExecX(r.sys)
	}
	if err := duo.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := resetLink(duo, triID); err != nil {
		t.Fatalf("an Owner of both orgs: %v", err)
	}
	if _, err := r.bob.set.UpdateOrgSettings(ctx, connect.NewRequest(&rpmgrv1.UpdateOrgSettingsRequest{OrgId: r.orgB,
		Settings: &rpmgrv1.OrgSettings{RequireMfa: proto.Bool(true)}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"require_mfa"}}})); err != nil {
		t.Fatal(err)
	}
	if _, err := resetLink(duo, triID); reason(err) != api.ReasonMFARequired {
		t.Errorf("the second org requires a second factor: %v", err)
	}
	if _, err := resetLink(duo, r.vwrID); err != nil {
		t.Errorf("a member of the first org only: %v", err)
	}
	r.withMFA(t, duo, "duo@example.com")
	if _, err := resetLink(duo, triID); err != nil {
		t.Errorf("signed in with a second factor: %v", err)
	}
	if _, err := resetLink(r.ada, triID); err != nil {
		t.Errorf("the Instance Admin: %v", err)
	}
}

// TestRecovery_RestoreReview (D95; docs/10-operations.md, "Backup and restore"): no account is
// recovered through the API while the instance is in restore review, nor by an Owner or Admin
// while an org of the user is.
func TestRecovery_RestoreReview(t *testing.T) {
	r := newRecoveryEnv(t)
	r.db.Client().Org.UpdateOneID(r.orgA).SetRestoreReviewSince(time.Now()).ExecX(r.sys)
	if _, err := resetLink(r.own, r.vwrID); reason(err) != api.ReasonRestoreReview {
		t.Errorf("an Owner while the org is in review: %v", err)
	}
	if _, err := resetLink(r.ada, r.vwrID); err != nil {
		t.Errorf("the Instance Admin while an org is in review: %v", err)
	}
	r.db.Client().Instance.UpdateOneID(1).SetRestoreReviewSince(time.Now()).ExecX(r.sys)
	if _, err := resetLink(r.ada, r.vwrID); reason(err) != api.ReasonRestoreReview {
		t.Errorf("the Instance Admin while the instance is in review: %v", err)
	}
	if err := removeTOTP(r.ada, r.vwrID); reason(err) != api.ReasonRestoreReview {
		t.Errorf("a removal while the instance is in review: %v", err)
	}
}

// TestRecovery_Tokens (D95, D63): a personal API token recovers accounts with the scope
// members.write, within its own org only, or instance.admin, and a step-up of its own; an Instance
// Admin's token without that scope recovers only as its org role allows.
func TestRecovery_Tokens(t *testing.T) {
	r := newRecoveryEnv(t)
	ctx := context.Background()
	ownSeed := r.withMFA(t, r.own, "own@example.com")
	adaSeed := r.withMFA(t, r.ada, "ada@example.com")
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
	members, readOnly := token(r.own, "org.read", "members.write"), token(r.own, "org.read")
	admin, adminMembers := token(r.ada, "instance.admin"), token(r.ada, "org.read", "members.write")
	if _, err := resetLink(members, r.vwrID); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("a token without its step-up: %v", err)
	}
	for _, c := range []struct {
		b    *browser
		seed []byte
	}{{members, ownSeed}, {readOnly, ownSeed}, {admin, adaSeed}, {adminMembers, adaSeed}} {
		if err := c.b.stepUp("", r.code(c.seed)); err != nil {
			t.Fatal(err)
		}
	}
	// The Owner owns org B too: a session reaches Sam, a member of both, a token of org A does not.
	r.db.Client().Membership.Create().SetOrgID(r.orgB).SetUserID(r.ownID).SetRole("owner").SetCreatedBy("test").ExecX(r.sys)
	if _, err := resetLink(r.own, r.samID); err != nil {
		t.Errorf("a session of an Owner of both orgs: %v", err)
	}
	for name, c := range map[string]struct {
		b    *browser
		user string
		want connect.Code
	}{
		"members.write for a Viewer":                     {members, r.vwrID, 0},
		"org.read only":                                  {readOnly, r.vwrID, connect.CodeNotFound},
		"members.write for a member of both orgs":        {members, r.samID, connect.CodeNotFound},
		"instance.admin for a member of both orgs":       {admin, r.samID, 0},
		"an Instance Admin's members.write, both orgs":   {adminMembers, r.samID, connect.CodeNotFound},
		"an Instance Admin's members.write, an IA":       {adminMembers, r.ia2ID, connect.CodeNotFound},
		"an Instance Admin's members.write for a Viewer": {adminMembers, r.vwrID, 0},
	} {
		if _, err := resetLink(c.b, c.user); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	r.setUpTOTP(t, r.vwr)
	if err := removeTOTP(members, r.vwrID); err != nil {
		t.Errorf("a token made with a second factor removes a Viewer's authenticator: %v", err)
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

// TestRecovery_OwnRemovalEndsSessions: a user's own removal of their authenticator ends their other
// sessions in the same change, as an administrator's ends all of them, and keeps the current one.
func TestRecovery_OwnRemovalEndsSessions(t *testing.T) {
	r := newRecoveryEnv(t)
	seed := r.setUpTOTP(t, r.vwr)
	other := r.browser()
	if err := other.loginWith("vwr@example.com", pw, r.code(seed)); err != nil {
		t.Fatal(err)
	}
	if err := r.vwr.loginWith("vwr@example.com", pw, r.code(seed)); err != nil {
		t.Fatal(err)
	}
	if err := r.vwr.stepUp("", r.code(seed)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.vwr.user.RemoveTOTP(context.Background(), connect.NewRequest(&rpmgrv1.RemoveTOTPRequest{})); err != nil {
		t.Fatal(err)
	}
	if _, err := other.session(); code(err) != connect.CodeUnauthenticated {
		t.Errorf("the other session after the removal: %v", err)
	}
	if _, err := r.vwr.session(); err != nil {
		t.Errorf("the current session after the removal: %v", err)
	}
}
