// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// reviewRefused reports whether err is the refusal of a write during restore review.
func reviewRefused(err error) bool {
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != connect.CodeFailedPrecondition {
		return false
	}
	for _, d := range cerr.Details() {
		if v, derr := d.Value(); derr == nil {
			if info, ok := v.(*errdetails.ErrorInfo); ok && info.GetReason() == api.ReasonRestoreReview {
				return true
			}
		}
	}
	return false
}

// TestRestore_OrgOwnerCannotEndInstanceReview (docs/12-testing-and-quality.md, "Security
// testing"): during restore review an org's Owner re-confirms only their own org's memberships
// and roles and resumes its suspended tokens; an Admin cannot confirm, another org's Owner finds
// nothing, and no API call ends the instance-wide review, not even the Instance Admin's: only
// `rpmgr restore confirm` on the controller host does. Until then the instance stays read-only,
// and each org until it is confirmed; revocations stay available throughout.
func TestRestore_OrgOwnerCannotEndInstanceReview(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ada := e.browser() // Instance Admin and Owner of org A
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	s, _ := ada.session()
	orgA := s.GetMemberships()[0].GetOrgId()
	orgB := storetest.Org(t, e.db, "org-b")
	members := e.orgs.Members
	inv, err := members.Invite(ctx, orgB, "bob@example.com", authz.RoleOwner, "local-cli", authz.RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := members.AcceptInvitation(ctx, inv, "", "Bob", pw); err != nil {
		t.Fatal(err)
	}
	bob := e.browser()
	if err := bob.login("bob@example.com", pw); err != nil {
		t.Fatal(err)
	}
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	carol, carolID := e.join(t, bob, orgB, "carol@example.com", authz.RoleAdmin)
	pat, err := bob.token.CreateAPIToken(ctx, connect.NewRequest(&rpmgrv1.CreateAPITokenRequest{OrgId: orgB, Name: "ci", Scopes: []string{"org.read"}}))
	if err != nil {
		t.Fatal(err)
	}
	bot := e.browser()
	bot.bearer = pat.Msg.GetToken()

	// The state a restore leaves when it failed closed (internal/controller tests the restore).
	c := e.db.Client()
	c.Instance.UpdateOneID(1).SetRestoreReviewSince(e.clock).ExecX(e.sys)
	c.Org.Update().SetRestoreReviewSince(e.clock).ExecX(e.sys)
	c.APIToken.UpdateOneID(pat.Msg.GetApiToken().GetId()).SetSuspendedAt(e.clock).ExecX(e.sys)

	me, err := bob.user.GetMe(ctx, connect.NewRequest(&rpmgrv1.GetMeRequest{}))
	if err != nil || me.Msg.GetRestoreReviewTime() == nil {
		t.Fatalf("GetMe during review: %v %v", me, err)
	}
	rename := func(b *browser, org string) error {
		_, err := b.org.UpdateOrg(ctx, connect.NewRequest(&rpmgrv1.UpdateOrgRequest{OrgId: org, Name: "renamed"}))
		return err
	}
	instanceWrite := func() error {
		_, err := ada.set.UpdateInstanceSettings(ctx, connect.NewRequest(&rpmgrv1.UpdateInstanceSettingsRequest{
			Settings:   &rpmgrv1.InstanceSettings{DefaultTransport: rpmgrv1.TransportPolicy_TRANSPORT_POLICY_H2.Enum()},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"default_transport"}}}))
		return err
	}
	for name, err := range map[string]error{"an org write in A": rename(ada, orgA), "an org write in B": rename(bob, orgB),
		"an instance write": instanceWrite()} {
		if !reviewRefused(err) {
			t.Errorf("%s during review: %v", name, err)
		}
	}
	if _, err := bob.org.ListMembers(ctx, connect.NewRequest(&rpmgrv1.ListMembersRequest{OrgId: orgB})); err != nil {
		t.Errorf("a read during review: %v", err)
	}
	if _, err := bot.org.ListMembers(ctx, connect.NewRequest(&rpmgrv1.ListMembersRequest{OrgId: orgB})); code(err) != connect.CodeUnauthenticated {
		t.Errorf("a suspended token: %v", err)
	}

	confirm := func(b *browser, org string) error {
		_, err := b.org.ConfirmRestoreReview(ctx, connect.NewRequest(&rpmgrv1.ConfirmRestoreReviewRequest{OrgId: org}))
		return err
	}
	if err := carol.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if err := confirm(carol, orgB); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Admin confirms: %v", err)
	}
	if _, err := carol.org.ResumeAPIToken(ctx, connect.NewRequest(&rpmgrv1.ResumeAPITokenRequest{OrgId: orgB,
		TokenId: pat.Msg.GetApiToken().GetId()})); code(err) != connect.CodePermissionDenied {
		t.Errorf("an Admin resumes a token: %v", err)
	}
	if err := confirm(bob, orgA); code(err) != connect.CodeNotFound {
		t.Errorf("an Owner confirms another org: %v", err)
	}
	// Revocations stay available: the Owner downgrades the Admin before confirming.
	if _, err := bob.org.UpdateMember(ctx, connect.NewRequest(&rpmgrv1.UpdateMemberRequest{OrgId: orgB, UserId: carolID,
		Role: authz.RoleViewer})); err != nil {
		t.Errorf("a downgrade during review: %v", err)
	}
	listed, err := bob.org.ListSuspendedAPITokens(ctx, connect.NewRequest(&rpmgrv1.ListSuspendedAPITokensRequest{OrgId: orgB}))
	if err != nil || len(listed.Msg.GetApiTokens()) != 1 || listed.Msg.GetApiTokens()[0].GetOwnerEmail() != "bob@example.com" ||
		listed.Msg.GetApiTokens()[0].GetApiToken().GetSuspendTime() == nil {
		t.Fatalf("the suspended tokens: %v %v", listed, err)
	}
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.org.ResumeAPIToken(ctx, connect.NewRequest(&rpmgrv1.ResumeAPITokenRequest{OrgId: orgB,
		TokenId: pat.Msg.GetApiToken().GetId()})); err != nil {
		t.Fatalf("the Owner resumes the token: %v", err)
	}
	if _, err := bot.org.ListMembers(ctx, connect.NewRequest(&rpmgrv1.ListMembersRequest{OrgId: orgB})); err != nil {
		t.Errorf("the resumed token: %v", err)
	}
	if err := confirm(bob, orgB); err != nil {
		t.Fatalf("the Owner confirms their org: %v", err)
	}
	if err := confirm(bob, orgB); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("confirmed twice: %v", err)
	}
	if err := rename(bob, orgB); err != nil {
		t.Errorf("a write in the confirmed org: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if err := confirm(ada, orgA); err != nil {
		t.Fatal(err)
	}

	// Every org is confirmed; the instance stays in review for every caller of the API.
	if err := instanceWrite(); !reviewRefused(err) {
		t.Errorf("an instance write with every org confirmed: %v", err)
	}
	if me, err := ada.user.GetMe(ctx, connect.NewRequest(&rpmgrv1.GetMeRequest{})); err != nil || me.Msg.GetRestoreReviewTime() == nil {
		t.Errorf("the instance review ended without rpmgr restore confirm: %v %v", me, err)
	}

	// The Instance Admin on the controller host ends it.
	boot := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(boot, []byte("version: 1\npublic_url: https://panel.example.com\ndatabase: {dsn: "+e.db.Path+"}\n"+
		"kek: {source: file, path: "+filepath.Join(t.TempDir(), "kek")+"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ConfirmRestore(ctx, boot, "org-b"); !errors.Is(err, controller.ErrNoReview) {
		t.Errorf("a confirmed org confirmed again on the host: %v", err)
	}
	if _, err := controller.ConfirmRestore(ctx, boot, "org-none"); err == nil || !strings.Contains(err.Error(), "no org") {
		t.Errorf("an unknown org: %v", err)
	}
	if pending, err := controller.ConfirmRestore(ctx, boot, ""); err != nil || len(pending) != 0 {
		t.Fatalf("rpmgr restore confirm: %v %v", pending, err)
	}
	if err := instanceWrite(); err != nil {
		t.Errorf("an instance write after rpmgr restore confirm: %v", err)
	}
	if _, err := controller.ConfirmRestore(ctx, boot, ""); !errors.Is(err, controller.ErrNoReview) {
		t.Errorf("confirmed twice on the host: %v", err)
	}
}
