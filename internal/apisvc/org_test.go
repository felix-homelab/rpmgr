// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
)

// TestOrg: the Owner renames the org and invites; an invitation as Admin needs a step-up, and
// retries with one request_id get one link; the invitee creates an account with the link and
// becomes a member; granting Admin needs a step-up; an Admin cannot touch the Owner; the last
// Owner stays; a removed member loses the org at their next request.
func TestOrg(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	s, _ := ada.session()
	org := s.GetMemberships()[0].GetOrgId()
	if r, err := ada.org.UpdateOrg(ctx, connect.NewRequest(&rpmgrv1.UpdateOrgRequest{OrgId: org, Name: "Home lab"})); err != nil ||
		r.Msg.GetOrg().GetName() != "Home lab" {
		t.Fatalf("rename: %v %v", r, err)
	}
	invite := func(b *browser, email, role, requestID string) (string, error) {
		r, err := b.org.CreateInvitation(ctx, connect.NewRequest(&rpmgrv1.CreateInvitationRequest{OrgId: org, Email: email, Role: role,
			RequestId: requestID}))
		if err != nil {
			return "", err
		}
		return r.Msg.GetUrl(), nil
	}
	if _, err := invite(ada, "adm@example.com", "admin", ""); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("an Admin invitation without a step-up: %v", err)
	}
	link, err := invite(ada, "op@example.com", "operator", "req-1")
	if err != nil || !strings.HasPrefix(link, "https://panel.example.com/invite#rpmgr_inv_") {
		t.Fatalf("an invitation: %q %v", link, err)
	}
	if again, err := invite(ada, "op@example.com", "operator", "req-1"); err != nil || again != link {
		t.Fatalf("a retry: %q %v", again, err)
	}
	_, tok, _ := strings.Cut(link, "#")
	op := e.browser()
	accepted, err := op.org.AcceptInvitation(ctx, connect.NewRequest(&rpmgrv1.AcceptInvitationRequest{Token: tok, DisplayName: "Op",
		Password: pw}))
	if err != nil || accepted.Msg.GetOrgId() != org {
		t.Fatalf("accept: %v %v", accepted, err)
	}
	opID := accepted.Msg.GetUserId()
	if err := op.login("op@example.com", pw); err != nil {
		t.Fatal(err)
	}
	if _, err := invite(op, "x@example.com", "viewer", ""); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Operator invites: %v", err)
	}
	if _, err := op.org.AcceptInvitation(ctx, connect.NewRequest(&rpmgrv1.AcceptInvitationRequest{Token: tok})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("an invitation twice: %v", err)
	}

	setRole := func(b *browser, user, role string) error {
		_, err := b.org.UpdateMember(ctx, connect.NewRequest(&rpmgrv1.UpdateMemberRequest{OrgId: org, UserId: user, Role: role}))
		return err
	}
	if err := setRole(ada, opID, "admin"); reason(err) != api.ReasonStepUpRequired {
		t.Fatalf("granting Admin without a step-up: %v", err)
	}
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if err := setRole(ada, opID, "admin"); err != nil {
		t.Fatalf("granting Admin: %v", err)
	}
	if err := setRole(op, e.ada, "viewer"); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Admin demotes the Owner: %v", err)
	}
	if err := setRole(ada, e.ada, "admin"); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("the last Owner steps down: %v", err)
	}
	if _, err := ada.org.RemoveMember(ctx, connect.NewRequest(&rpmgrv1.RemoveMemberRequest{OrgId: org, UserId: "usr_nobody"})); code(err) != connect.CodeNotFound {
		t.Fatalf("removing nobody: %v", err)
	}
	members, err := op.org.ListMembers(ctx, connect.NewRequest(&rpmgrv1.ListMembersRequest{OrgId: org}))
	if err != nil || len(members.Msg.GetMembers()) != 2 || members.Msg.GetMembers()[0].GetRole() != "owner" {
		t.Fatalf("the members: %v %v", members, err)
	}
	if _, err := ada.org.RemoveMember(ctx, connect.NewRequest(&rpmgrv1.RemoveMemberRequest{OrgId: org, UserId: opID})); err != nil {
		t.Fatal(err)
	}
	if _, err := op.org.GetOrg(ctx, connect.NewRequest(&rpmgrv1.GetOrgRequest{OrgId: org})); code(err) != connect.CodeNotFound {
		t.Fatalf("a removed member reads the org: %v", err)
	}
}
