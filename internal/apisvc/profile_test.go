// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// join invites an address into org with a role as b, accepts it with a new account, and returns
// the new user signed in.
func (e *env) join(t *testing.T, b *browser, org, email, role string) (*browser, string) {
	t.Helper()
	ctx := context.Background()
	inv, err := b.org.CreateInvitation(ctx, connect.NewRequest(&rpmgrv1.CreateInvitationRequest{OrgId: org, Email: email, Role: role}))
	if err != nil {
		t.Fatal(err)
	}
	_, tok, _ := strings.Cut(inv.Msg.GetUrl(), "#")
	nb := e.browser()
	r, err := nb.org.AcceptInvitation(ctx, connect.NewRequest(&rpmgrv1.AcceptInvitationRequest{Token: tok, DisplayName: email, Password: pw}))
	if err != nil {
		t.Fatal(err)
	}
	if err := nb.login(email, pw); err != nil {
		t.Fatal(err)
	}
	return nb, r.Msg.GetUserId()
}

// TestUser_Profile: a user reads their account and renames themselves; a password change needs
// the current password, ends the user's other sessions and replaces the password.
func TestUser_Profile(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ada, other := e.browser(), e.browser()
	for _, b := range []*browser{ada, other} {
		if err := b.login("ada@example.com", pw); err != nil {
			t.Fatal(err)
		}
	}
	me, err := ada.user.GetMe(ctx, connect.NewRequest(&rpmgrv1.GetMeRequest{}))
	if err != nil || me.Msg.GetUser().GetEmail() != "ada@example.com" || !me.Msg.GetUser().GetInstanceAdmin() ||
		me.Msg.GetUser().GetMfa() || len(me.Msg.GetMemberships()) != 1 || me.Msg.GetUser().GetLastLoginTime() == nil {
		t.Fatalf("GetMe: %v %v", me, err)
	}
	if r, err := ada.user.UpdateMe(ctx, connect.NewRequest(&rpmgrv1.UpdateMeRequest{DisplayName: " Ada L. "})); err != nil ||
		r.Msg.GetUser().GetDisplayName() != "Ada L." {
		t.Fatalf("UpdateMe: %v %v", r, err)
	}
	if _, err := ada.user.UpdateMe(ctx, connect.NewRequest(&rpmgrv1.UpdateMeRequest{})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("an empty display name: %v", err)
	}
	change := func(current, next string) error {
		_, err := ada.user.ChangePassword(ctx, connect.NewRequest(&rpmgrv1.ChangePasswordRequest{CurrentPassword: current, NewPassword: next}))
		return err
	}
	const next = "an entirely new passphrase"
	if err := change("wrong password", next); code(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "current password") {
		t.Fatalf("a wrong current password: %v", err)
	}
	if err := change(pw, "too short"); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a short new password: %v", err)
	}
	if err := change(pw, next); err != nil {
		t.Fatal(err)
	}
	if _, err := other.session(); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("the other session after a password change: %v", err)
	}
	if _, err := ada.session(); err != nil {
		t.Fatalf("the session that changed it: %v", err)
	}
	if err := e.browser().login("ada@example.com", pw); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("the old password: %v", err)
	}
	if err := e.browser().login("ada@example.com", next); err != nil {
		t.Fatalf("the new password: %v", err)
	}
}

// TestUser_Admin: only the Instance Admin lists users, page by page; reset links: the Instance
// Admin's for anyone, an Admin's for a member of their org but not for its Owner, nobody else's,
// and each after a step-up.
func TestUser_Admin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	s, _ := ada.session()
	org := s.GetMemberships()[0].GetOrgId()
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	adm, admID := e.join(t, ada, org, "adm@example.com", "admin")
	vwr, vwrID := e.join(t, ada, org, "vwr@example.com", "viewer")

	page, err := ada.user.ListUsers(ctx, connect.NewRequest(&rpmgrv1.ListUsersRequest{PageSize: 2}))
	if err != nil || len(page.Msg.GetUsers()) != 2 || page.Msg.GetNextPageToken() == "" {
		t.Fatalf("the first page: %v %v", page, err)
	}
	rest, err := ada.user.ListUsers(ctx, connect.NewRequest(&rpmgrv1.ListUsersRequest{PageSize: 2, PageToken: page.Msg.GetNextPageToken()}))
	if err != nil || len(rest.Msg.GetUsers()) != 1 || rest.Msg.GetNextPageToken() != "" {
		t.Fatalf("the last page: %v %v", rest, err)
	}
	if _, err := ada.user.ListUsers(ctx, connect.NewRequest(&rpmgrv1.ListUsersRequest{PageToken: "x" + page.Msg.GetNextPageToken()})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a tampered page token: %v", err)
	}
	if _, err := adm.user.ListUsers(ctx, connect.NewRequest(&rpmgrv1.ListUsersRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("an Admin lists users: %v", err)
	}

	link := func(b *browser, user string) error {
		r, err := b.user.CreatePasswordResetLink(ctx, connect.NewRequest(&rpmgrv1.CreatePasswordResetLinkRequest{UserId: user}))
		if err == nil && !strings.HasPrefix(r.Msg.GetUrl(), "https://panel.example.com/reset#rpmgr_prs_") {
			t.Fatalf("the link %q", r.Msg.GetUrl())
		}
		return err
	}
	if err := link(adm, vwrID); code(err) == 0 {
		t.Fatal("a reset link without a step-up")
	}
	for _, b := range []*browser{adm, vwr} {
		if err := b.stepUp(pw, ""); err != nil {
			t.Fatal(err)
		}
	}
	for name, c := range map[string]struct {
		b    *browser
		user string
		want connect.Code
	}{
		"the Instance Admin for a Viewer":  {ada, vwrID, 0},
		"the Instance Admin for nobody":    {ada, "usr_nobody", connect.CodeNotFound},
		"an Admin for a Viewer of the org": {adm, vwrID, 0},
		"an Admin for the Owner":           {adm, e.ada, connect.CodeNotFound},
		"a Viewer for the Admin":           {vwr, admID, connect.CodeNotFound},
	} {
		if err := link(c.b, c.user); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
}
