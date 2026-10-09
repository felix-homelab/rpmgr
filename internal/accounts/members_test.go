// SPDX-License-Identifier: Apache-2.0

package accounts_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// members is an org with an Owner (Ada, the first user), an Admin and a Viewer.
type members struct {
	*env
	m                      *accounts.Members
	log                    string
	org, owner, admin, vwr string
}

func newMembers(t *testing.T) *members {
	t.Helper()
	e := newEnv(t)
	x := &members{env: e, log: filepath.Join(t.TempDir(), "revocations.log")}
	rl, err := revlog.Open(x.log, func() time.Time { return e.clock })
	if err != nil {
		t.Fatal(err)
	}
	x.m = &accounts.Members{Accounts: e.acc, RevLog: rl}
	link, _ := e.acc.FirstUserLink("local-cli")
	u, err := e.acc.CompleteReset(context.Background(), link, pw, "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	x.owner = u.ID
	x.org = e.db.Client().Membership.Query().OnlyX(e.sys).OrgID
	x.admin = x.join(t, "adm@example.com", authz.RoleAdmin)
	x.vwr = x.join(t, "vwr@example.com", authz.RoleViewer)
	return x
}

// join invites an address with a role, as the Owner, and accepts it with a new account.
func (x *members) join(t *testing.T, email, role string) string {
	t.Helper()
	tok, err := x.m.Invite(context.Background(), x.org, email, role, x.owner, authz.RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	u, org, err := x.m.AcceptInvitation(context.Background(), tok, "", "Someone", pw)
	if err != nil || org != x.org {
		t.Fatalf("accept: %v", err)
	}
	return u.ID
}

func (x *members) role(t *testing.T, user string) string {
	t.Helper()
	r, err := x.db.Client().Membership.Query().Where(membership.OrgID(x.org), membership.UserID(user)).Only(x.sys)
	if err != nil {
		return ""
	}
	return string(r.Role)
}

// TestInvitations: only an Owner invites an Owner; an invitation creates an account for a new
// address, or adds the signed-in holder of the address; it works once, within 7 days; the holder
// of an existing account signs in first; another account cannot use it; a member is not added
// twice.
func TestInvitations(t *testing.T) {
	x := newMembers(t)
	ctx := context.Background()
	if _, err := x.m.Invite(context.Background(), x.org, "new@example.com", "superuser", x.owner, authz.RoleOwner); !errors.Is(err, accounts.ErrRole) {
		t.Fatalf("an unknown role: %v", err)
	}
	if _, err := x.m.Invite(context.Background(), x.org, "new@example.com", authz.RoleOwner, x.admin, authz.RoleAdmin); !errors.Is(err, accounts.ErrOwnerOnly) {
		t.Fatalf("an Admin invites an Owner: %v", err)
	}
	if _, err := x.m.Invite(context.Background(), x.org, "not an address", authz.RoleViewer, x.owner, authz.RoleOwner); !errors.Is(err, accounts.ErrEmail) {
		t.Fatalf("a bad address: %v", err)
	}
	tok, err := x.m.Invite(context.Background(), x.org, "Op@Example.com", authz.RoleOperator, x.admin, authz.RoleAdmin)
	if err != nil || len(tok) != token.Len {
		t.Fatalf("%q %v", tok, err)
	}
	if _, _, err := x.m.AcceptInvitation(ctx, tok, "", "Op", "short"); err == nil {
		t.Fatal("a short password")
	}
	u, _, err := x.m.AcceptInvitation(ctx, tok, "", "Op", pw)
	if err != nil || u.Email != "op@example.com" || x.role(t, u.ID) != authz.RoleOperator {
		t.Fatalf("a new account: %+v %v", u, err)
	}
	if _, _, err := x.m.AcceptInvitation(ctx, tok, "", "Op", pw); !errors.Is(err, accounts.ErrInvitation) {
		t.Fatalf("an invitation twice: %v", err)
	}

	// An existing account: sign in first, as that account.
	org2 := x.db.Client().Org.Create().SetName("Second").SetSlug("second").SaveX(x.sys).ID
	tok, _ = x.m.Invite(context.Background(), org2, "vwr@example.com", authz.RoleAdmin, x.owner, authz.RoleOwner)
	if _, _, err := x.m.AcceptInvitation(ctx, tok, "", "Someone", pw); !errors.Is(err, accounts.ErrSignInFirst) {
		t.Fatalf("an existing address, signed out: %v", err)
	}
	if _, _, err := x.m.AcceptInvitation(ctx, tok, x.admin, "", ""); !errors.Is(err, accounts.ErrOtherAddress) {
		t.Fatalf("another account: %v", err)
	}
	if _, org, err := x.m.AcceptInvitation(ctx, tok, x.vwr, "", ""); err != nil || org != org2 {
		t.Fatalf("the invited account: %v", err)
	}
	tok, _ = x.m.Invite(context.Background(), x.org, "vwr@example.com", authz.RoleAdmin, x.owner, authz.RoleOwner)
	if _, _, err := x.m.AcceptInvitation(ctx, tok, x.vwr, "", ""); !errors.Is(err, accounts.ErrMember) {
		t.Fatalf("a member again: %v", err)
	}

	expiring, _ := x.m.Invite(context.Background(), x.org, "late@example.com", authz.RoleViewer, x.owner, authz.RoleOwner)
	x.clock = x.clock.Add(accounts.InvitationTTL)
	if _, _, err := x.m.AcceptInvitation(ctx, expiring, "", "Late", pw); !errors.Is(err, accounts.ErrInvitation) {
		t.Fatalf("at its expiry: %v", err)
	}
	reset, _ := token.New(token.PasswordReset)
	if _, _, err := x.m.AcceptInvitation(ctx, reset, "", "X", pw); !errors.Is(err, accounts.ErrInvitation) {
		t.Fatalf("another kind of token: %v", err)
	}
}

// TestMembers_Rules: an Admin changes neither an Owner nor anyone into one; the last Owner stays
// one and stays; downgrades and removals go to the revocation log, upgrades do not; the list
// puts Owners first.
func TestMembers_Rules(t *testing.T) {
	x := newMembers(t)
	for name, err := range map[string]error{
		"an Admin demotes the Owner":     x.m.SetRole(context.Background(), x.org, x.owner, authz.RoleAdmin, x.admin, authz.RoleAdmin),
		"an Admin makes an Owner":        x.m.SetRole(context.Background(), x.org, x.vwr, authz.RoleOwner, x.admin, authz.RoleAdmin),
		"an Admin removes the Owner":     x.m.Remove(context.Background(), x.org, x.owner, x.admin, authz.RoleAdmin),
		"the only Owner steps down":      x.m.SetRole(context.Background(), x.org, x.owner, authz.RoleAdmin, x.owner, authz.RoleOwner),
		"the only Owner is removed":      x.m.Remove(context.Background(), x.org, x.owner, x.owner, authz.RoleOwner),
		"an unknown role":                x.m.SetRole(context.Background(), x.org, x.vwr, "root", x.owner, authz.RoleOwner),
		"a role for someone not in it":   x.m.SetRole(context.Background(), x.org, "usr_nobody", authz.RoleViewer, x.owner, authz.RoleOwner),
		"a removal of someone not in it": x.m.Remove(context.Background(), x.org, "usr_nobody", x.owner, authz.RoleOwner),
	} {
		if err == nil {
			t.Errorf("%s: allowed", name)
		}
	}
	if x.role(t, x.owner) != authz.RoleOwner {
		t.Fatal("the Owner changed")
	}
	if err := x.m.SetRole(context.Background(), x.org, x.vwr, authz.RoleOperator, x.admin, authz.RoleAdmin); err != nil {
		t.Fatalf("an upgrade by an Admin: %v", err)
	}
	if err := x.m.SetRole(context.Background(), x.org, x.admin, authz.RoleOwner, x.owner, authz.RoleOwner); err != nil {
		t.Fatalf("a second Owner: %v", err)
	}
	if err := x.m.SetRole(context.Background(), x.org, x.owner, authz.RoleViewer, x.owner, authz.RoleOwner); err != nil {
		t.Fatalf("an Owner steps down beside another: %v", err)
	}
	if err := x.m.Remove(context.Background(), x.org, x.vwr, x.admin, authz.RoleOwner); err != nil {
		t.Fatalf("a removal: %v", err)
	}
	list, err := x.m.List(x.org)
	if err != nil || len(list) != 2 || list[0].UserID != x.admin || list[0].Role != authz.RoleOwner || list[1].Role != authz.RoleViewer {
		t.Fatalf("the members: %+v %v", list, err)
	}
	got, err := revlog.Read(x.log)
	if err != nil || len(got) != 2 || got[0].Kind != revlog.RoleDowngraded || got[0].Subject != x.owner || got[0].Detail != authz.RoleViewer ||
		got[0].Org != x.org || got[1].Kind != revlog.MemberRemoved || got[1].Subject != x.vwr {
		t.Fatalf("the revocation log: %+v %v", got, err)
	}
	if len(x.actions(t, "member.role")) != 3 || len(x.actions(t, "member.remove")) != 1 {
		t.Fatal("audit entries")
	}
}
