// SPDX-License-Identifier: Apache-2.0

package accounts_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/password"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/token"
)

const pw = "correct horse battery staple"

type env struct {
	db    *store.DB
	sys   context.Context
	clock time.Time
	acc   *accounts.Accounts
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	e := &env{db: db, sys: storetest.SystemCtx(t), clock: time.Now()}
	e.acc = accounts.New(db, e.sys, func() time.Time { return e.clock })
	e.profile(t, rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_LOW_MEMORY) // fast enough for tests
	return e
}

func (e *env) profile(t *testing.T, p rpmgrv1.PasswordHashProfile) {
	t.Helper()
	if _, err := settings.UpdateInstance(e.sys, e.db, &rpmgrv1.InstanceSettings{PasswordHashProfile: &p},
		&fieldmaskpb.FieldMask{Paths: []string{"password_hash_profile"}}, 0); err != nil {
		t.Fatal(err)
	}
}

func (e *env) actions(t *testing.T, action string) []*ent.AuditEntry {
	t.Helper()
	return e.db.Client().AuditEntry.Query().Where(auditentry.Action(action)).AllX(e.sys)
}

// TestFirstUser: the first-user link creates the first user, Instance Admin and Owner of a new
// Default org, once; input that is not valid leaves the link usable; once a user exists, no new
// link can be made and an unused one creates nobody.
func TestFirstUser(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	link, err := e.acc.FirstUserLink("local-cli")
	if err != nil || !strings.HasPrefix(link, "rpmgr_prs_") {
		t.Fatalf("%q %v", link, err)
	}
	spare, err := e.acc.FirstUserLink("local-cli")
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		email, display, pw string
		want               error
	}{
		"no e-mail":         {"", "Ada", pw, accounts.ErrEmail},
		"no domain":         {"ada@", "Ada", pw, accounts.ErrEmail},
		"no display name":   {"ada@example.com", "  ", pw, accounts.ErrDisplayName},
		"long display name": {"ada@example.com", strings.Repeat("a", 101), pw, accounts.ErrDisplayName},
		"short password":    {"ada@example.com", "Ada", "eleven char", password.ErrLength},
	} {
		if _, err := e.acc.CompleteReset(ctx, link, c.pw, c.email, c.display); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	u, err := e.acc.CompleteReset(ctx, link, pw, " Ada@Example.COM ", " Ada Lovelace ")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "ada@example.com" || u.DisplayName != "Ada Lovelace" || !u.InstanceAdmin || u.PasswordHash == nil ||
		!strings.HasPrefix(*u.PasswordHash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("the first user: %+v", u)
	}
	m := e.db.Client().Membership.Query().Where(membership.UserID(u.ID)).OnlyX(e.sys)
	o := e.db.Client().Org.GetX(e.sys, m.OrgID)
	if m.Role != membership.RoleOwner || o.Slug != "default" {
		t.Fatalf("membership %+v in %+v", m, o)
	}
	if _, err := e.acc.CompleteReset(ctx, link, pw, "eve@example.com", "Eve"); !errors.Is(err, accounts.ErrLink) {
		t.Fatalf("a used link: %v", err)
	}
	if _, err := e.acc.CompleteReset(ctx, spare, pw, "eve@example.com", "Eve"); !errors.Is(err, accounts.ErrHasUsers) {
		t.Fatalf("a spare link after the first user: %v", err)
	}
	if _, err := e.acc.FirstUserLink("local-cli"); !errors.Is(err, accounts.ErrHasUsers) {
		t.Fatalf("a first-user link once a user exists: %v", err)
	}
	if n := e.db.Client().User.Query().CountX(e.sys); n != 1 {
		t.Fatalf("%d users", n)
	}
	if len(e.actions(t, "user.first_user_link")) != 2 || len(e.actions(t, "user.create")) != 1 {
		t.Fatal("audit entries of the links and the user")
	}
	if add := e.actions(t, "member.add"); len(add) != 1 || add[0].OrgID == nil || *add[0].OrgID != o.ID {
		t.Fatal("the membership's audit entry is not in the org's chain")
	}
}

// TestFirstUser_ExistingOrg: with an org already there, as after all-in-one init, the first user
// becomes its Owner and no org is created.
func TestFirstUser_ExistingOrg(t *testing.T) {
	e := newEnv(t)
	org := storetest.Org(t, e.db, "home")
	link, err := e.acc.FirstUserLink("local-cli")
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.acc.CompleteReset(context.Background(), link, pw, "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if m := e.db.Client().Membership.Query().Where(membership.UserID(u.ID)).OnlyX(e.sys); m.OrgID != org {
		t.Fatalf("membership in %s, want %s", m.OrgID, org)
	}
	if n := e.db.Client().Org.Query().CountX(e.sys); n != 1 {
		t.Fatalf("%d orgs", n)
	}
}

// TestResetLink: a reset link sets the user's password once, until it expires a day later; the
// old password stops working; a link for nobody, a malformed token and another kind of token are
// refused.
func TestResetLink(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	log := filepath.Join(t.TempDir(), "revocations.log")
	rl, err := revlog.Open(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.acc.ResetLog = rl
	first, _ := e.acc.FirstUserLink("local-cli")
	u, err := e.acc.CompleteReset(ctx, first, pw, "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.acc.ResetLink("usr_nobody", "local-cli"); !errors.Is(err, accounts.ErrNoUser) {
		t.Fatalf("a link for nobody: %v", err)
	}
	link, err := e.acc.ResetLink(u.ID, "local-cli")
	if err != nil {
		t.Fatal(err)
	}
	const next = "an entirely new passphrase"
	if got, err := e.acc.CompleteReset(ctx, link, next, "ignored@example.com", ""); err != nil || got.ID != u.ID || got.Email != "ada@example.com" {
		t.Fatalf("the reset: %v %v", got, err)
	}
	if _, err := e.acc.Authenticate(ctx, "ada@example.com", pw); !errors.Is(err, accounts.ErrCredentials) {
		t.Fatalf("the old password: %v", err)
	}
	if _, err := e.acc.Authenticate(ctx, "ada@example.com", next); err != nil {
		t.Fatalf("the new password: %v", err)
	}
	if _, err := e.acc.CompleteReset(ctx, link, pw, "", ""); !errors.Is(err, accounts.ErrLink) {
		t.Fatalf("a used link: %v", err)
	}
	// The reset supersedes the password; creating the first user supersedes nothing.
	if es, err := revlog.Read(log); err != nil || len(es) != 1 || es[0].Kind != revlog.CredentialSuperseded ||
		es[0].Subject != u.ID || es[0].Detail != revlog.Password {
		t.Fatalf("revocation log %+v %v", es, err)
	}

	expiring, _ := e.acc.ResetLink(u.ID, u.ID)
	e.clock = e.clock.Add(accounts.ResetLinkTTL)
	if _, err := e.acc.CompleteReset(ctx, expiring, pw, "", ""); !errors.Is(err, accounts.ErrLink) {
		t.Fatalf("a link at its expiry: %v", err)
	}
	enr, _ := token.New(token.Enrollment)
	unknown, _ := token.New(token.PasswordReset)
	for name, tok := range map[string]string{"malformed": "rpmgr_prs_nope", "another kind": enr, "unknown": unknown, "empty": ""} {
		if _, err := e.acc.CompleteReset(ctx, tok, pw, "", ""); !errors.Is(err, accounts.ErrLink) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(e.actions(t, "user.password_reset")) != 1 || len(e.actions(t, "user.reset_link")) != 2 {
		t.Fatal("audit entries of the reset")
	}
}

// TestAuthenticate: the right password signs in, whatever the case of the address, and records
// the sign-in; a wrong password, an unknown address, a malformed one and a disabled user are all
// ErrCredentials; a hash made under another profile is replaced at sign-in.
func TestAuthenticate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	link, _ := e.acc.FirstUserLink("local-cli")
	u, err := e.acc.CompleteReset(ctx, link, pw, "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.acc.Authenticate(ctx, "ADA@example.com", pw)
	if err != nil || got.ID != u.ID || got.LastLoginAt == nil {
		t.Fatalf("%+v %v", got, err)
	}
	for name, c := range map[string][2]string{
		"wrong password": {"ada@example.com", pw + "!"},
		"unknown":        {"eve@example.com", pw},
		"malformed":      {"not an address", pw},
		"empty":          {"", ""},
	} {
		if _, err := e.acc.Authenticate(ctx, c[0], c[1]); !errors.Is(err, accounts.ErrCredentials) {
			t.Errorf("%s: %v", name, err)
		}
	}

	e.profile(t, rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_DEFAULT)
	if _, err := e.acc.Authenticate(ctx, "ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	if h := e.db.Client().User.GetX(e.sys, u.ID).PasswordHash; h == nil || !strings.HasPrefix(*h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("not rehashed: %v", h)
	}
	e.db.Client().User.UpdateOneID(u.ID).SetStatus(user.StatusDisabled).ExecX(e.sys)
	if _, err := e.acc.Authenticate(ctx, "ada@example.com", pw); !errors.Is(err, accounts.ErrCredentials) {
		t.Fatalf("a disabled user: %v", err)
	}
}

// TestNormalizeEmail: trimmed and lower-case; one @ between two non-empty parts; no spaces or
// control characters; at most 254 bytes.
func TestNormalizeEmail(t *testing.T) {
	for in, want := range map[string]string{
		" Ada@Example.COM ": "ada@example.com", "a@b": "a@b", "": "", "@b": "", "a@": "", "a@b@c": "", "a b@c": "",
		"a@b\x00": "", strings.Repeat("a", 251) + "@b.c": "", strings.Repeat("a", 250) + "@b.c": strings.Repeat("a", 250) + "@b.c",
	} {
		got, err := accounts.NormalizeEmail(in)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
}

// TestLinkURLs: reset links and first-user links open their own pages of the web UI, with the
// token in the fragment, whether or not the public URL ends in a slash.
func TestLinkURLs(t *testing.T) {
	for _, public := range []string{"https://panel.example.com", "https://panel.example.com/"} {
		if got := accounts.LinkURL(public, "rpmgr_prs_x"); got != "https://panel.example.com/reset#rpmgr_prs_x" {
			t.Errorf("LinkURL(%q): %q", public, got)
		}
		if got := accounts.SetupURL(public, "rpmgr_prs_x"); got != "https://panel.example.com/setup#rpmgr_prs_x" {
			t.Errorf("SetupURL(%q): %q", public, got)
		}
	}
}

// TestSetProfile: the display name and the theme change together; "" keeps the theme, and a theme
// other than system, light and dark is refused without a change.
func TestSetProfile(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	first, _ := e.acc.FirstUserLink("local-cli")
	u, err := e.acc.CompleteReset(ctx, first, pw, "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if u.Theme != "system" {
		t.Fatalf("a new user's theme: %q", u.Theme)
	}
	if got, err := e.acc.SetProfile(ctx, u.ID, "Ada L.", "light"); err != nil || got.DisplayName != "Ada L." || got.Theme != "light" {
		t.Fatalf("to light: %v %v", got, err)
	}
	if got, err := e.acc.SetProfile(ctx, u.ID, "Ada", ""); err != nil || got.DisplayName != "Ada" || got.Theme != "light" {
		t.Fatalf("without a theme: %v %v", got, err)
	}
	if _, err := e.acc.SetProfile(ctx, u.ID, "Eve", "purple"); !errors.Is(err, accounts.ErrTheme) {
		t.Fatalf("an unknown theme: %v", err)
	}
	if got, _, _ := e.acc.User(u.ID); got.DisplayName != "Ada" || got.Theme != "light" {
		t.Fatalf("after a refused change: %q %q", got.DisplayName, got.Theme)
	}
}
