// SPDX-License-Identifier: Apache-2.0

package websession_test

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/token"
	"github.com/felix-homelab/rpmgr/internal/websession"
)

type env struct {
	db       *store.DB
	sys      context.Context
	clock    time.Time
	s        *websession.Sessions
	log      string
	ada, bob string
	org      string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	e := &env{db: db, sys: storetest.SystemCtx(t), clock: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC),
		log: filepath.Join(t.TempDir(), "revocations.log")}
	rl, err := revlog.Open(e.log, func() time.Time { return e.clock })
	if err != nil {
		t.Fatal(err)
	}
	e.s = websession.New(websession.Options{DB: db, Sys: e.sys, RevLog: rl, Now: func() time.Time { return e.clock }})
	e.org = storetest.Org(t, db, "org-a")
	c := db.Client()
	e.ada = c.User.Create().SetEmail("ada@example.com").SetDisplayName("Ada").SetInstanceAdmin(true).SaveX(e.sys).ID
	e.bob = c.User.Create().SetEmail("bob@example.com").SetDisplayName("Bob").SaveX(e.sys).ID
	c.Membership.Create().SetOrgID(e.org).SetUserID(e.ada).SetRole("admin").SetCreatedBy("test").ExecX(e.sys)
	return e
}

func (e *env) revocations(t *testing.T) []revlog.Entry {
	t.Helper()
	es, err := revlog.Read(e.log)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// TestSessions_Timeouts: a session lives 8 hours without use, slides on with use, but never past
// 7 days; its last use is written at most once a minute; tokens of another kind, malformed or
// unknown name no session.
func TestSessions_Timeouts(t *testing.T) {
	e := newEnv(t)
	tok, sess, err := e.s.Create(e.ada, []string{"pwd"}, "192.0.2.1", "test")
	if err != nil || !strings.HasPrefix(tok, "rpmgr_ses_") {
		t.Fatalf("%q %v", tok, err)
	}
	if !sess.IdleExpiresAt.Equal(e.clock.Add(8*time.Hour)) || !sess.AbsoluteExpiresAt.Equal(e.clock.Add(7*24*time.Hour)) {
		t.Fatalf("expiries %v %v", sess.IdleExpiresAt, sess.AbsoluteExpiresAt)
	}
	e.clock = e.clock.Add(30 * time.Second)
	if got, err := e.s.Lookup(tok); err != nil || !got.LastSeenAt.Equal(sess.LastSeenAt) {
		t.Fatalf("within a minute: %v, last seen %v", err, got.LastSeenAt)
	}
	// Used every 7 hours, it lives until its absolute expiry and not a moment longer.
	start := sess.CreatedAt
	for e.clock = start.Add(7 * time.Hour); e.clock.Before(start.Add(7 * 24 * time.Hour)); e.clock = e.clock.Add(7 * time.Hour) {
		if _, err := e.s.Lookup(tok); err != nil {
			t.Fatalf("at %v: %v", e.clock.Sub(start), err)
		}
	}
	e.clock = start.Add(7 * 24 * time.Hour)
	if _, err := e.s.Lookup(tok); !errors.Is(err, websession.ErrNoSession) {
		t.Fatalf("at the absolute expiry: %v", err)
	}

	idle, _, _ := e.s.Create(e.ada, []string{"pwd"}, "", "")
	e.clock = e.clock.Add(8*time.Hour - time.Second)
	if _, err := e.s.Lookup(idle); err != nil {
		t.Fatalf("just before the idle expiry: %v", err)
	}
	e.clock = e.clock.Add(8 * time.Hour)
	if _, err := e.s.Lookup(idle); !errors.Is(err, websession.ErrNoSession) {
		t.Fatalf("idle for 8 hours: %v", err)
	}
	enr, _ := token.New(token.Enrollment)
	unknown, _ := token.New(token.Session)
	for _, bad := range []string{"", "rpmgr_ses_x", enr, unknown} {
		if _, err := e.s.Lookup(bad); !errors.Is(err, websession.ErrNoSession) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// TestSessions_Revoke: a user ends one of their own sessions, not another user's; all others end
// at once, as a password change does; each revocation is in the revocation log; only live
// sessions are listed.
func TestSessions_Revoke(t *testing.T) {
	e := newEnv(t)
	one, s1, _ := e.s.Create(e.ada, []string{"pwd"}, "", "")
	two, s2, _ := e.s.Create(e.ada, []string{"pwd"}, "", "")
	three, s3, _ := e.s.Create(e.ada, []string{"pwd"}, "", "")
	bobs, _, _ := e.s.Create(e.bob, []string{"pwd"}, "", "")
	if err := e.s.Revoke(e.bob, s1.ID, e.bob); !errors.Is(err, websession.ErrNoSession) {
		t.Fatalf("another user's session: %v", err)
	}
	if err := e.s.Revoke(e.ada, s1.ID, e.ada); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Lookup(one); !errors.Is(err, websession.ErrNoSession) {
		t.Fatal("a revoked session still works")
	}
	if err := e.s.Revoke(e.ada, s1.ID, e.ada); !errors.Is(err, websession.ErrNoSession) {
		t.Fatalf("revoked twice: %v", err)
	}
	if list, _ := e.s.List(e.ada); len(list) != 2 || list[0].ID != s3.ID || list[1].ID != s2.ID {
		t.Fatalf("the live sessions: %v", list)
	}
	if n, err := e.s.RevokeAll(e.ada, s3.ID, e.ada, "password changed"); err != nil || n != 1 {
		t.Fatalf("RevokeAll: %d %v", n, err)
	}
	if _, err := e.s.Lookup(two); !errors.Is(err, websession.ErrNoSession) {
		t.Fatal("RevokeAll left a session")
	}
	for _, live := range []string{three, bobs} {
		if _, err := e.s.Lookup(live); err != nil {
			t.Fatalf("RevokeAll ended the kept or another user's session: %v", err)
		}
	}
	got := e.revocations(t)
	if len(got) != 2 || got[0].Kind != revlog.SessionRevoked || got[0].Subject != s1.ID || got[1].Subject != s2.ID ||
		got[1].Detail != "password changed" || got[1].Actor != e.ada {
		t.Fatalf("the revocation log: %+v", got)
	}
}

// TestCookie: __Host- prefix, Secure, HttpOnly, Path=/, no Domain, SameSite=Lax, expiring with the
// session; the clearing cookie has the same attributes and no value.
func TestCookie(t *testing.T) {
	e := newEnv(t)
	tok, sess, _ := e.s.Create(e.ada, []string{"pwd"}, "", "")
	c := websession.Cookie(tok, sess)
	line := c.String()
	for _, want := range []string{"__Host-rpmgr_session=" + tok, "Path=/", "HttpOnly", "Secure", "SameSite=Lax",
		"Expires=" + sess.AbsoluteExpiresAt.UTC().Format(http.TimeFormat)} {
		if !strings.Contains(line, want) {
			t.Errorf("%s lacks %s", line, want)
		}
	}
	if strings.Contains(line, "Domain") {
		t.Errorf("%s has a Domain", line)
	}
	if clear := websession.ClearCookie().String(); !strings.Contains(clear, "__Host-rpmgr_session=;") ||
		!strings.Contains(clear, "Max-Age=0") || !strings.Contains(clear, "Secure") {
		t.Errorf("the clearing cookie: %s", clear)
	}
}

// TestAuthenticate: no cookie is anonymous; a live session is its user with the roles of their
// memberships, the Instance Admin role and the step-up; any other cookie, and a disabled user's
// session, is an error.
func TestAuthenticate(t *testing.T) {
	e := newEnv(t)
	tok, sess, _ := e.s.Create(e.ada, []string{"pwd"}, "", "")
	header := func(v string) http.Header {
		h := http.Header{}
		if v != "" {
			h.Set("Cookie", websession.CookieName+"="+v)
		}
		return h
	}
	if c, err := e.s.Authenticate(context.Background(), header("")); c != nil || err != nil {
		t.Fatalf("no cookie: %v %v", c, err)
	}
	c, err := e.s.Authenticate(context.Background(), header(tok))
	if err != nil || c.UserID != e.ada || c.Memberships[e.org] != authz.RoleAdmin || !c.InstanceAdmin ||
		c.CredentialID != sess.ID || c.AuthMethod != "session" || !c.StepUpAt.IsZero() {
		t.Fatalf("a session: %+v %v", c, err)
	}
	until := e.clock.Add(5 * time.Minute)
	e.db.Client().Session.UpdateOneID(sess.ID).SetElevatedUntil(until).ExecX(e.sys)
	if c, _ := e.s.Authenticate(context.Background(), header(tok)); !c.StepUpAt.Equal(until.Add(-api.StepUpWindow)) {
		t.Fatalf("step-up at %v", c.StepUpAt)
	}
	if _, err := e.s.Authenticate(context.Background(), header("rpmgr_ses_forged")); err == nil {
		t.Fatal("a forged cookie")
	}
	e.db.Client().User.UpdateOneID(e.ada).SetStatus(user.StatusDisabled).ExecX(e.sys)
	if _, err := e.s.Authenticate(context.Background(), header(tok)); !errors.Is(err, websession.ErrDisabled) {
		t.Fatalf("a disabled user: %v", err)
	}
}
