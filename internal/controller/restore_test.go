// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
	entorg "github.com/felix-homelab/rpmgr/internal/store/ent/org"
	entsession "github.com/felix-homelab/rpmgr/internal/store/ent/session"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/token"
	"github.com/felix-homelab/rpmgr/internal/totp"
	"github.com/felix-homelab/rpmgr/internal/websession"
)

const restorePW, changedPW = "correct horse battery staple", "another horse battery staple"

// restoreEnv is a controller on a SQLite database whose revocation log is the state directory's,
// as on a controller host, with a boot file that names both.
type restoreEnv struct {
	*sessionEnv
	cfg, logPath string
	log          *revlog.Log
	revoker      controller.Revoker
}

func startRestoreEnv(t *testing.T, db *store.DB) *restoreEnv {
	t.Helper()
	state := filepath.Dir(db.Path)
	x := &restoreEnv{cfg: filepath.Join(t.TempDir(), "controller.yaml"), logPath: filepath.Join(state, "revocations.log")}
	var err error
	if x.log, err = revlog.Open(x.logPath, nil); err != nil {
		t.Fatal(err)
	}
	x.sessionEnv = startSessionsWith(t, db, func(o *controller.SessionsOptions) { o.Version, o.RevLog = "0.1.0", x.log })
	x.revoker = controller.Revoker{Sessions: x.sessions, Log: x.log}
	boot := "version: 1\npublic_url: https://panel.example.com\ndatabase: {dsn: " + db.Path + "}\nkek: {source: file, path: " +
		filepath.Join(state, "kek") + "}\n"
	if err := os.WriteFile(x.cfg, []byte(boot), 0o600); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x *restoreEnv) backup(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "rpmgr.backup")
	if _, err := controller.Backup(context.Background(), x.cfg, out, "0.1.0", time.Now); err != nil {
		t.Fatal(err)
	}
	return out
}

// restore restores archive and serves new sessions on the restored database, with the KEK of the
// one before and the restored revocation log.
func (x *restoreEnv) restore(t *testing.T, archive string, logs ...string) (*restoreEnv, controller.RestoreResult) {
	t.Helper()
	res, err := controller.Restore(context.Background(), controller.RestoreOptions{ConfigPath: x.cfg, Archive: archive, RevocationLogs: logs})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenSQLite(context.Background(), x.db.Path, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r := &restoreEnv{cfg: x.cfg, logPath: x.logPath}
	if r.log, err = revlog.Open(r.logPath, nil); err != nil {
		t.Fatal(err)
	}
	r.sessionEnv = &sessionEnv{db: db, org: x.org, dbEpoch: res.NewEpoch, sealer: x.sealer, sys: x.sys}
	serveSessions(t, r.sessionEnv, func(o *controller.SessionsOptions) { o.Version, o.RevLog = "0.1.0", r.log })
	r.revoker = controller.Revoker{Sessions: r.sessions, Log: r.log}
	return r, res
}

// people are the users of a restore test, managed through the accounts package as the API does.
type people struct {
	acc               *accounts.Accounts
	members           *accounts.Members
	tokens            *accounts.Tokens
	mfa               *accounts.MFA
	web               *websession.Sessions
	owner, bob, carol string
}

func newPeople(t *testing.T, x *restoreEnv) *people {
	t.Helper()
	ctx := context.Background()
	p := rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_LOW_MEMORY
	if _, err := settings.UpdateInstance(x.sys, x.db, &rpmgrv1.InstanceSettings{PasswordHashProfile: &p},
		&fieldmaskpb.FieldMask{Paths: []string{"password_hash_profile"}}, 0); err != nil {
		t.Fatal(err)
	}
	acc := accounts.New(x.db, x.sys, nil)
	acc.ResetLog = x.log
	ps := &people{acc: acc, members: &accounts.Members{Accounts: acc, RevLog: x.log}, tokens: &accounts.Tokens{Accounts: acc, RevLog: x.log},
		mfa: &accounts.MFA{Accounts: acc, Sealer: x.sealer, RevLog: x.log}, web: websession.New(websession.Options{DB: x.db, Sys: x.sys, RevLog: x.log})}
	link, err := acc.FirstUserLink("local-cli")
	if err != nil {
		t.Fatal(err)
	}
	u, err := acc.CompleteReset(ctx, link, restorePW, "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	ps.owner = u.ID
	ps.bob = ps.join(t, x.org, "bob@example.com")
	ps.carol = ps.join(t, x.org, "carol@example.com")
	return ps
}

func (ps *people) join(t *testing.T, org, email string) string {
	t.Helper()
	tok, err := ps.members.Invite(context.Background(), org, email, authz.RoleAdmin, ps.owner, authz.RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := ps.members.AcceptInvitation(context.Background(), tok, "", "Someone", restorePW)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// TestRestore_RevocationsReapplied: after restoring a backup taken before a certificate
// revocation, an API-token revocation, a member removal, a role downgrade and a password change,
// all stay in effect, read from the revocation log; so does the revocation of a certificate issued
// after the backup, which the restored database does not hold. Every session and every one-time
// credential of the backup that could still be used is invalidated. Restoring the same backup twice
// yields two different db_epochs.
func TestRestore_RevocationsReapplied(t *testing.T) {
	ctx := context.Background()
	x := startRestoreEnv(t, storetest.Migrated(t, store.SQLite))
	ps := newPeople(t, x)
	_, apiTok, err := ps.tokens.Create(ctx, x.org, ps.owner, "ci", []string{authz.PermOrgRead}, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	leaked := x.certAt(t, x.newIdentity(), time.Now().Add(-time.Hour))
	webTok, _, err := ps.web.Create(ps.owner, []string{"pwd"}, "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	resetTok, err := ps.acc.ResetLink(ps.bob, ps.owner)
	if err != nil {
		t.Fatal(err)
	}
	inviteTok, err := ps.members.Invite(ctx, x.org, "dave@example.com", authz.RoleViewer, ps.owner, authz.RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	enrollTok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	x.db.Client().EnrollmentToken.Create().SetOrgID(x.org).SetTokenHash(token.Hash(enrollTok)).SetRole("connector").
		SetExpiresAt(time.Now().Add(time.Hour)).SetCreatedBy(ps.owner).ExecX(x.sys)
	archive := x.backup(t)

	// After the backup.
	serial := pki.SerialHex(leaked.Leaf.SerialNumber)
	if err := x.revoker.RevokeCertificate(x.sys, serial, "key leaked", admin); err != nil {
		t.Fatal(err)
	}
	late := x.certAt(t, x.newIdentity(), time.Now().Add(-time.Minute))
	lateSerial := pki.SerialHex(late.Leaf.SerialNumber)
	if err := x.revoker.RevokeCertificate(x.sys, lateSerial, "host lost", admin); err != nil {
		t.Fatal(err)
	}
	if err := ps.tokens.Revoke(ctx, x.org, ps.owner, apiTok.ID); err != nil {
		t.Fatal(err)
	}
	if err := ps.members.Remove(ctx, x.org, ps.bob, ps.owner, authz.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := ps.members.SetRole(ctx, x.org, ps.carol, authz.RoleViewer, ps.owner, authz.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := ps.mfa.ChangePassword(ctx, ps.owner, restorePW, changedPW); err != nil {
		t.Fatal(err)
	}

	r, res := x.restore(t, archive)
	if res.NewEpoch == "" || res.NewEpoch == res.OldEpoch || res.OldEpoch != x.dbEpoch || res.TrustDomain != x.ca.TrustDomain() {
		t.Errorf("result %+v; the backup's epoch was %s", res, x.dbEpoch)
	}
	if len(res.Review) > 0 {
		t.Errorf("a complete log failed closed: %v", res.Review)
	}
	if res.Reapplied != 6 || res.Unknown != 1 {
		t.Errorf("%d entries applied again, %d unknown; want 6 and 1 (the certificate issued after the backup)", res.Reapplied, res.Unknown)
	}
	checkRestored(t, r, ps, leaked, late, apiTok.ID)
	if _, err := os.Stat(x.db.Path + res.Previous); err != nil {
		t.Errorf("the replaced database: %v", err)
	}
	if n := r.db.Client().AuditEntry.Query().Where(auditentry.Action("instance.restore")).CountX(r.sys); n != 1 {
		t.Errorf("%d audit entries of the restore", n)
	}
	stale := accounts.New(r.db, r.sys, nil)
	if _, err := stale.CompleteReset(ctx, resetTok, changedPW, "", ""); !errors.Is(err, accounts.ErrLink) {
		t.Errorf("a reset link of the backup: %v", err)
	}
	if _, _, err := (&accounts.Members{Accounts: stale}).AcceptInvitation(ctx, inviteTok, "", "Dave", restorePW); err == nil {
		t.Error("an invitation of the backup was accepted")
	}
	if _, err := websession.New(websession.Options{DB: r.db, Sys: r.sys, RevLog: r.log}).Lookup(webTok); !errors.Is(err, websession.ErrNoSession) {
		t.Errorf("a web session of the backup: %v", err)
	}
	if tok := r.db.Client().EnrollmentToken.Query().OnlyX(r.sys); tok.RevokedAt == nil {
		t.Error("an enrollment token of the backup is still usable")
	}

	// The restored log holds the backup's entries and those applied again; a second restore of
	// the same backup finds them there and yields another epoch.
	logged, err := revlog.Read(x.logPath)
	if err != nil {
		t.Fatal(err)
	}
	r2, res2 := r.restore(t, archive)
	if res2.NewEpoch == res.NewEpoch || res2.NewEpoch == res.OldEpoch || res2.Reapplied != 6 {
		t.Errorf("the second restore: %+v", res2)
	}
	checkRestored(t, r2, ps, leaked, late, apiTok.ID)
	if again, _ := revlog.Read(x.logPath); len(again) != len(logged) {
		t.Errorf("the log after the second restore holds %d entries, after the first %d", len(again), len(logged))
	}
}

// checkRestored checks that every revocation of TestRestore_RevocationsReapplied is in effect on r.
func checkRestored(t *testing.T, r *restoreEnv, ps *people, leaked, late tls.Certificate, apiTok string) {
	t.Helper()
	c := r.db.Client()
	for name, cert := range map[string]tls.Certificate{"the revoked certificate": leaked, "the certificate issued after the backup": late} {
		if err := pki.CheckRenewable(r.sys, c, cert.Leaf); !errors.Is(err, pki.ErrCertRevoked) {
			t.Errorf("%s: %v", name, err)
		}
		cc, _ := r.dial(t, cert, "controller."+r.ca.TrustDomain(), false)
		st, err := agentv1.NewControlClient(cc).Session(testCtx(t))
		if err == nil {
			_, err = st.Recv()
		}
		if code(err) != codes.Unavailable {
			t.Errorf("%s opens a control session: %v", name, err)
		}
	}
	serial, lateSerial := pki.SerialHex(leaked.Leaf.SerialNumber), pki.SerialHex(late.Leaf.SerialNumber)
	deny, err := pki.DenyList(r.sys, c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, d := range deny {
		listed[d.GetSerial()] = true
	}
	if !listed[serial] || !listed[lateSerial] {
		t.Errorf("deny-list %v", deny)
	}
	if tok := c.APIToken.GetX(r.sys, apiTok); tok.RevokedAt == nil {
		t.Error("the revoked API token is usable again")
	}
	if c.Membership.Query().Where(membership.UserID(ps.bob)).ExistX(r.sys) {
		t.Error("the removed member is back")
	}
	if m := c.Membership.Query().Where(membership.UserID(ps.carol)).OnlyX(r.sys); m.Role != membership.RoleViewer {
		t.Errorf("the downgraded member is %s again", m.Role)
	}
	if u := c.User.GetX(r.sys, ps.owner); u.PasswordHash != nil {
		t.Error("the password of the backup, changed since, still works")
	}
	if all, live := c.Session.Query().CountX(r.sys), c.Session.Query().Where(entsession.RevokedAtIsNil()).CountX(r.sys); all == 0 || live > 0 {
		t.Errorf("%d of the backup's %d web sessions are live", live, all)
	}
}

// TestRestore_Refusals: a restore refuses while a controller runs and an archive that is not one,
// and leaves the database and the logs as they were. The sink and a replica's log together apply
// an entry they both hold once.
func TestRestore_Refusals(t *testing.T) {
	ctx := context.Background()
	x := startRestoreEnv(t, storetest.Migrated(t, store.SQLite))
	archive := x.backup(t)
	for _, id := range []string{"ses_after1", "ses_after2"} {
		if _, err := x.log.Append(revlog.Entry{Kind: revlog.SessionRevoked, Subject: id}); err != nil {
			t.Fatal(err)
		}
	}
	sink := revlog.Sink{Dir: t.TempDir()}
	if _, err := sink.Ship(x.logPath, "ctn_a"); err != nil {
		t.Fatal(err)
	}
	notArchive := filepath.Join(t.TempDir(), "x.backup")
	if err := os.WriteFile(notArchive, []byte("neither a tar file\nnor a log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(x.db.Path)
	restore := func(archive string, logs ...string) error {
		_, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: x.cfg, Archive: archive, RevocationLogs: logs})
		return err
	}
	if err := restore(notArchive); err == nil || !strings.Contains(err.Error(), "not a backup archive") {
		t.Errorf("not an archive: %v", err)
	}
	if err := restore(filepath.Join(t.TempDir(), "none")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing archive: %v", err)
	}
	running, err := store.OpenSQLite(ctx, x.db.Path, store.SQLiteOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := restore(archive); !errors.Is(err, controller.ErrControllerRunning) {
		t.Errorf("with a controller running: %v", err)
	}
	_ = running.Close()
	if after, _ := os.ReadFile(x.db.Path); string(after) != string(before) {
		t.Error("a refused restore changed the database")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(x.db.Path), "*.restoring*")); len(left) > 0 {
		t.Errorf("a refused restore left %v", left)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(x.db.Path), "*.before-restore-*")); len(left) > 0 {
		t.Errorf("a refused restore moved %v aside", left)
	}
	if _, res := x.restore(t, archive, sink.Dir, x.logPath); res.Reapplied != 2 || len(res.Review) > 0 {
		t.Errorf("the sink and the local log merged: %d entries applied again, review %v; want 2 and none", res.Reapplied, res.Review)
	}
}

// TestRestore_IncompleteLogFailsClosed (docs/12-testing-and-quality.md, "Security testing"): with
// a broken sink hash chain, an unreachable replica log, or no log since the backup at all, the
// restore fails closed: every API token is suspended, every session invalidated, every user must
// reset their password and set up their second factor again, and the instance and every org are
// in read-only restore review. Entries present only in a reachable replica's local log are merged
// and re-applied all the same.
func TestRestore_IncompleteLogFailsClosed(t *testing.T) {
	ctx := context.Background()
	x := startRestoreEnv(t, storetest.Migrated(t, store.SQLite))
	ps := newPeople(t, x)
	seed, _, err := ps.mfa.EnrollTOTP(ps.owner, "rpmgr test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ps.mfa.ConfirmTOTP(ps.owner, totp.Code(seed, totp.StepOf(time.Now()))); err != nil {
		t.Fatal(err)
	}
	keep, _, err := ps.tokens.Create(ctx, x.org, ps.owner, "kept", []string{authz.PermOrgRead}, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	_, gone, err := ps.tokens.Create(ctx, x.org, ps.owner, "gone", []string{authz.PermOrgRead}, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ps.web.Create(ps.carol, []string{"pwd"}, "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	archive := x.backup(t)

	// After the backup: a member removal reaches the sink, which then breaks; a token revocation
	// is only in the local log.
	if err := ps.members.Remove(ctx, x.org, ps.bob, ps.owner, authz.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := ps.members.SetRole(ctx, x.org, ps.carol, authz.RoleViewer, ps.owner, authz.RoleOwner); err != nil {
		t.Fatal(err)
	}
	broken := revlog.Sink{Dir: t.TempDir()}
	if _, err := broken.Ship(x.logPath, "ctn_a"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(broken.Dir, "1")); err != nil {
		t.Fatal(err)
	}
	if err := ps.tokens.Revoke(ctx, x.org, ps.owner, gone.ID); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		logs    func() []string
		applied bool // the local log was read
	}{
		{"a broken sink chain", func() []string { return []string{broken.Dir, x.logPath} }, true},
		{"an unreachable replica log", func() []string { return []string{x.logPath, filepath.Join(t.TempDir(), "replica-b.log")} }, true},
		{"no log since the backup", func() []string {
			if err := os.Rename(x.logPath, x.logPath+".lost"); err != nil {
				t.Fatal(err)
			}
			return nil
		}, false},
	} {
		r, res := x.restore(t, archive, tc.logs()...)
		if len(res.Review) == 0 {
			t.Errorf("%s: the restore did not fail closed", tc.name)
			continue
		}
		c := r.db.Client()
		if inst := c.Instance.GetX(r.sys, 1); inst.RestoreReviewSince == nil {
			t.Errorf("%s: the instance is not in review", tc.name)
		}
		if n := c.Org.Query().Where(entorg.RestoreReviewSinceIsNil()).CountX(r.sys); n != 0 {
			t.Errorf("%s: %d orgs are not in review", tc.name, n)
		}
		if _, err := (&accounts.Tokens{Accounts: accounts.New(r.db, r.sys, nil)}).Authenticate(keep, "192.0.2.1"); !errors.Is(err, accounts.ErrToken) {
			t.Errorf("%s: an API token of the backup works: %v", tc.name, err)
		}
		if n := c.Session.Query().Where(entsession.RevokedAtIsNil()).CountX(r.sys); n != 0 {
			t.Errorf("%s: %d sessions are live", tc.name, n)
		}
		if n := c.User.Query().Where(user.PasswordHashNotNil()).CountX(r.sys); n != 0 {
			t.Errorf("%s: %d users keep their password", tc.name, n)
		}
		if c.TOTPCredential.Query().ExistX(r.sys) || c.RecoveryCode.Query().ExistX(r.sys) {
			t.Errorf("%s: a second factor of the backup is kept", tc.name)
		}
		if n := c.AuditEntry.Query().Where(auditentry.Action("instance.restore_review")).CountX(r.sys); n != 1 {
			t.Errorf("%s: %d audit entries of the review", tc.name, n)
		}
		// Merged from the reachable local log.
		removed := !c.Membership.Query().Where(membership.UserID(ps.bob)).ExistX(r.sys)
		revoked := c.APIToken.GetX(r.sys, gone.ID).RevokedAt != nil
		if tc.applied != (removed && revoked) {
			t.Errorf("%s: the local log's entries applied %v, member removed %v, token revoked %v", tc.name, tc.applied, removed, revoked)
		}
	}
}
