// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/apitoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/invitation"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
	entorg "github.com/felix-homelab/rpmgr/internal/store/ent/org"
	"github.com/felix-homelab/rpmgr/internal/store/ent/passwordreset"
	"github.com/felix-homelab/rpmgr/internal/store/ent/recoverycode"
	"github.com/felix-homelab/rpmgr/internal/store/ent/revokedidentity"
	"github.com/felix-homelab/rpmgr/internal/store/ent/revokedserial"
	entsession "github.com/felix-homelab/rpmgr/internal/store/ent/session"
	"github.com/felix-homelab/rpmgr/internal/store/ent/totpcredential"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
)

// RestoreOptions are the inputs of `rpmgr restore` (docs/10-operations.md, "Backup and
// restore").
type RestoreOptions struct {
	ConfigPath string // the controller's boot file, or all-in-one's
	Archive    string // the archive of `rpmgr backup`
	// RevocationLogs are where the revocations since the backup are: sink directories and local
	// revocations.log files. None means the state directory's revocations.log.
	RevocationLogs []string
	Now            func() time.Time
}

// RestoreResult is what a restore reports.
type RestoreResult struct {
	TrustDomain string
	Backup      time.Time // when the backup was taken
	OldEpoch    string    // the backup's
	NewEpoch    string
	Reapplied   int // revocation log entries newer than the backup, applied again
	// Unknown counts those of them whose subject the backup does not hold, as one created after
	// it; a revoked certificate or identity among them stays on the deny-list all the same.
	Unknown  int
	Previous string // the suffix of the replaced database and logs, which stay in the state directory
	// Review lists why the revocations since the backup may be incomplete. Then the restore failed
	// closed and the instance is in restore review.
	Review []string
}

// ErrControllerRunning is returned by Restore while a controller holds the database.
var ErrControllerRunning = errors.New("controller: a controller is running on this database; stop every controller before a restore")

type archive struct {
	info              BackupInfo
	db, revs, cpoints []byte
}

func readArchive(path string) (archive, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator's archive
	if err != nil {
		return archive{}, err
	}
	defer func() { _ = f.Close() }()
	var a archive
	seen := map[string]bool{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return archive{}, fmt.Errorf("controller: %s is not a backup archive: %w", path, err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return archive{}, err
		}
		seen[h.Name] = true
		switch h.Name {
		case BackupMeta:
			if err := json.Unmarshal(b, &a.info); err != nil {
				return archive{}, fmt.Errorf("controller: %s: %w", BackupMeta, err)
			}
		case BackupDatabase:
			a.db = b
		case BackupRevocations:
			a.revs = b
		case BackupCheckpoints:
			a.cpoints = b
		}
	}
	for _, name := range []string{BackupMeta, BackupDatabase, BackupRevocations, BackupCheckpoints} {
		if !seen[name] {
			return archive{}, fmt.Errorf("controller: %s is not a backup archive: no %s", path, name)
		}
	}
	if a.info.Format != 1 {
		return archive{}, fmt.Errorf("controller: backup format %d is not supported", a.info.Format)
	}
	return a, nil
}

// Restore is `rpmgr restore`: with every controller stopped, it puts the archive's database and
// logs in place, gives the instance a new db_epoch, invalidates every session and every one-time
// credential of the backup that can still be used, and applies again every revocation logged after
// the backup, merged from the given sinks and local logs (docs/10-operations.md, "Backup and
// restore"). When those revocations may be incomplete it fails closed into restore review. It
// prepares everything next to the database first and replaces nothing when a step fails; the
// replaced files are kept with the suffix RestoreResult.Previous. It is local administration,
// audited as local-cli.
func Restore(ctx context.Context, o RestoreOptions) (RestoreResult, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	cfg, err := loadController(o.ConfigPath)
	if err != nil {
		return RestoreResult{}, err
	}
	dsn := cfg.Database.DSN
	state := filepath.Dir(dsn)
	unlock, err := store.HoldLock(dsn)
	if errors.Is(err, store.ErrLocked) {
		return RestoreResult{}, ErrControllerRunning
	}
	if err != nil {
		return RestoreResult{}, err
	}
	defer func() { _ = unlock() }()
	a, err := readArchive(o.Archive)
	if err != nil {
		return RestoreResult{}, err
	}

	// Everything is staged next to the files it replaces, then renamed into place.
	files := []struct{ live, staged string }{
		{dsn, dsn + ".restoring"},
		{filepath.Join(state, BackupRevocations), filepath.Join(state, BackupRevocations+".restoring")},
		{filepath.Join(state, BackupCheckpoints), filepath.Join(state, BackupCheckpoints+".restoring")},
	}
	clean := func() {
		for _, f := range files {
			for _, s := range []string{"", "-wal", "-shm"} {
				_ = os.Remove(f.staged + s)
			}
		}
	}
	clean()
	defer clean()
	for i, b := range [][]byte{a.db, a.revs, a.cpoints} {
		if err := os.WriteFile(files[i].staged, b, 0o600); err != nil {
			return RestoreResult{}, err
		}
	}
	newer, review, err := sinceBackup(files[1].staged, files[1].live, o.RevocationLogs)
	if err != nil {
		return RestoreResult{}, err
	}
	res := RestoreResult{TrustDomain: a.info.TrustDomain, Backup: a.info.Created, OldEpoch: a.info.DBEpoch, Review: review}
	if err := prepare(ctx, files[0].staged, files[1].staged, a.info, newer, o.Now, &res); err != nil {
		return RestoreResult{}, err
	}

	res.Previous = ".before-restore-" + o.Now().UTC().Format("20060102T150405Z")
	for _, f := range files {
		for _, s := range []string{"", "-wal", "-shm"} {
			if err := os.Rename(f.live+s, f.live+s+res.Previous); err != nil && !errors.Is(err, os.ErrNotExist) {
				return RestoreResult{}, err
			}
		}
	}
	for _, f := range files {
		for _, s := range []string{"", "-wal", "-shm"} {
			if err := os.Rename(f.staged+s, f.live+s); err != nil && (s == "" || !errors.Is(err, os.ErrNotExist)) {
				return RestoreResult{}, fmt.Errorf("controller: putting the restored %s in place: %w; the replaced files end in %s",
					filepath.Base(f.live), err, res.Previous)
			}
		}
	}
	return res, ownLike(state, state)
}

// sinceBackup returns the entries of the given sinks and local logs that the backup's own log, at
// backupLog, does not hold, oldest first; without a source it reads the local log at local. It
// also returns why they may be incomplete: a source that cannot be read, has a broken chain or
// holds a kind this version does not know, or no source at all. Without a sink a single node's
// whole log is not off the host, so a lost local log is a backlog that cannot be reached.
func sinceBackup(backupLog, local string, sources []string) ([]revlog.Entry, []string, error) {
	before, err := revlog.Read(backupLog)
	if err != nil {
		return nil, nil, fmt.Errorf("controller: the backup's revocation log: %w", err)
	}
	known := map[string]bool{}
	for _, e := range before {
		known[e.Hash] = true
	}
	var newer []revlog.Entry
	var problems []string
	if len(sources) == 0 {
		if _, err := os.Stat(local); err != nil {
			problems = append(problems, "no revocation log since the backup: neither a sink nor the old host's revocations.log was given with --revocation-log")
		} else {
			sources = []string{local}
		}
	}
	for _, src := range sources {
		entries, err := readSource(src)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", src, err))
			continue
		}
		for _, e := range entries {
			if !e.Kind.Valid() {
				problems = append(problems, fmt.Sprintf("%s: entry %d has the unknown kind %q", src, e.Seq, e.Kind))
				continue
			}
			if !known[e.Hash] {
				known[e.Hash] = true
				newer = append(newer, e)
			}
		}
	}
	sort.SliceStable(newer, func(i, j int) bool { return newer[i].Time.Before(newer[j].Time) })
	return newer, problems, nil
}

// readSource reads a sink directory or a local log, verifying its chain.
func readSource(path string) ([]revlog.Entry, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return revlog.Read(path)
	}
	sink, err := revlog.Sink{Dir: path}.Read()
	if err != nil {
		return nil, err
	}
	out := make([]revlog.Entry, len(sink))
	for i, e := range sink {
		out[i] = e.Entry
	}
	return out, nil
}

// prepare brings the staged database up to date and secures it: migrations, a new epoch, the
// invalidations and the revocations since the backup, which also go into the staged log, and the
// restore review when res.Review says why they may be incomplete.
func prepare(ctx context.Context, dbPath, logPath string, info BackupInfo, newer []revlog.Entry, now func() time.Time, res *RestoreResult) error {
	db, err := store.OpenSQLite(ctx, dbPath, store.SQLiteOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	dir, err := migrations.Dir(store.SQLite)
	if err != nil {
		return err
	}
	if _, err := store.Migrate(ctx, db, dir); err != nil {
		return err
	}
	sys, err := authz.System(ctx, "local-cli", "rpmgr restore", audit.SystemScopes(db))
	if err != nil {
		return err
	}
	if res.NewEpoch, err = store.NewEpoch(sys, db); err != nil {
		return err
	}
	rl, err := revlog.Open(logPath, now)
	if err != nil {
		return err
	}
	err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
		if err := invalidate(sys, tx, now().UTC()); err != nil {
			return err
		}
		for _, e := range newer {
			known, err := reapply(sys, tx, info.TrustDomain, e)
			if err != nil {
				return fmt.Errorf("controller: applying %s %s again: %w", e.Kind, e.Subject, err)
			}
			res.Reapplied++
			if !known {
				res.Unknown++
			}
		}
		if len(res.Review) > 0 {
			if err := failClosed(sys, tx, now().UTC()); err != nil {
				return err
			}
			if _, err := audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "instance.restore_review",
				TargetType: "instance", TargetID: res.NewEpoch, Result: audit.Success, Reason: strings.Join(res.Review, "; ")}); err != nil {
				return err
			}
		}
		_, err := audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "instance.restore",
			TargetType: "instance", TargetID: res.NewEpoch, Result: audit.Success,
			Reason: fmt.Sprintf("backup of %s, epoch %s; %d revocations since applied again, %d of them to subjects the backup does not hold",
				info.Created.UTC().Format(time.RFC3339), info.DBEpoch, res.Reapplied, res.Unknown)})
		return err
	})
	if err != nil {
		return err
	}
	// The restored log holds them too, so that a later restore of an older backup finds them
	// without the sink.
	for _, e := range newer {
		e.Seq, e.Prev, e.Hash = 0, "", ""
		if _, err := rl.Append(e); err != nil {
			return err
		}
	}
	return nil
}

// failClosed is the restore review after a restore whose revocations since the backup may be
// incomplete (docs/10-operations.md, "Backup and restore"): every API token is suspended, every
// user must reset their password and set up their second factor again, and the instance and
// every org are read-only until they are confirmed. Sessions end anyway.
func failClosed(ctx context.Context, tx *ent.Tx, now time.Time) error {
	if err := tx.Instance.Update().SetRestoreReviewSince(now).Exec(ctx); err != nil {
		return err
	}
	if err := tx.Org.Update().SetRestoreReviewSince(now).Exec(ctx); err != nil {
		return err
	}
	if err := tx.APIToken.Update().Where(apitoken.RevokedAtIsNil(), apitoken.SuspendedAtIsNil()).SetSuspendedAt(now).Exec(ctx); err != nil {
		return err
	}
	if err := tx.User.Update().ClearPasswordHash().Exec(ctx); err != nil {
		return err
	}
	if _, err := tx.TOTPCredential.Delete().Exec(ctx); err != nil {
		return err
	}
	_, err := tx.RecoveryCode.Delete().Exec(ctx)
	return err
}

// invalidate ends every session and every one-time credential of the backup that can still be
// used: a token consumed after the backup would otherwise be usable again (docs/10-operations.md,
// "Backup and restore").
func invalidate(ctx context.Context, tx *ent.Tx, now time.Time) error {
	if err := tx.Session.Update().Where(entsession.RevokedAtIsNil()).SetRevokedAt(now).Exec(ctx); err != nil {
		return err
	}
	if err := tx.EnrollmentToken.Update().Where(enrollmenttoken.RevokedAtIsNil()).SetRevokedAt(now).Exec(ctx); err != nil {
		return err
	}
	if err := tx.PasswordReset.Update().Where(passwordreset.UsedAtIsNil()).SetUsedAt(now).Exec(ctx); err != nil {
		return err
	}
	_, err := tx.Invitation.Delete().Where(invitation.AcceptedAtIsNil()).Exec(ctx)
	return err
}

// reapply applies one revocation again, with its original time and reason; known reports whether
// the backup holds its subject.
func reapply(ctx context.Context, tx *ent.Tx, td string, e revlog.Entry) (bool, error) {
	switch e.Kind {
	case revlog.CertificateRevoked:
		_, _, err := pki.RevokeCertificate(ctx, tx, e.Subject, e.Detail, e.Time)
		if !errors.Is(err, pki.ErrNotIssued) {
			return true, err
		}
		return false, denySerial(ctx, tx, e)
	case revlog.IdentityRevoked:
		return reapplyIdentity(ctx, tx, td, e)
	case revlog.CertificateSuperseded:
		n, err := tx.IssuedCertificate.Update().Where(issuedcertificate.ID(e.Subject), issuedcertificate.SupersededAtIsNil()).
			SetSupersededAt(e.Time).Save(ctx)
		return n > 0, err
	case revlog.APITokenRevoked:
		n, err := tx.APIToken.Update().Where(apitoken.ID(e.Subject), apitoken.RevokedAtIsNil()).SetRevokedAt(e.Time).Save(ctx)
		return n > 0, err
	case revlog.MemberRemoved:
		n, err := tx.Membership.Delete().Where(membership.OrgID(e.Org), membership.UserID(e.Subject)).Exec(ctx)
		return n > 0, err
	case revlog.RoleDowngraded:
		return downgrade(ctx, tx, e.Org, e.Subject, membership.Role(e.Detail))
	case revlog.CredentialSuperseded:
		return supersede(ctx, tx, e.Subject, e.Detail)
	case revlog.SessionRevoked, revlog.GrantRemoved:
		return true, nil // every session ends anyway; grants come with Phase 3
	}
	return false, fmt.Errorf("unknown kind %q", e.Kind)
}

// denySerial keeps a certificate that the backup does not hold, revoked after it, on the deny-list
// until it expires.
func denySerial(ctx context.Context, tx *ent.Tx, e revlog.Entry) error {
	if done, err := tx.RevokedSerial.Query().Where(revokedserial.ID(e.Subject)).Exist(ctx); err != nil || done {
		return err
	}
	notAfter := e.Time.Add(pki.MaxLeafLifetime)
	if e.NotAfter != nil {
		notAfter = *e.NotAfter
	}
	create := tx.RevokedSerial.Create().SetID(e.Subject).SetRevokedAt(e.Time).SetReason(e.Detail).SetNotAfter(notAfter)
	ok, err := orgExists(ctx, tx, e.Org)
	if err != nil {
		return err
	}
	if ok && e.Org != "" {
		create.SetOrgID(e.Org)
	}
	return create.Exec(ctx)
}

// reapplyIdentity revokes an identity again. One of an org the backup does not hold is revoked
// without the org, so that it stays denied; the deny-list keeps it at least as long as the log
// says.
func reapplyIdentity(ctx context.Context, tx *ent.Tx, td string, e revlog.Entry) (bool, error) {
	u, err := url.Parse(e.Subject)
	if err != nil {
		return false, err
	}
	id, err := pki.ParseSPIFFE(u, td)
	if err != nil {
		return false, err
	}
	known, err := orgExists(ctx, tx, id.Org)
	if err != nil {
		return false, err
	}
	if !known {
		id.Org = ""
	}
	if _, _, err := pki.RevokeIdentity(ctx, tx, id, e.Detail, e.Time); err != nil {
		return false, err
	}
	if e.NotAfter != nil {
		if err := tx.RevokedIdentity.Update().Where(revokedidentity.ID(id.String()), revokedidentity.NotAfterLT(*e.NotAfter)).
			SetNotAfter(*e.NotAfter).Exec(ctx); err != nil {
			return false, err
		}
	}
	return known, nil
}

// orgExists reports whether the org id exists; no org, as of a controller, counts as existing.
func orgExists(ctx context.Context, tx *ent.Tx, id string) (bool, error) {
	if id == "" {
		return true, nil
	}
	return tx.Org.Query().Where(entorg.ID(id)).Exist(ctx)
}

// roleRank orders the roles: a downgrade applied again never raises a role.
var roleRank = map[membership.Role]int{membership.RoleViewer: 1, membership.RoleOperator: 2, membership.RoleAdmin: 3, membership.RoleOwner: 4}

func downgrade(ctx context.Context, tx *ent.Tx, org, userID string, role membership.Role) (bool, error) {
	if roleRank[role] == 0 {
		return false, fmt.Errorf("unknown role %q", role)
	}
	m, err := tx.Membership.Query().Where(membership.OrgID(org), membership.UserID(userID)).Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if roleRank[role] < roleRank[m.Role] {
		err = tx.Membership.UpdateOne(m).SetRole(role).Exec(ctx)
	}
	return true, err
}

// supersede undoes a credential that the backup holds but that was replaced after it, because the
// backup's may be the very one that was compromised: a password must be reset, an authenticator
// and recovery codes set up again. A Detail naming something else supersedes all three.
func supersede(ctx context.Context, tx *ent.Tx, userID, what string) (bool, error) {
	if ok, err := tx.User.Query().Where(user.ID(userID)).Exist(ctx); err != nil || !ok {
		return false, err
	}
	all := what != revlog.Password && what != revlog.MFA && what != revlog.RecoveryCodes
	if what == revlog.Password || all {
		if err := tx.User.UpdateOneID(userID).ClearPasswordHash().Exec(ctx); err != nil {
			return true, err
		}
	}
	if what == revlog.MFA || all {
		if _, err := tx.TOTPCredential.Delete().Where(totpcredential.UserID(userID)).Exec(ctx); err != nil {
			return true, err
		}
	}
	if what != revlog.Password {
		if _, err := tx.RecoveryCode.Delete().Where(recoverycode.UserID(userID)).Exec(ctx); err != nil {
			return true, err
		}
	}
	return true, nil
}
