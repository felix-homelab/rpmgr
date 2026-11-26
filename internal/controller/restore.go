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
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/dns/apply"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
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
	// StageDir is where the restore does its SQLite work: a directory the caller owns with mode 0700,
	// which no other user can write. Empty means a new private directory under the temporary one.
	StageDir string
	// RevocationLogs are where the revocations since the backup are: sink directories and local
	// revocations.log files. None means the state directory's revocations.log.
	RevocationLogs []string
	// DNSDisabled sets every managed DNS zone to disabled, for a copy that must never touch
	// production DNS (docs/15-dns.md, "Held zones and plan approval"). Otherwise every zone starts
	// held.
	DNSDisabled bool
	// Replaces names the database that the restored one takes the place of, a boot file or a SQLite
	// file, when the boot file names a new PostgreSQL database: the controller lock is per
	// database, so only this tells the restore whether a controller still runs on the old one. The
	// restore takes its lock exclusively, refusing while a controller holds it, and does nothing
	// else to it. Without it the operator has stopped every controller. It has no use on SQLite,
	// where the restore replaces the database in place.
	Replaces string
	Getenv   func(string) string // default os.Getenv
	Now      func() time.Time
}

// RestoreResult is what a restore reports.
type RestoreResult struct {
	Dialect     string // the restored database's engine, sqlite or postgres
	TrustDomain string
	Backup      time.Time // when the backup was taken
	OldEpoch    string    // the backup's
	NewEpoch    string
	Reapplied   int // revocation log entries newer than the backup, applied again
	DNSZones    int // managed DNS zones, all held, or with RestoreOptions.DNSDisabled all disabled
	// Unknown counts those of them whose subject the backup does not hold, as one created after
	// it; a revoked certificate or identity among them stays on the deny-list all the same.
	Unknown  int
	Previous string // the suffix of the replaced logs, and on SQLite database, which stay in the state directory
	// Review lists why the revocations since the backup may be incomplete. Then the restore failed
	// closed and the instance is in restore review.
	Review []string
	// Kept lists the revocations since the backup not applied again, because the restored instance
	// would have no active Instance Admin without them; the Instance Admin checks them.
	Kept []string
	// RootKeysDropped lists the roots, by the SHA-256 of their public key, that the archive still
	// held the key of and the restore took offline again, as the revocation log's `root_offline`
	// marker says (docs/04-security.md, "Offline root CA").
	RootKeysDropped []string
	// ReplacesRetired is where `migrate-db` moved the database named by RestoreOptions.Replaces, when
	// it did: its controller is not the one the restore replaces.
	ReplacesRetired string
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
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	d, err := bootDatabase(o.ConfigPath)
	if err != nil {
		return RestoreResult{}, err
	}
	dsn := d.DSN
	state := stateDir(d)
	if o.Replaces != "" && d.Driver != "postgres" {
		return RestoreResult{}, ErrReplacesNeedsPostgres
	}
	if d.Driver == "postgres" && len(o.RevocationLogs) == 0 {
		return RestoreResult{}, ErrRevocationLogNeeded
	}
	var res RestoreResult
	var pg *store.DB
	locked := []*store.DB{} // the PostgreSQL databases whose controller lock the restore holds
	if d.Driver == "postgres" {
		// The controller lock of the target database, exclusive, held to the end: a controller, which
		// holds it shared or exclusive, makes the restore refuse.
		pg, err = store.OpenPostgres(ctx, dsn, store.PostgresOptions{
			PasswordFile: d.PasswordFile, PasswordCredential: d.PasswordCredential, Getenv: o.Getenv, Lock: true})
		if errors.Is(err, store.ErrLocked) {
			return RestoreResult{}, ErrControllerRunning
		}
		if err != nil {
			return RestoreResult{}, err
		}
		defer func() { _ = pg.Close() }()
		locked = append(locked, pg)
		if o.Replaces != "" {
			release, old, retired, lerr := lockReplaced(ctx, o, d)
			if lerr != nil {
				return RestoreResult{}, lerr
			}
			defer release()
			res.ReplacesRetired = retired
			if old != nil {
				locked = append(locked, old)
			}
		}
	} else {
		unlock, err := store.HoldLockNoFollow(dsn)
		if errors.Is(err, store.ErrLocked) {
			return RestoreResult{}, ErrControllerRunning
		}
		if err != nil {
			return RestoreResult{}, err
		}
		defer func() { _ = unlock() }()
	}
	a, err := readArchive(o.Archive)
	if err != nil {
		return RestoreResult{}, err
	}

	// The state directory belongs to the service user, which a restore run by root must not let
	// steer it: every SQLite operation and every read of a file the user controls happens in a
	// private staging directory only the caller can write, and only finished files go into the state
	// directory, through a root handle (os.Root) that follows no link out of it, never by path.
	root, err := os.OpenRoot(state)
	if err != nil {
		return RestoreResult{}, err
	}
	defer func() { _ = root.Close() }()
	// Files of the state directory that the restore replaces. A SQLite database is the first of
	// them, with its journal files; a PostgreSQL database is not a file, so the restored one is
	// staged under the archive's name and filled in through the copier.
	live := []string{BackupRevocations, BackupCheckpoints}
	staged0 := BackupDatabase
	hasFile := d.Driver != "postgres"
	if hasFile {
		live = append([]string{filepath.Base(dsn)}, live...)
		staged0 = live[0]
	}
	stage, done, err := stagingDir(o.StageDir, append([]string{staged0}, live...)...)
	if err != nil {
		return RestoreResult{}, err
	}
	defer done()
	suffixes := func(i int) []string {
		if i == 0 && hasFile {
			return []string{"", "-wal", "-shm"}
		}
		return []string{""}
	}
	var names []string
	for i, n := range live {
		for _, s := range suffixes(i) {
			names = append(names, n+s)
		}
	}
	if err := refuseLinks(root, names...); err != nil {
		return RestoreResult{}, err
	}
	staged := func(name string) string { return filepath.Join(stage, name) }
	for n, b := range map[string][]byte{staged0: a.db, BackupRevocations: a.revs, BackupCheckpoints: a.cpoints} {
		if err := stageFile(staged(n), b); err != nil {
			return RestoreResult{}, err
		}
	}
	// The local revocation log is read through the root, into the staging directory.
	if err := copyFrom(root, BackupRevocations, staged(localLog)); err != nil {
		return RestoreResult{}, err
	}
	hook("staged")
	newer, review, err := sinceBackup(staged(BackupRevocations), staged(localLog), o.RevocationLogs)
	if err != nil {
		return RestoreResult{}, err
	}
	res.Dialect, res.TrustDomain, res.Backup, res.OldEpoch, res.Review = dialectOf(d), a.info.TrustDomain, a.info.Created, a.info.DBEpoch, review
	if err := prepare(ctx, staged(staged0), staged(BackupRevocations), a.info, newer, o.Now, o.DNSDisabled, &res); err != nil {
		return RestoreResult{}, err
	}

	// The finished files are copied into temporary names inside the root, then the live ones are
	// moved aside and the copies renamed into place: nothing is replaced when a copy fails.
	type move struct{ tmp, live string }
	var moves []move
	defer func() {
		for _, m := range moves {
			_ = root.Remove(m.tmp)
		}
	}()
	for i, n := range live {
		for _, s := range suffixes(i) {
			if _, err := os.Lstat(staged(n + s)); err != nil {
				if errors.Is(err, os.ErrNotExist) && s != "" {
					continue
				}
				return RestoreResult{}, err
			}
			hook("copying")
			tmp := ".restoring-" + n + s
			if err := copyInto(root, staged(n+s), tmp); err != nil {
				return RestoreResult{}, err
			}
			moves = append(moves, move{tmp, n + s})
		}
	}
	if res.Previous, err = freeSuffix(root, names, o.Now()); err != nil {
		return RestoreResult{}, err
	}
	hook("moving")
	var aside [][2]string
	putBack := func() {
		for i := len(aside) - 1; i >= 0; i-- {
			_ = root.Rename(aside[i][1], aside[i][0])
		}
	}
	for i, n := range live {
		for _, s := range suffixes(i) {
			if err := root.Rename(n+s, n+s+res.Previous); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if pg != nil {
					putBack()
				}
				return RestoreResult{}, err
			}
			aside = append(aside, [2]string{n + s, n + s + res.Previous})
		}
	}
	if pg != nil {
		// Everything is ready and the live files are out of the way: the copier fills the empty
		// database in one transaction, or leaves it as it was, and then the files go back.
		if err := restorePostgres(ctx, locked, pg, staged(staged0)); err != nil {
			putBack()
			return RestoreResult{}, err
		}
	}
	hook("installing")
	for i, m := range moves {
		if err := root.Rename(m.tmp, m.live); err != nil {
			if pg != nil {
				// The database holds the restore now: what is left stays, for the operator to place.
				var left []string
				for _, r := range moves[i:] {
					left = append(left, r.tmp+" as "+r.live)
				}
				moves = nil
				return RestoreResult{}, fmt.Errorf("controller: the PostgreSQL database holds the restore (epoch %s), but putting %s in place failed: %w; "+
					"in %s, move %s into place by hand; the replaced files end in %s", res.NewEpoch, m.live, err, state, strings.Join(left, ", "), res.Previous)
			}
			return RestoreResult{}, fmt.Errorf("controller: putting the restored %s in place: %w; the replaced files end in %s",
				m.live, err, res.Previous)
		}
	}
	moves = nil
	return res, ownLike(state, state)
}

// Errors of Restore for options that do not fit the boot file's database.
var (
	// ErrReplacesNeedsPostgres is returned for --replaces with a SQLite boot file, which restores in
	// place and has no other database to replace.
	ErrReplacesNeedsPostgres = errors.New("controller: --replaces is for a restore into a new PostgreSQL database; a SQLite restore replaces the database in place")
	// ErrRevocationLogNeeded is returned for a restore into PostgreSQL without --revocation-log: the
	// host's own log says nothing of what other controllers on that database revoked.
	ErrRevocationLogNeeded = errors.New("controller: a restore into PostgreSQL needs --revocation-log, the sink directory or every controller's revocations.log")
)

// freeSuffix returns the suffix of the replaced files, made of the time, with a number added when a
// replaced file of that name exists already, so that nothing is ever overwritten.
func freeSuffix(root *os.Root, names []string, now time.Time) (string, error) {
	base := ".before-restore-" + now.UTC().Format("20060102T150405Z")
	for i := 0; ; i++ {
		suffix := base
		if i > 0 {
			suffix = fmt.Sprintf("%s-%d", base, i)
		}
		free := true
		for _, n := range names {
			if _, err := root.Lstat(n + suffix); err == nil {
				free = false
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
		}
		if free {
			return suffix, nil
		}
	}
}

// lockReplaced takes the controller lock of the database that the restore replaces, exclusively,
// until release is called: a controller on it, or a replica, makes the restore refuse. For a
// PostgreSQL database it returns the open database, which the caller watches for a lost lock, and
// where `migrate-db` moved it, if it did. A SQLite file is locked by its name without following
// links, and is refused if it is no plain file. The database it names is never the target.
func lockReplaced(ctx context.Context, o RestoreOptions, target config.Database) (release func(), db *store.DB, retired string, err error) {
	old, err := endpoint(o.Replaces)
	if err != nil {
		return nil, nil, "", err
	}
	if sameDatabase(old, target) {
		return nil, nil, "", fmt.Errorf("%w: --replaces names the database the restore fills", ErrSameDatabase)
	}
	running := func() error {
		hint := ""
		if old.Driver == target.Driver {
			hint = "; --replaces may name the target under another name"
		}
		return fmt.Errorf("%w (the database --replaces names%s)", ErrControllerRunning, hint)
	}
	if old.Driver != "postgres" {
		if err := refuseLinked(old.DSN, true); err != nil {
			return nil, nil, "", err
		}
		unlock, err := store.HoldLockNoFollow(old.DSN)
		if errors.Is(err, store.ErrLocked) {
			return nil, nil, "", running()
		}
		if err != nil {
			return nil, nil, "", err
		}
		return func() { _ = unlock() }, nil, "", nil
	}
	db, err = openMigrateEnd(ctx, old, o.Getenv, false)
	if errors.Is(err, ErrStopController) {
		return nil, nil, "", running()
	}
	if err != nil {
		return nil, nil, "", fmt.Errorf("controller: the database --replaces names: %w", err)
	}
	release = func() { _ = db.Close() }
	inst, err := db.ReadClient().Instance.Query().Only(migrateScope(ctx))
	if err != nil || inst.RetiredAt == nil { // no installation to read, or one that is not retired
		return release, db, "", nil
	}
	if inst.RetiredTo == nil {
		return release, db, "an unknown boot file", nil
	}
	return release, db, *inst.RetiredTo, nil
}

// restorePostgres copies the prepared SQLite database at path into the empty, migrated PostgreSQL
// database pg, which the caller holds the controller lock of, in one transaction. A target that
// holds a row is refused (store.ErrTargetNotEmpty) and one at another schema version is refused
// (store.ErrSchemaMismatch); either way the target is left as it was.
func restorePostgres(ctx context.Context, locked []*store.DB, pg *store.DB, path string) error {
	if err := migrateEmptyTarget(ctx, pg); err != nil {
		return fmt.Errorf("controller: the target database: %w", err)
	}
	src, err := store.OpenSQLite(ctx, path, store.SQLiteOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	hook("copying to postgres")
	copyCtx, cancel := untilLost(ctx, locked...)
	defer cancel(nil)
	if _, err := store.CopyDatabase(copyCtx, src, pg, store.CopyOptions{}); err != nil {
		return errors.Join(fmt.Errorf("controller: restoring into PostgreSQL: %w", err), context.Cause(copyCtx))
	}
	return nil
}

// localLog is the name, in the staging directory, of the state directory's revocation log as it was
// when the restore began.
const localLog = "local-" + BackupRevocations

// restoreHook, if set, runs at the steps of Restore, "staged", "copying", "copying to postgres"
// (only there), "moving" and "installing": a test plants a link there, as the service user could.
var restoreHook func(step string)

func hook(step string) {
	if restoreHook != nil {
		restoreHook(step)
	}
}

// stagingDir returns the directory in which a restore does its SQLite work: dir, which the caller
// must own and no one else may write (the root updater passes /var/lib/rpmgr-update/restore), or a
// new private one under the temporary directory. The files a restore stages are removed from it
// at the start and at the end.
func stagingDir(dir string, files ...string) (string, func(), error) {
	remove := func(d string) {
		for _, n := range append([]string{localLog}, files...) {
			for _, s := range []string{"", "-wal", "-shm", "-journal"} {
				_ = os.Remove(filepath.Join(d, n+s))
			}
		}
	}
	if dir == "" {
		d, err := os.MkdirTemp("", "rpmgr-restore-")
		if err != nil {
			return "", nil, err
		}
		return d, func() { remove(d); _ = os.Remove(d) }, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", nil, err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 || !ownedByCaller(fi) {
		return "", nil, fmt.Errorf("controller: the staging directory %s must be a directory of mode 0700 that the caller owns", dir)
	}
	remove(dir)
	return dir, func() { remove(dir) }, nil
}

// stageFile creates path, which must not exist, in the private staging directory.
func stageFile(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the private staging directory
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// copyFrom copies name of root to path, if it exists; a file that does not is no error.
func copyFrom(root *os.Root, name, path string) error {
	in, err := root.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the private staging directory
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// copyInto copies the file at path, in the private staging directory, to the new file name of root,
// mode 0600; a name that exists, such as a link planted there, is replaced only by removing it first
// and creating the new file exclusively, never by writing through it.
func copyInto(root *os.Root, path, name string) error {
	if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	in, err := os.Open(path) //nolint:gosec // G304: the private staging directory
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// ErrUnsafeStateFile is returned for a file of the state directory that is no regular file, such as
// a link planted by the service user, which a restore or backup run by root would follow.
var ErrUnsafeStateFile = errors.New("controller: a file of the state directory is no regular file")

// refuseLinks refuses any of names in root that exists and is not a regular file.
func refuseLinks(root *os.Root, names ...string) error {
	for _, n := range names {
		if fi, err := root.Lstat(n); err == nil && !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: %s", ErrUnsafeStateFile, n)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
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
	sink, err := revlog.NewSink(revlog.DirBackend{Dir: path}).Read()
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
func prepare(ctx context.Context, dbPath, logPath string, info BackupInfo, newer []revlog.Entry, now func() time.Time, dnsDisabled bool, res *RestoreResult) error {
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
	// A database that `migrate-db` retired is no controller's, and one restored from it would refuse to
	// start: only an archive of the controller that runs now can be restored.
	if inst, err := db.Client().Instance.Get(sys, 1); err == nil && inst.RetiredAt != nil {
		return fmt.Errorf("%w: the archive holds a database retired %s; restore an archive of the controller that runs now",
			ErrRetired, inst.RetiredAt.UTC().Format(time.RFC3339))
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
		// The zones are held for review, or disabled: what the backup held is not what the provider
		// holds now (docs/15-dns.md, "Held zones and plan approval").
		n, err := apply.HoldAll(sys, tx, dnsDisabled)
		if err != nil {
			return err
		}
		res.DNSZones = n
		// The archive's own log may hold a marker its database does not show: a backup's snapshot of
		// the database can precede the commit that nulled the key, while its copy of the log, taken
		// after, holds the marker. Applying a marker again is harmless.
		own, err := revlog.Read(logPath)
		if err != nil {
			return err
		}
		for _, e := range own {
			if e.Kind != revlog.RootOffline {
				continue
			}
			if _, err := reapply(sys, tx, info.TrustDomain, e); errors.Is(err, errDroppedRootKey) {
				res.RootKeysDropped = append(res.RootKeysDropped, e.Subject)
			} else if err != nil {
				return fmt.Errorf("controller: applying %s %s again: %w", e.Kind, e.Subject, err)
			}
		}
		for _, e := range newer {
			known, err := reapply(sys, tx, info.TrustDomain, e)
			if errors.Is(err, errKeptInstanceAdmin) {
				res.Kept = append(res.Kept, fmt.Sprintf("the Instance Admin role of %s, revoked %s, stays: the backup has no other active Instance Admin",
					e.Subject, e.Time.UTC().Format(time.RFC3339)))
				err = nil
			}
			if errors.Is(err, errDroppedRootKey) {
				res.RootKeysDropped = append(res.RootKeysDropped, e.Subject)
				err = nil
			}
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
		_, err = audit.Append(sys, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "instance.restore",
			TargetType: "instance", TargetID: res.NewEpoch, Result: audit.Success,
			Reason: fmt.Sprintf("backup of %s, epoch %s; %d revocations since applied again, %d of them to subjects the backup does not hold%s; %d dns zones %s",
				info.Created.UTC().Format(time.RFC3339), info.DBEpoch, res.Reapplied, res.Unknown, keptReason(res.Kept)+droppedReason(res.RootKeysDropped), res.DNSZones, dnsState(dnsDisabled))})
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

func dnsState(disabled bool) string {
	if disabled {
		return "disabled"
	}
	return "held"
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
		_, _, err := castore.RevokeCertificate(ctx, tx, e.Subject, e.Detail, e.Time)
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
	case revlog.InstanceAdminRevoked:
		return revokeInstanceAdmin(ctx, tx, e.Subject)
	case revlog.CredentialSuperseded:
		return supersede(ctx, tx, e.Subject, e.Detail)
	case revlog.SessionRevoked, revlog.GrantRemoved:
		return true, nil // every session ends anyway; grants come with Phase 3
	case revlog.RootOffline:
		held, found, err := castore.ApplyRootOffline(ctx, tx, e.Subject)
		if err != nil || !found {
			return found, err
		}
		// The audit entry of the ceremony may be missing from the restored database, or have been
		// pruned: write it from the marker, so that `ca status` still knows the KEK to warn about.
		if _, err := audit.Append(ctx, tx, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: castore.RootActionOffline,
			TargetType: "ca", TargetID: e.Subject, Result: audit.Success, Diff: castore.RootOfflineDiff(e.Detail),
			Reason: "applied again by a restore from the revocation log's marker"}); err != nil {
			return false, err
		}
		if held {
			err = errDroppedRootKey
		}
		return true, err
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
	if _, _, err := castore.RevokeIdentity(ctx, tx, id, e.Detail, e.Time); err != nil {
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

// errDroppedRootKey reports that an archive held the key of a root that went offline after it: the
// restore has set key_enc to null.
var errDroppedRootKey = errors.New("controller: the archive held the offline root's key")

// errKeptInstanceAdmin reports an Instance Admin revocation that a restore does not apply again.
var errKeptInstanceAdmin = errors.New("controller: the restored instance keeps its last active Instance Admin")

// revokeInstanceAdmin revokes a user's Instance Admin role again, unless that would leave the
// restored instance without an active Instance Admin to review it, as when every other one was
// made after the backup: then it keeps the role and returns errKeptInstanceAdmin.
func revokeInstanceAdmin(ctx context.Context, tx *ent.Tx, userID string) (bool, error) {
	u, err := tx.User.Get(ctx, userID)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil || !u.InstanceAdmin {
		return err == nil, err
	}
	n, err := tx.User.Query().Where(user.InstanceAdmin(true), user.StatusEQ(user.StatusActive), user.IDNEQ(userID)).Count(ctx)
	if err != nil {
		return true, err
	}
	if n == 0 {
		return true, errKeptInstanceAdmin
	}
	return true, tx.User.UpdateOne(u).SetInstanceAdmin(false).Exec(ctx)
}

// keptReason is the part of the restore's audit reason that names the revocations it kept.
// droppedReason is what the audit entry of a restore says of the root keys it took offline again.
func droppedReason(dropped []string) string {
	if len(dropped) == 0 {
		return ""
	}
	return "; the archive held the key of the root " + strings.Join(dropped, ", ") + ", restored without it"
}

func keptReason(kept []string) string {
	if len(kept) == 0 {
		return ""
	}
	return "; kept: " + strings.Join(kept, "; ")
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
