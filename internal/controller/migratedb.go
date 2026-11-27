// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
)

// ErrDSNArgument is returned for a database address as an argument: a DSN and its password never
// appear on a command line.
var ErrDSNArgument = errors.New("controller: a database address is not accepted as an argument; name a boot file or a SQLite database")

// ErrSameDatabase is returned when source and target are one database.
var ErrSameDatabase = errors.New("controller: source and target are the same database")

// dsnLike matches the start of a URL and the keys of a key-value DSN.
var dsnLike = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://|(^|\s)(host|hostaddr|port|user|password|dbname|sslmode|service|passfile)\s*=`)

// migrateHook, if set, is called at "before copy" and "after copy": a test hook.
var migrateHook func(stage string)

// MigrateDBOptions are the settings of MigrateDB.
type MigrateDBOptions struct {
	From   string // a SQLite database file or a boot file
	ToFile string // a boot file
	// NoRetire leaves the source usable after the copy, for a test copy.
	NoRetire bool
	Getenv   func(string) string // default os.Getenv
	Now      func() time.Time    // default time.Now
	// Progress is called after each table with its name and row count.
	Progress func(table string, rows int64)
}

// MigrateDBResult describes a finished migration.
type MigrateDBResult struct {
	From, To string // the dialects
	Copy     store.CopyResult
	Retired  bool
}

// MigrateDB copies the database of a stopped controller into an empty one of either dialect, with
// every sealed value as it is: it reads no KEK and opens no secret. Source and target are each
// locked exclusively, so a running controller on either is refused (ErrStopController). An empty
// target is migrated with this binary's migrations; one with a row or a different schema is
// refused by the copier (store.ErrTargetNotEmpty, store.ErrSchemaMismatch). After the target's
// transaction has committed the source is retired unless o.NoRetire, and the migration is audited
// as local-cli in the target.
func MigrateDB(ctx context.Context, o MigrateDBOptions) (res MigrateDBResult, err error) {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	for _, arg := range []string{o.From, o.ToFile} {
		if arg == "" || dsnLike.MatchString(arg) {
			return MigrateDBResult{}, ErrDSNArgument
		}
	}
	from, err := endpoint(o.From)
	if err != nil {
		return MigrateDBResult{}, err
	}
	to, err := endpoint(o.ToFile)
	if err != nil {
		return MigrateDBResult{}, err
	}
	if sameDatabase(from, to) {
		return MigrateDBResult{}, ErrSameDatabase
	}
	if from.Driver == "sqlite" {
		if err := checkSourceFile(from.DSN); err != nil {
			return MigrateDBResult{}, err
		}
	}
	src, err := openMigrateEnd(ctx, from, o.Getenv, false)
	if err != nil {
		return MigrateDBResult{}, fmt.Errorf("source: %w", err)
	}
	defer func() { _ = src.Close() }()
	if err := checkSource(ctx, src); err != nil {
		return MigrateDBResult{}, fmt.Errorf("source: %w", err)
	}
	// The source stays in one write transaction to the end: one moment of it is copied, nothing else
	// can write to it, and the retirement joins it.
	stx, err := store.BeginSource(ctx, src)
	if err != nil {
		return MigrateDBResult{}, fmt.Errorf("source: %w", err)
	}
	defer func() { _ = stx.Rollback() }()

	plan, err := planTarget(to)
	if err != nil {
		return MigrateDBResult{}, fmt.Errorf("target: %w", err)
	}
	if migrateHook != nil {
		migrateHook("before target")
	}
	committed, opened := false, false
	defer func() { // what this command made and that holds no copy is not left behind; after a failed
		if plan != nil && opened && !committed && err != nil { // open nothing is, the lock is not ours
			plan.remove()
		}
	}()
	dst, err := openMigrateEnd(ctx, to, o.Getenv, true)
	if errors.Is(err, store.ErrLocked) || errors.Is(err, ErrStopController) {
		if from.Driver == to.Driver {
			err = fmt.Errorf("%w; the target may be the source under another name", err)
		}
	}
	if err != nil {
		return MigrateDBResult{}, fmt.Errorf("target: %w", err)
	}
	opened = true
	defer func() { _ = dst.Close() }()
	// The copy writes to the target's pool directly, so neither the fence nor the epoch covers it:
	// opening ended the sessions of a controller before it, and this waits for the rest.
	if err := settleLock(ctx, src, dst); err != nil {
		return MigrateDBResult{}, err
	}
	if err := migrateEmptyTarget(ctx, dst); err != nil {
		return MigrateDBResult{}, fmt.Errorf("target: %w", err)
	}

	if migrateHook != nil {
		migrateHook("before copy")
	}
	copyCtx, cancel := untilLost(ctx, src, dst)
	defer cancel(nil)
	res = MigrateDBResult{From: src.Dialect, To: dst.Dialect}
	if res.Copy, err = store.CopyDatabase(copyCtx, src, dst, store.CopyOptions{Source: stx, Progress: o.Progress}); err != nil {
		return MigrateDBResult{}, errors.Join(err, context.Cause(copyCtx))
	}
	committed = true
	// Interrupted or not, the source is retired now: the target holds the copy.
	ctx = context.WithoutCancel(ctx)
	if migrateHook != nil {
		migrateHook("after copy")
	}
	if errors.Is(context.Cause(copyCtx), ErrLockLost) { // untilLost cancelled it
		return res, fmt.Errorf("controller: the copy committed, but %w; do not start a controller on the source before checking it", ErrLockLost)
	}

	// The target has committed; the audit entry says what happened to the source.
	reason := fmt.Sprintf("%s to %s: %d tables, %d rows, hash %s; source kept (--no-retire)",
		res.From, res.To, res.Copy.Tables, res.Copy.Rows, res.Copy.Hash)
	if !o.NoRetire {
		if err := retire(ctx, src, stx, o.ToFile, o.Now()); err != nil {
			return res, fmt.Errorf("controller: the copy committed, but the source could not be retired, so do not start a controller on it: %w", err)
		}
		res.Retired = true
		reason = strings.TrimSuffix(reason, "source kept (--no-retire)") + "source retired"
	}
	if err := stx.Commit(); err != nil {
		return res, fmt.Errorf("controller: the copy committed, but the source's retirement did not: %w", err)
	}
	sys, err := authz.System(ctx, "local-cli", "rpmgr migrate-db", audit.SystemScopes(dst))
	if err != nil {
		return res, fmt.Errorf("controller: the copy committed, but its audit entry failed: %w", err)
	}
	if _, err := audit.Record(sys, dst, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli", Action: "database.migrate",
		TargetType: "instance", TargetID: "1", Result: audit.Success, Reason: reason}); err != nil {
		return res, fmt.Errorf("controller: the copy committed, but its audit entry failed: %w", err)
	}
	return res, nil
}

// untilLost derives a context that ends when either database loses its controller lock.
func untilLost(ctx context.Context, dbs ...*store.DB) (context.Context, context.CancelCauseFunc) {
	c, cancel := context.WithCancelCause(ctx)
	for _, db := range dbs {
		go func() {
			select {
			case <-db.LockLost():
				cancel(ErrLockLost)
			case <-c.Done():
			}
		}()
	}
	return c, cancel
}

var sqliteMagic = []byte("SQLite format 3\x00")

// endpoint reads what database arg names: a SQLite database file itself, or the `database` section
// of a boot file.
func endpoint(arg string) (config.Database, error) {
	abs, err := filepath.Abs(arg)
	if err != nil {
		return config.Database{}, err
	}
	fh, err := os.Open(abs) //nolint:gosec // G304: the operator's --from or --to-file
	if err != nil {
		return config.Database{}, err
	}
	head := make([]byte, len(sqliteMagic))
	n, err := io.ReadFull(fh, head)
	_ = fh.Close()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return config.Database{}, fmt.Errorf("controller: %s: %w", arg, err)
	}
	if bytes.Equal(head[:n], sqliteMagic) {
		return config.Database{Driver: "sqlite", DSN: abs}, nil
	}
	return config.LoadDatabase(abs)
}

func sameDatabase(a, b config.Database) bool {
	if a.Driver != b.Driver {
		return false
	}
	if a.Driver == "postgres" {
		return a.DSN == b.DSN
	}
	if filepath.Clean(a.DSN) == filepath.Clean(b.DSN) {
		return true
	}
	x, errX := os.Stat(a.DSN)
	y, errY := os.Stat(b.DSN)
	return errX == nil && errY == nil && os.SameFile(x, y)
}

// openMigrateEnd opens a database with the controller lock held exclusively, whatever its dialect.
func openMigrateEnd(ctx context.Context, d config.Database, getenv func(string) string, create bool) (*store.DB, error) {
	var db *store.DB
	var err error
	if d.Driver == "postgres" {
		db, err = store.OpenPostgres(ctx, d.DSN, store.PostgresOptions{
			PasswordFile: d.PasswordFile, PasswordCredential: d.PasswordCredential, Getenv: getenv, Lock: true})
	} else {
		db, err = store.OpenSQLite(ctx, d.DSN, store.SQLiteOptions{Lock: true, Create: create})
	}
	if errors.Is(err, store.ErrLocked) {
		return nil, ErrStopController
	}
	return db, err
}

// checkSource refuses a source that this binary cannot copy as it is: one behind it or ahead of
// it, one without an installation, and one that is retired already.
func checkSource(ctx context.Context, src *store.DB) error {
	dir, err := migrations.Dir(src.Dialect)
	if err != nil {
		return err
	}
	pending, err := store.Pending(ctx, src, dir)
	if err != nil {
		return err
	}
	if len(pending) > 0 {
		return fmt.Errorf("%w: it is behind this binary by %d migrations; run `rpmgr migrate` on it first", store.ErrSchemaMismatch, len(pending))
	}
	sys := migrateScope(ctx)
	inst, err := src.ReadClient().Instance.Query().Only(sys)
	if err != nil {
		return fmt.Errorf("the database holds no installation: %w", err)
	}
	if inst.RetiredAt != nil {
		return fmt.Errorf("%w (retired %s)", ErrRetired, inst.RetiredAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// migrateEmptyTarget migrates a target that no rpmgr has touched, but never one that holds a table of
// something else. A target that is partly migrated is left to the copier, which refuses it.
func migrateEmptyTarget(ctx context.Context, dst *store.DB) error {
	q := `SELECT count(*), coalesce(sum(name = '` + store.RevisionTable + `'), 0) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`
	if dst.Dialect == store.Postgres {
		q = `SELECT count(*), count(*) FILTER (WHERE tablename = '` + store.RevisionTable + `') FROM pg_tables WHERE schemaname = current_schema()`
	}
	var tables, ours int
	if err := dst.Writer.QueryRowContext(ctx, q).Scan(&tables, &ours); err != nil {
		return err
	}
	if tables > ours {
		if ours == 0 {
			return fmt.Errorf("%w: it holds %d tables that are not rpmgr's", store.ErrTargetNotEmpty, tables)
		}
		return nil
	}
	if tables > 0 {
		return nil // rpmgr has migrated it; the copier compares its schema with the source's
	}
	dir, err := migrations.Dir(dst.Dialect)
	if err != nil {
		return err
	}
	_, err = store.Migrate(ctx, dst, dir)
	return err
}

// migrateScope is the system scope of local-cli on a database whose audit log must stay as it is:
// the source is read for the copy and then retired, and the target's entry records both.
func migrateScope(ctx context.Context) context.Context {
	sys, err := authz.System(ctx, "local-cli", "rpmgr migrate-db", func(context.Context, string, string) error { return nil })
	if err != nil { // the grant function does not fail
		panic(err)
	}
	return sys
}

// retire marks the installation of src as moved to the boot file to, in the transaction stx.
func retire(ctx context.Context, src *store.DB, stx *store.SourceTx, to string, now time.Time) error {
	abs, _ := filepath.Abs(to)
	q := "UPDATE instance SET retired_at = ?, retired_to = ? WHERE retired_at IS NULL"
	if src.Dialect == store.Postgres {
		q = "UPDATE instance SET retired_at = $1, retired_to = $2 WHERE retired_at IS NULL"
	}
	r, err := stx.ExecContext(ctx, q, now.UTC(), abs)
	if err != nil {
		return err
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		return errors.Join(err, errors.New("no installation to retire"))
	}
	return nil
}

// ErrLinkedState is returned for a file of a SQLite database that is a link, a special file or has
// more than one name: a lock or journal name is derived from the path, so another name bypasses it.
var ErrLinkedState = errors.New("controller: a file of the database is a link, a special file or has several names")

// ErrHardLinked is returned for a SQLite source with another name: the controller lock and the
// write-ahead log are named after the path, so a second name would bypass both.
var ErrHardLinked = errors.New("controller: the source database has more than one hard link; name its only path")

// ErrOtherUser is returned when migrate-db would cross users: it creates files, so it runs as the
// owner of the directories it works in and never changes an owner.
var ErrOtherUser = errors.New("controller: run migrate-db as the owner of the database's directory, for example sudo -u rpmgr rpmgr migrate-db")

// effectiveUID is os.Geteuid; a test replaces it.
var effectiveUID = os.Geteuid

// checkOwner refuses a SQLite database in a directory that another user owns.
func checkOwner(path string) error {
	if uid, _, ok := dirOwner(filepath.Dir(path)); ok && uid != effectiveUID() {
		return fmt.Errorf("%w (%s is owned by user %d, this is user %d)", ErrOtherUser, filepath.Dir(path), uid, effectiveUID())
	}
	return nil
}

// checkSourceFile refuses a missing source, one with more than one name, one with a linked lock or
// journal name, and one in another user's directory.
func checkSourceFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("controller: no source database at %s: %w", path, err)
	}
	if hardLinks(fi) {
		return ErrHardLinked
	}
	path = store.ResolvePath(path)
	if err := checkOwner(path); err != nil {
		return err
	}
	return refuseLinked(path, false)
}

var sidecars = []string{".lock", "-wal", "-shm"}

// refuseLinked refuses a lock, journal or shared-memory name, and with main the file itself, that
// exists as anything but a regular file with one name. It uses lstat, so a link is seen.
func refuseLinked(path string, main bool) error {
	names := sidecars
	if main {
		names = append([]string{""}, sidecars...)
	}
	for _, s := range names {
		if fi, err := os.Lstat(path + s); err == nil && (!fi.Mode().IsRegular() || hardLinks(fi)) {
			return fmt.Errorf("%w: %s", ErrLinkedState, path+s)
		}
	}
	return nil
}

// targetPlan remembers which files of a SQLite target did not exist before this command.
type targetPlan struct{ fresh []string }

// planTarget refuses a SQLite target in another user's directory or with a linked name, and notes
// the files it will create. The target's own path is not resolved: a link there is refused. It
// returns nil for a PostgreSQL target.
func planTarget(to config.Database) (*targetPlan, error) {
	if to.Driver != "sqlite" {
		return nil, nil
	}
	if err := refuseLinked(to.DSN, true); err != nil {
		return nil, err
	}
	path := store.ResolvePath(to.DSN)
	if err := errors.Join(checkOwner(path), refuseLinked(path, false)); err != nil {
		return nil, err
	}
	p := &targetPlan{}
	for _, s := range append([]string{""}, sidecars...) {
		if _, err := os.Lstat(path + s); errors.Is(err, os.ErrNotExist) {
			p.fresh = append(p.fresh, path+s)
		}
	}
	return p, nil
}

// remove removes the files this command made, except the lock file, which a controller may hold.
func (p *targetPlan) remove() {
	for _, name := range p.fresh {
		if !strings.HasSuffix(name, ".lock") {
			_ = os.Remove(name)
		}
	}
}
