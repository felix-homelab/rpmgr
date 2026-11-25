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
	"slices"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/migrations"
)

// Moving a controller's database between SQLite and PostgreSQL (docs/16-cli.md, `rpmgr
// migrate-db`; docs/10-operations.md, "Moving between SQLite and PostgreSQL").

// ErrRetired is returned for a database that `rpmgr migrate-db` has retired: it holds the same
// installation, epoch and revisions as its target, and a controller on each would hand agents two
// histories (docs/06-data-model.md, "Copying a database").
var ErrRetired = errors.New("controller: this database was retired by `rpmgr migrate-db`; start the controller on its target")

// ErrDSNArgument is returned when an argument of `rpmgr migrate-db` is a database address and not a
// file: a DSN and its password never appear on a command line, where `ps` and the shell history
// would keep them.
var ErrDSNArgument = errors.New("controller: a database address is not accepted as an argument; name a boot file or a SQLite database")

// ErrSameDatabase is returned when source and target are one database.
var ErrSameDatabase = errors.New("controller: source and target are the same database")

// dsnLike matches the start of a URL and the keys of a key-value DSN.
var dsnLike = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://|(^|\s)(host|hostaddr|port|user|password|dbname|sslmode|service|passfile)\s*=`)

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
	src, err := openMigrateEnd(ctx, from, o.Getenv)
	if err != nil {
		return MigrateDBResult{}, fmt.Errorf("source: %w", err)
	}
	defer func() { _ = src.Close() }()
	if err := checkSource(ctx, src); err != nil {
		return MigrateDBResult{}, fmt.Errorf("source: %w", err)
	}
	// From here to the end the source is held in one write transaction: what the copy reads is one
	// moment of it, nothing else can write to it meanwhile, and the retirement joins it.
	stx, err := store.BeginSource(ctx, src)
	if err != nil {
		return MigrateDBResult{}, fmt.Errorf("source: %w", err)
	}
	defer func() { _ = stx.Rollback() }()

	created, err := createSQLiteTarget(to)
	if err != nil {
		return MigrateDBResult{}, fmt.Errorf("target: %w", err)
	}
	committed := false
	defer func() { // a target this command made, and that holds no copy, is not left behind
		if created != nil {
			created.finish(!committed && err != nil)
		}
	}()
	dst, err := openMigrateEnd(ctx, to, o.Getenv)
	if errors.Is(err, store.ErrLocked) || errors.Is(err, ErrStopController) {
		if from.Driver == to.Driver {
			err = fmt.Errorf("%w; the target may be the source under another name", err)
		}
	}
	if err != nil {
		return MigrateDBResult{}, fmt.Errorf("target: %w", err)
	}
	defer func() { _ = dst.Close() }()
	if err := migrateEmptyTarget(ctx, dst); err != nil {
		return MigrateDBResult{}, fmt.Errorf("target: %w", err)
	}

	// A PostgreSQL controller lock lost during the copy means another controller may run: stop.
	copyCtx, cancel := untilLost(ctx, src, dst)
	defer cancel(nil)
	res = MigrateDBResult{From: src.Dialect, To: dst.Dialect}
	if res.Copy, err = store.CopyDatabase(copyCtx, src, dst, store.CopyOptions{Source: stx, Progress: o.Progress}); err != nil {
		return MigrateDBResult{}, errors.Join(err, context.Cause(copyCtx))
	}
	committed = true
	if err := lockHeld(src, dst); err != nil {
		return res, fmt.Errorf("controller: the copy committed, but %w; do not start a controller on the source before checking it", err)
	}

	// The target has committed. The source is retired in its own transaction, which has held the
	// file since before the copy; the audit entry says what happened to it.
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

// ErrLockLost is returned when the PostgreSQL session that holds a database's controller lock ends
// while the command works on it.
var ErrLockLost = errors.New("controller: the PostgreSQL controller lock was lost")

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

// lockHeld checks again that no lock was lost.
func lockHeld(dbs ...*store.DB) error {
	for _, db := range dbs {
		select {
		case <-db.LockLost():
			return ErrLockLost
		default:
		}
	}
	return nil
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
func openMigrateEnd(ctx context.Context, d config.Database, getenv func(string) string) (*store.DB, error) {
	var db *store.DB
	var err error
	if d.Driver == "postgres" {
		db, err = store.OpenPostgres(ctx, d.DSN, store.PostgresOptions{
			PasswordFile: d.PasswordFile, PasswordCredential: d.PasswordCredential, Getenv: getenv, Lock: true})
	} else {
		db, err = store.OpenSQLite(ctx, d.DSN, store.SQLiteOptions{Lock: true})
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

// migrateEmptyTarget migrates a target that no rpmgr has touched, with this binary's migrations,
// but never one that holds a table of something else. A target that is partly migrated is left to
// the copier, which refuses it.
func migrateEmptyTarget(ctx context.Context, dst *store.DB) error {
	query := `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`
	if dst.Dialect == store.Postgres {
		query = `SELECT tablename FROM pg_tables WHERE schemaname = current_schema()`
	}
	rows, err := dst.Writer.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return err
		}
		tables = append(tables, name)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	if len(tables) > 0 && !slices.Contains(tables, store.RevisionTable) {
		return fmt.Errorf("%w: it holds %d tables that are not rpmgr's", store.ErrTargetNotEmpty, len(tables))
	}
	if len(tables) > 0 {
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
	abs, err := filepath.Abs(to)
	if err != nil {
		abs = to
	}
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

// refuseRetired is the check of every command that opens a database without the controller lock:
// what it writes to a retired database would reach no controller.
func refuseRetired(ctx context.Context, db *store.DB) error {
	if at, to, ok := db.Retired(ctx); ok {
		return fmt.Errorf("%w (retired %s to %s)", ErrRetired, at.UTC().Format(time.RFC3339), to)
	}
	return nil
}

// ErrHardLinked is returned for a SQLite source with another name: the controller lock and the
// write-ahead log are named after the path, so a second name would bypass both.
var ErrHardLinked = errors.New("controller: the source database has more than one hard link; name its only path")

// checkSourceFile refuses a missing source and one with more than one name.
func checkSourceFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("controller: no source database at %s: %w", path, err)
	}
	if hardLinks(fi) {
		return ErrHardLinked
	}
	return nil
}

// newTarget is a SQLite target that this command created.
type newTarget struct{ path string }

// createSQLiteTarget creates the target file of a SQLite database that does not exist yet, with
// mode 0600 as a restore does and never over another file. It returns nil for any other target.
func createSQLiteTarget(to config.Database) (*newTarget, error) {
	if to.Driver != "sqlite" {
		return nil, nil
	}
	path := store.ResolvePath(to.DSN)
	if _, err := os.Lstat(path); err == nil {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator's boot file names it
	if err != nil {
		return nil, err
	}
	return &newTarget{path}, f.Close()
}

// finish runs when the target is closed. A target that holds no copy is removed with its log files, but
// not its lock file, which a controller may hold; one that does is given to the owner of its directory when root made it, so that the
// service user can open it.
func (t *newTarget) finish(remove bool) {
	for _, suffix := range []string{"", ".lock", "-wal", "-shm"} {
		name := t.path + suffix
		if remove {
			if suffix != ".lock" { // never the lock: a controller may hold it
				_ = os.Remove(name)
			}
		} else if os.Geteuid() == 0 {
			if uid, gid, ok := dirOwner(filepath.Dir(t.path)); ok {
				_ = os.Chown(name, uid, gid)
			}
		}
	}
}
