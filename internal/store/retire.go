// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrRetired is returned for a database that `rpmgr migrate-db` has retired: it holds the same
// installation, epoch and revisions as its target, and a controller on each would hand agents two
// histories (docs/06-data-model.md, "Copying a database").
var ErrRetired = errors.New("store: this database was retired by `rpmgr migrate-db`; use its target")

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Retired reports whether `rpmgr migrate-db` has retired the installation of db, when, and the
// boot file of the database it moved to. A database whose schema predates the columns is not
// retired; a query that fails is an error, so that a caller refuses and never assumes.
func (db *DB) Retired(ctx context.Context) (at time.Time, to string, retired bool, err error) {
	return retiredIn(ctx, db.Reader, db.Dialect, false)
}

// retiredIn reads the retirement through q. With lock, on PostgreSQL it takes a share lock on the
// instance row, which the retirement's UPDATE must wait for: a write that checked first then
// commits before the retirement does, and one that starts after it sees it.
func retiredIn(ctx context.Context, q queryer, dialect string, lock bool) (at time.Time, to string, retired bool, err error) {
	has := `SELECT count(*) FROM pragma_table_info('instance') WHERE name = 'retired_at'`
	read := `SELECT retired_at, retired_to FROM instance`
	if dialect == Postgres {
		has = `SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'instance' AND column_name = 'retired_at'`
		if lock {
			read += " FOR SHARE"
		}
	}
	fail := func(err error) (time.Time, string, bool, error) {
		return time.Time{}, "", false, fmt.Errorf("store: cannot tell whether the database is retired: %w", err)
	}
	rows, err := q.QueryContext(ctx, has)
	if err != nil {
		return fail(err)
	}
	var n int
	if rows.Next() {
		err = rows.Scan(&n)
	}
	if err = errors.Join(err, rows.Err(), rows.Close()); err != nil {
		return fail(err)
	}
	if n == 0 { // a schema from before the columns
		return time.Time{}, "", false, nil
	}
	if rows, err = q.QueryContext(ctx, read); err != nil {
		return fail(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a sql.NullTime
		var t sql.NullString
		if err := rows.Scan(&a, &t); err != nil {
			return fail(err)
		}
		if a.Valid {
			return a.Time, t.String, true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return fail(err)
	}
	return time.Time{}, "", false, nil
}

// guardRetired is the check inside the write transactions of a database opened with
// SQLiteOptions.RefuseRetired, a command that takes no controller lock: a retirement that commits
// while the transaction waits for the write lock is seen, or fails the transaction on SQLite, so
// no write lands only in a retired database.
func (db *DB) guardRetired(ctx context.Context, tx queryer) error {
	if !db.refuseRetired {
		return nil
	}
	at, to, retired, err := retiredIn(ctx, tx, db.Dialect, true)
	if err != nil {
		return err
	}
	if retired {
		return fmt.Errorf("%w (retired %s to %s)", ErrRetired, at.UTC().Format(time.RFC3339), to)
	}
	return nil
}
