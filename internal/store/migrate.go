// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ariga.io/atlas/sql/migrate"
)

// RevisionTable records applied migrations. It is created by the store, not by the migrations, and
// rpmgr needs no Atlas CLI at run time (S5).
const RevisionTable = "rpmgr_schema_revisions"

// Pending returns the migrations of dir that db has not applied yet. It refuses a directory whose
// atlas.sum does not match its files (an edited or unlisted migration), before anything runs.
func Pending(ctx context.Context, db *DB, dir migrate.Dir) ([]migrate.File, error) {
	if err := migrate.Validate(dir); err != nil {
		return nil, fmt.Errorf("store: migration directory: %w", err)
	}
	rrw := &revisions{db: db.Writer, dialect: db.Dialect}
	if err := rrw.init(ctx); err != nil {
		return nil, err
	}
	drv, err := atlasDriver(db.Dialect, db.Writer)
	if err != nil {
		return nil, err
	}
	ex, err := migrate.NewExecutor(drv, dir, rrw, migrate.WithOperatorVersion(operatorVersion))
	if err != nil {
		return nil, err
	}
	pending, err := ex.Pending(ctx)
	if errors.Is(err, migrate.ErrNoPendingFiles) {
		return nil, nil
	}
	return pending, err
}

// Migrate applies the pending migrations of dir to db and returns how many it applied. Each
// migration file runs in its own transaction, so a failing file leaves no partial change and no
// revision (docs/06-data-model.md, "Migrations"). Before migrating a SQLite database, the caller
// takes a VacuumInto copy when Pending reports files.
//
// SQLite: Atlas adds a foreign key or reorders columns by rebuilding the table between
// "PRAGMA foreign_keys = off" and "= on" in the migration file. SQLite ignores that pragma inside a
// transaction, and the file contains no "PRAGMA foreign_key_check". Migrate therefore follows
// SQLite's documented procedure for such changes on one pinned connection: foreign keys off, the
// file in a transaction, "PRAGMA foreign_key_check" (any row fails the file), commit, foreign keys
// on again.
func Migrate(ctx context.Context, db *DB, dir migrate.Dir) (int, error) {
	pending, err := Pending(ctx, db, dir)
	if err != nil {
		return 0, err
	}
	for i, f := range pending {
		if err := applyFile(ctx, db.Dialect, db.Writer, dir, f); err != nil {
			return i, fmt.Errorf("store: migration %s: %w", f.Name(), err)
		}
	}
	return len(pending), nil
}

// operatorVersion is recorded with every applied migration.
const operatorVersion = "rpmgr"

func applyFile(ctx context.Context, d string, db *sql.DB, dir migrate.Dir, f migrate.File) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if d == SQLite {
		if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = off"); err != nil {
			return err
		}
		defer func() {
			if _, perr := conn.ExecContext(ctx, "PRAGMA foreign_keys = on"); perr != nil && err == nil {
				err = perr
			}
		}()
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	drv, err := atlasDriver(d, tx)
	if err != nil {
		return err
	}
	ex, err := migrate.NewExecutor(drv, dir, &revisions{db: tx, dialect: d}, migrate.WithOperatorVersion(operatorVersion))
	if err != nil {
		return err
	}
	if err := ex.Execute(ctx, f); err != nil {
		return err
	}
	if d == SQLite {
		if err := foreignKeyCheck(ctx, tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// foreignKeyCheck fails if any row violates a foreign key (SQLite only).
func foreignKeyCheck(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var violations []string
	for rows.Next() {
		var (
			table, parent string
			rowid         sql.NullInt64
			fkid          int
		)
		if err := rows.Scan(&table, &rowid, &parent, &fkid); err != nil {
			return err
		}
		violations = append(violations, fmt.Sprintf("%s row %d → %s", table, rowid.Int64, parent))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(violations) > 0 {
		return fmt.Errorf("foreign key violations after the migration: %s", strings.Join(violations, "; "))
	}
	return nil
}

// execQuerier is satisfied by *sql.DB and *sql.Tx.
type execQuerier interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// revisions implements migrate.RevisionReadWriter on a plain table.
type revisions struct {
	db      execQuerier
	dialect string
}

var _ migrate.RevisionReadWriter = (*revisions)(nil)

func (r *revisions) q(query string) string {
	if r.dialect != Postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

func (r *revisions) init(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+RevisionTable+` (
  version text PRIMARY KEY, description text NOT NULL, type integer NOT NULL,
  applied integer NOT NULL, total integer NOT NULL, executed_at text NOT NULL,
  execution_time bigint NOT NULL, error text NOT NULL, error_stmt text NOT NULL,
  hash text NOT NULL, partial_hashes text NOT NULL, operator_version text NOT NULL)`)
	return err
}

// Ident names the revision table, so that Atlas's "database is clean" check on first use ignores
// it. On PostgreSQL the check looks at schemas, so the schema must be named.
func (r *revisions) Ident() *migrate.TableIdent {
	if r.dialect == Postgres {
		return &migrate.TableIdent{Name: RevisionTable, Schema: "public"}
	}
	return &migrate.TableIdent{Name: RevisionTable}
}

func (r *revisions) ReadRevisions(ctx context.Context) ([]*migrate.Revision, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT version, description, type, applied, total,
  executed_at, execution_time, error, error_stmt, hash, partial_hashes, operator_version
  FROM `+RevisionTable+` ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*migrate.Revision
	for rows.Next() {
		rev, err := scanRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

func (r *revisions) ReadRevision(ctx context.Context, v string) (*migrate.Revision, error) {
	row := r.db.QueryRowContext(ctx, r.q(`SELECT version, description, type, applied, total,
  executed_at, execution_time, error, error_stmt, hash, partial_hashes, operator_version
  FROM `+RevisionTable+` WHERE version = ?`), v)
	rev, err := scanRevision(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, migrate.ErrRevisionNotExist
	}
	return rev, err
}

func (r *revisions) WriteRevision(ctx context.Context, rev *migrate.Revision) error {
	ph, err := json.Marshal(rev.PartialHashes)
	if err != nil {
		return err
	}
	if _, err := r.db.ExecContext(ctx, r.q(`DELETE FROM `+RevisionTable+` WHERE version = ?`), rev.Version); err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, r.q(`INSERT INTO `+RevisionTable+` (version, description, type,
  applied, total, executed_at, execution_time, error, error_stmt, hash, partial_hashes,
  operator_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		rev.Version, rev.Description, int(rev.Type), rev.Applied, rev.Total,
		rev.ExecutedAt.UTC().Format(time.RFC3339Nano), int64(rev.ExecutionTime), rev.Error,
		rev.ErrorStmt, rev.Hash, string(ph), rev.OperatorVersion)
	return err
}

func (r *revisions) DeleteRevision(ctx context.Context, v string) error {
	_, err := r.db.ExecContext(ctx, r.q(`DELETE FROM `+RevisionTable+` WHERE version = ?`), v)
	return err
}

type scanner interface{ Scan(...any) error }

func scanRevision(s scanner) (*migrate.Revision, error) {
	var (
		rev      migrate.Revision
		typ      int
		executed string
		dur      int64
		ph       string
	)
	if err := s.Scan(&rev.Version, &rev.Description, &typ, &rev.Applied, &rev.Total, &executed,
		&dur, &rev.Error, &rev.ErrorStmt, &rev.Hash, &ph, &rev.OperatorVersion); err != nil {
		return nil, err
	}
	rev.Type = migrate.RevisionType(typ)
	rev.ExecutionTime = time.Duration(dur)
	t, err := time.Parse(time.RFC3339Nano, executed)
	if err != nil {
		return nil, err
	}
	rev.ExecutedAt = t
	if err := json.Unmarshal([]byte(ph), &rev.PartialHashes); err != nil {
		return nil, err
	}
	return &rev, nil
}
