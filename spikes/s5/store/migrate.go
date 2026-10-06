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

// RevisionTable records applied migrations. It is created by the store, not by the migrations.
const RevisionTable = "rpmgr_schema_revisions"

// Migrate applies the pending migrations of dir to db, at most n of them (n <= 0: all). Each
// migration file runs in its own transaction on PostgreSQL. On SQLite a file runs outside a
// transaction, because Atlas's table rebuilds switch PRAGMA foreign_keys off and on, which SQLite
// ignores inside a transaction; the rebuild checks foreign keys itself (PRAGMA foreign_key_check).
// Migrate refuses a directory whose atlas.sum does not match its files.
func Migrate(ctx context.Context, d string, db *sql.DB, dir migrate.Dir, n int) error {
	if err := migrate.Validate(dir); err != nil {
		return fmt.Errorf("store: migration directory: %w", err)
	}
	rrw := &revisions{db: db, dialect: d}
	if err := rrw.init(ctx); err != nil {
		return err
	}
	drv, err := atlasDriver(d, db)
	if err != nil {
		return err
	}
	ex, err := migrate.NewExecutor(drv, dir, rrw, migrate.WithOperatorVersion("rpmgr-s5"))
	if err != nil {
		return err
	}
	pending, err := ex.Pending(ctx)
	switch {
	case errors.Is(err, migrate.ErrNoPendingFiles):
		return nil
	case err != nil:
		return err
	}
	if n <= 0 || n > len(pending) {
		n = len(pending)
	}
	for _, f := range pending[:n] {
		if err := applyFile(ctx, d, db, dir, rrw, f); err != nil {
			return fmt.Errorf("store: migration %s: %w", f.Name(), err)
		}
	}
	return nil
}

func applyFile(ctx context.Context, d string, db *sql.DB, dir migrate.Dir, rrw *revisions, f migrate.File) error {
	if d == SQLite {
		drv, err := atlasDriver(d, db)
		if err != nil {
			return err
		}
		ex, err := migrate.NewExecutor(drv, dir, rrw, migrate.WithOperatorVersion("rpmgr-s5"))
		if err != nil {
			return err
		}
		return ex.Execute(ctx, f)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	drv, err := atlasDriver(d, tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	ex, err := migrate.NewExecutor(drv, dir, &revisions{db: tx, dialect: d}, migrate.WithOperatorVersion("rpmgr-s5"))
	if err != nil {
		tx.Rollback()
		return err
	}
	if err := ex.Execute(ctx, f); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// execQuerier is satisfied by *sql.DB and *sql.Tx.
type execQuerier interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// revisions implements migrate.RevisionReadWriter on a plain table. The Atlas CLI keeps its own
// revision table; rpmgr applies the embedded migrations itself and needs no CLI at run time.
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
	defer rows.Close()
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
