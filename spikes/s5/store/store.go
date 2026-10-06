// SPDX-License-Identifier: Apache-2.0

// Package store opens the database for both dialects, generates versioned migrations from the
// Ent schema through Ent's Go API and the ariga.io/atlas library, and applies them with Atlas's
// executor. Nothing here needs the Atlas CLI.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"ariga.io/atlas/sql/migrate"
	"ariga.io/atlas/sql/postgres"
	atlasschema "ariga.io/atlas/sql/schema"
	"ariga.io/atlas/sql/sqlite"
	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	entschema "entgo.io/ent/dialect/sql/schema"
	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
	_ "modernc.org/sqlite"             // registers "sqlite"

	"github.com/felix-homelab/rpmgr/spikes/s5/ent"
	entmigrate "github.com/felix-homelab/rpmgr/spikes/s5/ent/migrate"
	_ "github.com/felix-homelab/rpmgr/spikes/s5/ent/runtime" // registers policies, hooks, interceptors
)

// Dialects supported by the store (ADR-0011).
const (
	SQLite   = dialect.SQLite   // "sqlite3"
	Postgres = dialect.Postgres // "postgres"
)

// sqlitePragmas are applied by modernc.org/sqlite on every new connection. foreign_keys is off by
// default in SQLite; without it no foreign key, composite or not, is enforced.
const sqlitePragmas = "_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// SQLiteDSN returns the DSN for a SQLite database file with the pragmas the store requires.
func SQLiteDSN(path string) string {
	return "file:" + path + "?" + sqlitePragmas
}

// OpenDB opens a database handle for d. For SQLite it refuses a connection on which foreign keys
// are not enforced.
func OpenDB(ctx context.Context, d, dsn string) (*sql.DB, error) {
	switch d {
	case SQLite:
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(1) // one writer connection (docs/06-data-model.md, "Database engines")
		var fk int
		if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
			db.Close()
			return nil, err
		}
		if fk != 1 {
			db.Close()
			return nil, errors.New("store: SQLite foreign keys are not enforced; open with SQLiteDSN")
		}
		return db, nil
	case Postgres:
		return sql.Open("pgx", dsn)
	default:
		return nil, fmt.Errorf("store: unsupported dialect %q", d)
	}
}

// NewClient returns an Ent client on db. Every query and mutation needs an authz scope.
func NewClient(d string, db *sql.DB) *ent.Client {
	return ent.NewClient(ent.Driver(entsql.OpenDB(d, db)))
}

// atlasDriver opens the Atlas migration driver for d on conn.
func atlasDriver(d string, conn atlasschema.ExecQuerier) (migrate.Driver, error) {
	switch d {
	case SQLite:
		return sqlite.Open(conn)
	case Postgres:
		return postgres.Open(conn)
	}
	return nil, fmt.Errorf("store: unsupported dialect %q", d)
}

// Diff writes a new migration file named name into dir with the changes between the migrations
// already in dir (replayed on the clean dev database devDB) and the Ent schema, with composite
// foreign keys. It returns migrate.ErrNoPlan when the directory is up to date.
func Diff(ctx context.Context, d string, devDB *sql.DB, dir migrate.Dir, name string) error {
	m, err := entschema.NewMigrate(entsql.OpenDB(d, devDB),
		entschema.WithDir(dir),
		entschema.WithMigrationMode(entschema.ModeReplay),
		entschema.WithDialect(d),
		entschema.WithFormatter(migrate.DefaultFormatter),
		entschema.WithDropColumn(true),
		entschema.WithDropIndex(true),
		entschema.WithErrNoPlan(true),
		entschema.WithDiffHook(CompositeForeignKeys(CompositeFKExceptions...)),
	)
	if err != nil {
		return err
	}
	return m.NamedDiff(ctx, name, entmigrate.Tables...)
}

// Check compares the live schema of db with the Ent schema (with composite foreign keys), the
// test of docs/12-testing-and-quality.md, "Database tests": the schema produced by the migrations
// must equal the Ent schema. It plans the migration Ent would apply and fails if the plan is not
// empty; nothing is applied.
func Check(ctx context.Context, d string, db *sql.DB) error {
	var changes []string
	m, err := entschema.NewMigrate(entsql.OpenDB(d, db),
		entschema.WithDialect(d),
		entschema.WithDropColumn(true),
		entschema.WithDropIndex(true),
		entschema.WithDiffHook(CompositeForeignKeys(CompositeFKExceptions...)),
		entschema.WithApplyHook(func(entschema.Applier) entschema.Applier {
			return entschema.ApplyFunc(func(_ context.Context, _ dialect.ExecQuerier, plan *migrate.Plan) error {
				for _, c := range plan.Changes {
					changes = append(changes, c.Cmd)
				}
				return nil // record only, never apply
			})
		}),
	)
	if err != nil {
		return err
	}
	if err := m.Create(ctx, entmigrate.Tables...); err != nil {
		return err
	}
	if len(changes) > 0 {
		return fmt.Errorf("store: live schema differs from the Ent schema:\n%s", strings.Join(changes, "\n"))
	}
	return nil
}
