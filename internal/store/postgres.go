// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"fmt"

	"ariga.io/atlas/sql/migrate"
	atlaspostgres "ariga.io/atlas/sql/postgres"
	atlasschema "ariga.io/atlas/sql/schema"
	atlassqlite "ariga.io/atlas/sql/sqlite"
	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
)

// OpenPostgres opens a PostgreSQL database. Phase 1 tests every migration on PostgreSQL, but boot
// files accept it only from Phase 2, with HA (D57).
func OpenPostgres(ctx context.Context, dsn string) (*DB, error) {
	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.PingContext(ctx); err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("store: open PostgreSQL: %w", err)
	}
	c := NewClient(Postgres, pool)
	return &DB{Dialect: Postgres, Writer: pool, Reader: pool, unlock: func() error { return nil }, client: c, readClient: c}, nil
}

// atlasDriver opens Atlas's migration driver for d on conn.
func atlasDriver(d string, conn atlasschema.ExecQuerier) (migrate.Driver, error) {
	switch d {
	case SQLite:
		return atlassqlite.Open(conn)
	case Postgres:
		return atlaspostgres.Open(conn)
	}
	return nil, fmt.Errorf("store: unsupported dialect %q", d)
}
