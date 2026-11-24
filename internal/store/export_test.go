// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"time"

	"entgo.io/ent/dialect/sql/schema"
	"github.com/jackc/pgx/v5"
)

// PostgresConfig runs the checks of OpenPostgres that need no server and returns the connection
// settings it would use.
func PostgresConfig(dsn string, o PostgresOptions) (*pgx.ConnConfig, error) {
	return postgresConfig(dsn, o)
}

// PostgresConfigErr runs the checks of OpenPostgres that need no server.
func PostgresConfigErr(dsn string, o PostgresOptions) error {
	_, err := postgresConfig(dsn, o)
	return err
}

// CheckServerVersion is checkServerVersion.
var CheckServerVersion = checkServerVersion

// SetLockCheckInterval sets how often the controller lock's connection is checked until the test
// ends.
func SetLockCheckInterval(cleanup func(func()), d time.Duration) {
	old := lockCheckInterval
	lockCheckInterval = d
	cleanup(func() { lockCheckInterval = old })
}

// CopyOrder is the order in which CopyDatabase copies the tables of db.
func CopyOrder(db *DB) ([]*schema.Table, error) {
	return copyOrder(context.Background(), db.Reader, db.Dialect)
}
