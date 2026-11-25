// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"time"
)

// Retired reports whether `rpmgr migrate-db` has retired the installation of db, when, and the
// boot file of the database it moved to. A database whose schema predates the columns, or that
// holds no installation, is not retired.
func (db *DB) Retired(ctx context.Context) (at time.Time, to string, retired bool) {
	var a sql.NullTime
	var t sql.NullString
	if err := db.Reader.QueryRowContext(ctx, "SELECT retired_at, retired_to FROM instance WHERE retired_at IS NOT NULL").Scan(&a, &t); err != nil || !a.Valid {
		return time.Time{}, "", false
	}
	return a.Time, t.String, true
}
