// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// IsForeignKeyViolation reports whether err is a foreign-key violation on either dialect. SQLite
// reports an ON DELETE RESTRICT violation as SQLITE_CONSTRAINT_TRIGGER, not
// SQLITE_CONSTRAINT_FOREIGNKEY (S8), so both count.
func IsForeignKeyViolation(err error) bool {
	switch sqliteCode(err) {
	case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY, sqlite3.SQLITE_CONSTRAINT_TRIGGER:
		return true
	}
	return pgCode(err) == "23503"
}

// IsUniqueViolation reports whether err violates a unique index or primary key on either dialect.
func IsUniqueViolation(err error) bool {
	switch sqliteCode(err) {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return true
	}
	return pgCode(err) == "23505"
}

// sqliteCode returns the extended SQLite result code of err, or -1.
func sqliteCode(err error) int {
	var e *sqlite.Error
	if errors.As(err, &e) {
		return e.Code()
	}
	return -1
}

func pgCode(err error) string {
	var e *pgconn.PgError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
