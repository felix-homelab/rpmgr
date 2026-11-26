// SPDX-License-Identifier: Apache-2.0

package store

import (
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DSNParts are the parts of a PostgreSQL DSN that are no secret.
type DSNParts struct {
	Host, Port, Database, User string
	// SSLMode is one of the sslmode values PostgreSQL knows, or "".
	SSLMode string
	// HasPassword reports that the DSN, PGPASSWORD or a .pgpass file sets a password, as
	// postgresConfig refuses.
	HasPassword bool
}

var sslModes = []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}

// SummarizeDSN reads dsn the way OpenPostgres does, with the same parser and allowed parameters, so
// that what it returns is what the controller would connect to. Only the first host of a list is
// returned. It returns false for a DSN that does not parse or sets a parameter that is not allowed.
// Nothing else of the DSN is returned, and never the password. A URL whose authority is not closed
// before its one '@' (a raw '/', '?', '#' or '@' in the password) is refused: the parts of it are ambiguous.
func SummarizeDSN(dsn string) (DSNParts, bool) {
	if i := strings.Index(dsn, "://"); i >= 0 && (strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")) {
		rest := dsn[i+3:]
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		if strings.Count(rest[:end], "@") > 1 || strings.Contains(rest[end:], "@") {
			return DSNParts{}, false
		}
	}
	cfg, err := pgx.ParseConfigWithOptions(dsn, pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: dsnKeys},
	})
	if err != nil {
		return DSNParts{}, false
	}
	p := DSNParts{Host: cfg.Host, Database: cfg.Database, User: cfg.User, HasPassword: cfg.Password != ""}
	if cfg.Port != 0 {
		p.Port = strconv.Itoa(int(cfg.Port))
	}
	if m := dsnParam(dsn, "sslmode"); slices.Contains(sslModes, m) {
		p.SSLMode = m
	}
	return p, true
}
