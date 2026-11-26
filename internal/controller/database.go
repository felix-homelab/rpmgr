// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// lockSettle is how long a controller that has just taken the PostgreSQL controller lock waits
// before its first write: the stop bound of docs/03-connections.md, "Timeouts, keepalive and
// backoff". The server releases a lost session's lock only when it notices the loss, so the
// controller that lost the lock may still be writing.
var lockSettle = 10 * time.Second

// ErrSQLiteOnly is returned by a command that works on a SQLite database only, when the boot file
// names PostgreSQL.
var ErrSQLiteOnly = errors.New("controller: the database is PostgreSQL, which this command does not work on yet")

// requireSQLite refuses what for a controller on PostgreSQL.
func requireSQLite(cfg config.Controller, what string) error {
	if cfg.Database.Driver == "postgres" {
		return fmt.Errorf("%w: %s", ErrSQLiteOnly, what)
	}
	return nil
}

// dbOptions are what a command asks of its database.
type dbOptions struct {
	// Lock takes the controller lock for as long as the database is open: the exclusive one,
	// which refuses a second controller (replicas take the shared one, from slice 9.5).
	Lock bool
	// RefuseRetired makes every write refuse a database that `rpmgr migrate-db` retired.
	RefuseRetired bool
}

// openDatabase opens the database of cfg, whichever its driver, with the password of a PostgreSQL
// database read from its file or credential.
func openDatabase(ctx context.Context, cfg config.Controller, getenv func(string) string, o dbOptions) (*store.DB, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	d := cfg.Database
	if d.Driver == "postgres" {
		return store.OpenPostgres(ctx, d.DSN, store.PostgresOptions{PasswordFile: d.PasswordFile,
			PasswordCredential: d.PasswordCredential, Getenv: getenv, Lock: o.Lock, RefuseRetired: o.RefuseRetired})
	}
	return store.OpenSQLite(ctx, d.DSN, store.SQLiteOptions{Lock: o.Lock, RefuseRetired: o.RefuseRetired})
}

// settleLock waits out lockSettle after a controller took the PostgreSQL lock, and ends early when
// the lock is lost or ctx ends. SQLite has no such wait: its file lock ends with the process.
func settleLock(ctx context.Context, db *store.DB) error {
	if db.Dialect != store.Postgres || lockSettle <= 0 {
		return nil
	}
	t := time.NewTimer(lockSettle)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-db.LockLost():
		return ErrLockLost
	case <-ctx.Done():
		return ctx.Err()
	}
}
