// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// lockSettleMargin is added to the store's detection bound (store.LockStopBound) before a controller
// that has just taken the PostgreSQL controller lock writes: the server releases a lost session's
// lock only when it notices the loss, and the controller that lost it stops writing at once, but
// only when it has noticed (docs/03-connections.md, "Timeouts, keepalive and backoff").
const lockSettleMargin = 5 * time.Second

// lockSettle is the wait; a test replaces it.
var lockSettle = func() time.Duration { return store.LockStopBound() + lockSettleMargin }

// ErrLockLost is returned when the PostgreSQL session that holds a database's controller lock ends
// while the process works on it.
var ErrLockLost = store.ErrLockLost

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
	// Local is a command run from a shell: a password credential is then not loaded unless the
	// command runs under systemd-run, as with the KEK.
	Local bool
}

// openDatabase opens the database of cfg, whichever its driver, with the password of a PostgreSQL
// database read from its file or credential.
func openDatabase(ctx context.Context, cfg config.Controller, getenv func(string) string, o dbOptions) (*store.DB, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	d := cfg.Database
	if d.Driver == "postgres" {
		if o.Local && d.PasswordCredential != "" && getenv("CREDENTIALS_DIRECTORY") == "" {
			path := filepath.Join("/etc/rpmgr/credstore", d.PasswordCredential)
			return nil, fmt.Errorf("controller: the database password credential %s is not loaded: run the command under "+
				"systemd-run --pipe --wait --property=LoadCredentialEncrypted=%s:%s", d.PasswordCredential, d.PasswordCredential, path)
		}
		return store.OpenPostgres(ctx, d.DSN, store.PostgresOptions{PasswordFile: d.PasswordFile,
			PasswordCredential: d.PasswordCredential, Getenv: getenv, Lock: o.Lock, RefuseRetired: o.RefuseRetired})
	}
	return store.OpenSQLite(ctx, d.DSN, store.SQLiteOptions{Lock: o.Lock, RefuseRetired: o.RefuseRetired})
}

// settleLock waits out lockSettle after a controller (or a command that writes, as migrate-db does)
// took the PostgreSQL lock of dbs, and ends early when a lock is lost or ctx ends. SQLite has no
// such wait: its file lock ends with the process.
func settleLock(ctx context.Context, dbs ...*store.DB) error {
	wait := lockSettle()
	postgres := false
	for _, db := range dbs {
		postgres = postgres || db.Dialect == store.Postgres
	}
	if !postgres || wait <= 0 {
		return nil
	}
	lctx, cancel := untilLost(ctx, dbs...)
	defer cancel(nil)
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-lctx.Done():
		if errors.Is(context.Cause(lctx), ErrLockLost) {
			return ErrLockLost
		}
		return ctx.Err()
	}
}
