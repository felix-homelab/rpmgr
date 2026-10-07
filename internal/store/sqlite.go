// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// The DSN is built from the path in the boot file, so a _pragma that the path smuggled in must not
// run more than one statement (S8; docs/06-data-model.md, "Database engines").
func init() { sqlite.StrictPragmas(true) }

// SQLiteOptions are the per-database settings of OpenSQLite.
type SQLiteOptions struct {
	// BusyTimeout is how long a writer waits for another process's write lock; default 5 s.
	BusyTimeout time.Duration
	// Readers is the size of the read-only pool; default 4.
	Readers int
	// Lock holds the controller lock for as long as the database is open, so a second controller
	// on the same database refuses to start (one controller per SQLite database). Administration
	// commands that run next to a controller leave it off.
	Lock bool
}

// DB is an opened database. On SQLite, Writer is the single writer connection and Reader a pool of
// read-only connections (docs/06-data-model.md, "Database engines").
type DB struct {
	Dialect string
	Path    string // SQLite only
	Writer  *sql.DB
	Reader  *sql.DB
	unlock  func() error
}

// ErrLocked is returned when another controller holds the database.
var ErrLocked = errors.New("store: another controller is using this database")

// OpenSQLite opens the SQLite database at path, creating it if needed. Every connection gets the
// controller's pragmas, and the open fails if any connection does not enforce foreign keys.
func OpenSQLite(ctx context.Context, path string, o SQLiteOptions) (*DB, error) {
	if o.BusyTimeout <= 0 {
		o.BusyTimeout = 5 * time.Second
	}
	if o.Readers <= 0 {
		o.Readers = 4
	}
	if path == "" || strings.ContainsAny(path, "?#%") {
		return nil, fmt.Errorf("store: SQLite path %q: must not be empty or contain '?', '#' or '%%'", path)
	}
	db := &DB{Dialect: SQLite, Path: path, unlock: func() error { return nil }}
	if o.Lock {
		unlock, err := lockFile(path + ".lock")
		if err != nil {
			return nil, err
		}
		db.unlock = unlock
	}
	var err error
	if db.Writer, err = openPool(ctx, sqliteDSN(path, o.BusyTimeout, false), 1); err != nil {
		_ = db.Close()
		return nil, err
	}
	if db.Reader, err = openPool(ctx, sqliteDSN(path, o.BusyTimeout, true), o.Readers); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// sqliteDSN returns the DSN of one pool. busy_timeout comes first, so that the pragmas after it
// already wait for another process that is switching the file to WAL (S6).
func sqliteDSN(path string, busy time.Duration, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busy.Milliseconds()))
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Set("_txlock", "immediate") // a writer takes the write lock at BEGIN, not mid-transaction
	}
	return "file:" + path + "?" + q.Encode()
}

// openPool opens a pool of n connections and checks every one of them. Opening a new database can
// return SQLITE_BUSY without waiting while another process switches it to WAL (S6), so the first
// connections are retried a few times.
func openPool(ctx context.Context, dsn string, n int) (*sql.DB, error) {
	pool, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	pool.SetMaxOpenConns(n)
	pool.SetMaxIdleConns(n)
	pool.SetConnMaxIdleTime(0)
	conns := make([]*sql.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for i := 0; i < n; i++ {
		c, err := connWithRetry(ctx, pool)
		if err == nil {
			conns = append(conns, c)
			err = checkConn(ctx, c)
		}
		if err != nil {
			_ = pool.Close()
			return nil, fmt.Errorf("store: open SQLite: %w", err)
		}
	}
	return pool, nil
}

func connWithRetry(ctx context.Context, pool *sql.DB) (*sql.Conn, error) {
	delay := 20 * time.Millisecond
	for attempt := 1; ; attempt++ {
		c, err := pool.Conn(ctx)
		if err == nil {
			if err = c.PingContext(ctx); err == nil {
				return c, nil
			}
			_ = c.Close()
		}
		if sqliteCode(err)&0xff != sqlite3.SQLITE_BUSY || attempt == 8 {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// checkConn refuses a connection that does not enforce foreign keys or is not in WAL mode:
// SQLite enforces no foreign key, composite or not, without the pragma (S5).
func checkConn(ctx context.Context, c *sql.Conn) error {
	var fk int
	if err := c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
		return err
	}
	if fk != 1 {
		return errors.New("foreign keys are not enforced on a connection")
	}
	var journal string
	if err := c.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return err
	}
	if journal != "wal" {
		return fmt.Errorf("journal mode is %q, not wal", journal)
	}
	return nil
}

// Close closes the pools and releases the controller lock.
func (db *DB) Close() error {
	var errs []error
	if db.Writer != nil {
		errs = append(errs, db.Writer.Close())
	}
	if db.Reader != nil && db.Reader != db.Writer {
		errs = append(errs, db.Reader.Close())
	}
	errs = append(errs, db.unlock())
	return errors.Join(errs...)
}

// VacuumInto writes a consistent copy of the SQLite database to target while readers and the
// writer keep working: before migrations and for `rpmgr backup` (S8). It needs an ordinary
// connection, because a query_only one refuses it, but it takes no write lock. An existing target
// is refused.
func (db *DB) VacuumInto(ctx context.Context, target string) error {
	if db.Dialect != SQLite {
		return fmt.Errorf("store: VACUUM INTO needs SQLite, not %s", db.Dialect)
	}
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("store: backup target %s exists", target)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	pool, err := sql.Open("sqlite", sqliteDSN(db.Path, 5*time.Second, false))
	if err != nil {
		return err
	}
	defer func() { _ = pool.Close() }()
	if _, err := pool.ExecContext(ctx, "VACUUM INTO ?", target); err != nil {
		return fmt.Errorf("store: VACUUM INTO %s: %w", target, err)
	}
	return nil
}
