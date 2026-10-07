// SPDX-License-Identifier: Apache-2.0

package s8

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// newStore opens a migrated store in a fresh temporary directory.
func newStore(t *testing.T, o Options) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.db")
	s, err := Open(path, o, 8)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s, path
}

// sqliteCode returns the SQLite result code of err, or -1.
func sqliteCode(err error) int {
	var e *sqlite.Error
	if errors.As(err, &e) {
		return e.Code()
	}
	return -1
}

func TestPlatformAndVersion(t *testing.T) {
	s, _ := newStore(t, DefaultOptions)
	var version string
	if err := s.R.QueryRow(`SELECT sqlite_version()`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("platform %s/%s, Go %s, SQLite %s", runtime.GOOS, runtime.GOARCH, runtime.Version(), version)
	// RETURNING (used by config_seq and token consumption, 04) needs SQLite >= 3.35.
	var major, minor int
	if _, err := fmt.Sscanf(version, "%d.%d", &major, &minor); err != nil {
		t.Fatalf("version %q: %v", version, err)
	}
	if major < 3 || (major == 3 && minor < 35) {
		t.Fatalf("SQLite %s lacks RETURNING", version)
	}
}

// TestPragmasOnEveryConnection checks that every pooled connection, writer and readers,
// carries the controller's settings, for both synchronous modes.
func TestPragmasOnEveryConnection(t *testing.T) {
	for _, mode := range []struct {
		name string
		want int
	}{{"FULL", 2}, {"NORMAL", 1}} {
		t.Run(mode.name, func(t *testing.T) {
			o := DefaultOptions
			o.Synchronous = mode.name
			s, _ := newStore(t, o)
			ctx := context.Background()
			check := func(db *sql.DB, who string, n int) {
				conns := make([]*sql.Conn, n)
				for i := range conns {
					c, err := db.Conn(ctx)
					if err != nil {
						t.Fatal(err)
					}
					conns[i] = c
				}
				defer func() {
					for _, c := range conns {
						c.Close()
					}
				}()
				for i, c := range conns {
					var journal string
					var busy, fk, sync int
					if err := c.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journal); err != nil {
						t.Fatal(err)
					}
					c.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busy)
					c.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk)
					c.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&sync)
					if journal != "wal" || busy != 5000 || fk != 1 || sync != mode.want {
						t.Errorf("%s connection %d: journal_mode=%s busy_timeout=%d foreign_keys=%d synchronous=%d",
							who, i, journal, busy, fk, sync)
					}
				}
			}
			check(s.W, "writer", 1)
			check(s.R, "reader", 8)
		})
	}
}

// TestReadersAreReadOnly: a reader connection refuses writes.
func TestReadersAreReadOnly(t *testing.T) {
	s, _ := newStore(t, DefaultOptions)
	_, err := s.R.Exec(`INSERT INTO orgs (id, name) VALUES ('org_x', 'x')`)
	if err == nil {
		t.Fatal("write through a query_only reader succeeded")
	}
	if code := sqliteCode(err) & 0xff; code != sqlite3.SQLITE_READONLY {
		t.Fatalf("want SQLITE_READONLY, got %v (code %d)", err, code)
	}
}

// TestInvalidInputRejected covers failure paths of opening a database.
func TestInvalidInputRejected(t *testing.T) {
	dir := t.TempDir()
	t.Run("unknown _txlock", func(t *testing.T) {
		db, _ := sql.Open("sqlite", "file:"+filepath.Join(dir, "a.db")+"?_txlock=bogus")
		defer db.Close()
		if err := db.Ping(); err == nil {
			t.Fatal("bogus _txlock accepted")
		}
	})
	// A _pragma value runs as SQL text, so by default anything after a ';' runs too; the
	// controller reads its DSN from the boot file, so it turns on sqlite.StrictPragmas.
	multi := "file:" + filepath.Join(dir, "b.db") + "?_pragma=foreign_keys(1)%3BDROP%20TABLE%20x"
	t.Run("multi-statement pragma runs by default", func(t *testing.T) {
		db, _ := sql.Open("sqlite", multi)
		defer db.Close()
		err := db.Ping()
		if err == nil || !strings.Contains(err.Error(), "no such table: x") {
			t.Fatalf("expected the DROP TABLE after ';' to run, got %v", err)
		}
	})
	t.Run("multi-statement pragma rejected with StrictPragmas", func(t *testing.T) {
		prev := sqlite.StrictPragmas(true)
		defer sqlite.StrictPragmas(prev)
		db, _ := sql.Open("sqlite", multi)
		defer db.Close()
		if err := db.Ping(); !errors.Is(err, sqlite.ErrMultiStatementPragma) {
			t.Fatalf("want ErrMultiStatementPragma, got %v", err)
		}
		// The controller's own DSN is accepted in strict mode.
		s, err := Open(filepath.Join(dir, "strict.db"), DefaultOptions, 1)
		if err != nil {
			t.Fatalf("controller DSN in strict mode: %v", err)
		}
		s.Close()
	})
	t.Run("missing directory", func(t *testing.T) {
		_, err := Open(filepath.Join(dir, "no", "such", "dir", "c.db"), DefaultOptions, 1)
		if err == nil {
			t.Fatal("open in a missing directory succeeded")
		}
	})
	t.Run("not a database", func(t *testing.T) {
		p := filepath.Join(dir, "garbage.db")
		if err := os.WriteFile(p, []byte(strings.Repeat("not a sqlite file ", 512)), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Open(p, DefaultOptions, 1)
		if err == nil {
			defer s.Close()
			_, err = s.R.Exec(`SELECT count(*) FROM sqlite_master`)
		}
		if err == nil || sqliteCode(err)&0xff != sqlite3.SQLITE_NOTADB {
			t.Fatalf("want SQLITE_NOTADB, got %v", err)
		}
	})
}

// TestCompositeForeignKeys: a row can never reference another org's row (06, "Tenancy
// enforcement"), and the referential actions work.
func TestCompositeForeignKeys(t *testing.T) {
	s, _ := newStore(t, DefaultOptions)
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO orgs (id, name) VALUES ('org_a', 'A'), ('org_b', 'B')`,
		`INSERT INTO connectors (id, org_id, name) VALUES ('con_a', 'org_a', 'nas'), ('con_b', 'org_b', 'nas')`,
		`INSERT INTO routes (id, org_id, name) VALUES ('rte_a', 'org_a', 'web'), ('rte_b', 'org_b', 'web')`,
	} {
		if _, err := s.W.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	ok := `INSERT INTO route_targets (id, org_id, route_id, connector_id, host, port) VALUES (?, ?, ?, ?, '127.0.0.1', 8080)`
	if _, err := s.W.ExecContext(ctx, ok, "tgt_1", "org_a", "rte_a", "con_a"); err != nil {
		t.Fatalf("same-org target: %v", err)
	}
	for _, c := range []struct{ name, org, route, conn string }{
		{"org B route uses org A connector", "org_b", "rte_b", "con_a"},
		{"org A route with org B connector", "org_a", "rte_a", "con_b"},
		{"target claims org A for org B route", "org_a", "rte_b", "con_a"},
		{"unknown connector", "org_a", "rte_a", "con_x"},
	} {
		_, err := s.W.ExecContext(ctx, ok, "tgt_x", c.org, c.route, c.conn)
		if sqliteCode(err) != sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY {
			t.Errorf("%s: want SQLITE_CONSTRAINT_FOREIGNKEY, got %v", c.name, err)
		}
	}
	// Moving a target to another org's route by UPDATE is refused as well.
	_, err := s.W.ExecContext(ctx, `UPDATE route_targets SET route_id = 'rte_b' WHERE id = 'tgt_1'`)
	if sqliteCode(err) != sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY {
		t.Errorf("cross-org update: want SQLITE_CONSTRAINT_FOREIGNKEY, got %v", err)
	}
	// NOT NULL org_id.
	_, err = s.W.ExecContext(ctx, `INSERT INTO routes (id, org_id, name) VALUES ('rte_n', NULL, 'n')`)
	if sqliteCode(err) != sqlite3.SQLITE_CONSTRAINT_NOTNULL {
		t.Errorf("NULL org_id: want SQLITE_CONSTRAINT_NOTNULL, got %v", err)
	}
	// RESTRICT: a connector that still serves a target cannot be deleted (06, "Lifecycle").
	// SQLite implements RESTRICT as an action trigger, so the extended code is
	// SQLITE_CONSTRAINT_TRIGGER, not SQLITE_CONSTRAINT_FOREIGNKEY; error mapping must accept both.
	_, err = s.W.ExecContext(ctx, `DELETE FROM connectors WHERE id = 'con_a'`)
	if sqliteCode(err) != sqlite3.SQLITE_CONSTRAINT_TRIGGER ||
		!strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
		t.Errorf("delete referenced connector: want SQLITE_CONSTRAINT_TRIGGER (FOREIGN KEY), got %v", err)
	}
	// CASCADE: deleting the route removes its targets.
	if _, err := s.W.ExecContext(ctx, `DELETE FROM routes WHERE id = 'rte_a'`); err != nil {
		t.Fatal(err)
	}
	var n int
	s.R.QueryRowContext(ctx, `SELECT count(*) FROM route_targets`).Scan(&n)
	if n != 0 {
		t.Errorf("cascade left %d targets", n)
	}
	rows, err := s.R.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Error("foreign_key_check reports violations")
	}
}

// TestOneWriterConcurrentReaders: readers never block or fail while the single writer commits,
// and every read transaction sees one consistent snapshot of whole commits.
func TestOneWriterConcurrentReaders(t *testing.T) {
	s, _ := newStore(t, DefaultOptions)
	ctx := context.Background()
	if _, err := s.W.Exec(`INSERT INTO orgs (id, name) VALUES ('org_a', 'A')`); err != nil {
		t.Fatal(err)
	}
	const batches, perBatch = 40, 50
	var done atomic.Bool
	var readerErr atomic.Value
	var reads atomic.Int64
	var wg sync.WaitGroup
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			last := 0
			for !done.Load() {
				tx, err := s.R.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
				if err != nil {
					readerErr.Store(err)
					return
				}
				var a, b int
				err1 := tx.QueryRowContext(ctx, `SELECT count(*) FROM routes`).Scan(&a)
				time.Sleep(time.Millisecond)
				err2 := tx.QueryRowContext(ctx, `SELECT count(*) FROM routes`).Scan(&b)
				tx.Rollback()
				switch {
				case err1 != nil || err2 != nil:
					readerErr.Store(fmt.Errorf("read: %v %v", err1, err2))
					return
				case a != b:
					readerErr.Store(fmt.Errorf("snapshot changed inside a read transaction: %d -> %d", a, b))
					return
				case a%perBatch != 0:
					readerErr.Store(fmt.Errorf("saw a partial commit: %d rows", a))
					return
				case a < last:
					readerErr.Store(fmt.Errorf("count went backwards: %d -> %d", last, a))
					return
				}
				last = a
				reads.Add(1)
			}
		}()
	}
	for b := 0; b < batches; b++ {
		tx, err := s.W.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < perBatch; i++ {
			if _, err := tx.Exec(`INSERT INTO routes (id, org_id, name) VALUES (?, 'org_a', ?)`,
				fmt.Sprintf("rte_%d_%d", b, i), fmt.Sprintf("r%d-%d", b, i)); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	done.Store(true)
	wg.Wait()
	if err, _ := readerErr.Load().(error); err != nil {
		t.Fatal(err)
	}
	var n int
	s.R.QueryRow(`SELECT count(*) FROM routes`).Scan(&n)
	if n != batches*perBatch {
		t.Fatalf("want %d rows, got %d", batches*perBatch, n)
	}
	if reads.Load() == 0 {
		t.Fatal("readers made no progress")
	}
	t.Logf("%d consistent read transactions during %d commits", reads.Load(), batches)
}

// TestBusyTimeout: a second writer (another process in production, e.g. `rpmgr backup` or an
// admin command) waits for busy_timeout, then gets SQLITE_BUSY; it succeeds when the first
// writer commits in time.
func TestBusyTimeout(t *testing.T) {
	_, path := newStore(t, DefaultOptions)
	ctx := context.Background()
	first, err := Open(path, DefaultOptions, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	t.Run("times out", func(t *testing.T) {
		o := DefaultOptions
		o.BusyTimeoutMS = 300
		second, err := Open(path, o, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		tx, err := first.W.BeginTx(ctx, nil) // BEGIN IMMEDIATE: holds the write lock
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		start := time.Now()
		_, err = second.W.Exec(`INSERT INTO orgs (id, name) VALUES ('org_t', 't')`)
		elapsed := time.Since(start)
		if sqliteCode(err)&0xff != sqlite3.SQLITE_BUSY {
			t.Fatalf("want SQLITE_BUSY, got %v", err)
		}
		if elapsed < 250*time.Millisecond {
			t.Fatalf("gave up after %v, before busy_timeout (300 ms)", elapsed)
		}
		t.Logf("SQLITE_BUSY after %v", elapsed)
	})
	t.Run("waits and succeeds", func(t *testing.T) {
		o := DefaultOptions
		o.BusyTimeoutMS = 5000
		second, err := Open(path, o, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		tx, err := first.W.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			time.Sleep(150 * time.Millisecond)
			tx.Commit()
		}()
		start := time.Now()
		if _, err := second.W.Exec(`INSERT INTO orgs (id, name) VALUES ('org_w', 'w')`); err != nil {
			t.Fatalf("second writer: %v", err)
		}
		if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
			t.Fatalf("second writer did not wait for the lock (%v)", elapsed)
		}
	})
}

// TestTransactionsUnderContention: configuration transactions from many goroutines and from two
// independent writer pools get unique, gap-free revisions in commit order (03, "Revisions and
// ordering"); a failing transaction rolls back completely, including its revision.
func TestTransactionsUnderContention(t *testing.T) {
	s, path := newStore(t, DefaultOptions)
	ctx := context.Background()
	if _, err := s.W.Exec(`INSERT INTO orgs (id, name) VALUES ('org_a', 'A')`); err != nil {
		t.Fatal(err)
	}
	other, err := Open(path, DefaultOptions, 1) // a second process's writer
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	const workers, perWorker = 16, 25
	var failed, rolledBack atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			db := s.W
			if w%2 == 1 {
				db = other.W
			}
			for i := 0; i < perWorker; i++ {
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					failed.Add(1)
					continue
				}
				if _, err := NextRevision(ctx, tx, fmt.Sprintf("w%d", w)); err != nil {
					tx.Rollback()
					failed.Add(1)
					continue
				}
				if i%10 == 9 { // a configuration change that violates a constraint
					_, err := tx.Exec(`INSERT INTO routes (id, org_id, name) VALUES (?, 'org_missing', 'x')`,
						fmt.Sprintf("rte_bad_%d_%d", w, i))
					if sqliteCode(err) != sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY {
						failed.Add(1)
					}
					tx.Rollback()
					rolledBack.Add(1)
					continue
				}
				if _, err := tx.Exec(`INSERT INTO routes (id, org_id, name) VALUES (?, 'org_a', ?)`,
					fmt.Sprintf("rte_%d_%d", w, i), fmt.Sprintf("r%d-%d", w, i)); err != nil {
					tx.Rollback()
					failed.Add(1)
					continue
				}
				if err := tx.Commit(); err != nil {
					failed.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()
	if failed.Load() != 0 {
		t.Fatalf("%d transactions failed unexpectedly", failed.Load())
	}
	committed := int64(workers*perWorker) - rolledBack.Load()
	var seq, revs, minSeq, maxSeq, routes int64
	s.R.QueryRow(`SELECT seq FROM config_seq`).Scan(&seq)
	s.R.QueryRow(`SELECT count(*), min(seq), max(seq) FROM config_revisions`).Scan(&revs, &minSeq, &maxSeq)
	s.R.QueryRow(`SELECT count(*) FROM routes`).Scan(&routes)
	if seq != committed || revs != committed || minSeq != 1 || maxSeq != committed || routes != committed {
		t.Fatalf("committed=%d: config_seq=%d revisions=%d [%d..%d] routes=%d",
			committed, seq, revs, minSeq, maxSeq, routes)
	}
}

// TestVacuumInto: `rpmgr backup` takes a consistent copy with VACUUM INTO while the controller
// keeps reading and writing (10, "Backup and restore"); the copy opens, passes integrity_check
// and can be used as the restored database.
func TestVacuumInto(t *testing.T) {
	s, _ := newStore(t, DefaultOptions)
	ctx := context.Background()
	if _, err := s.W.Exec(`INSERT INTO orgs (id, name) VALUES ('org_a', 'A');
		INSERT INTO connectors (id, org_id, name) VALUES ('con_a', 'org_a', 'nas')`); err != nil {
		t.Fatal(err)
	}
	const perBatch = 20
	var stop atomic.Bool
	var writes sync.WaitGroup
	writes.Add(1)
	go func() {
		defer writes.Done()
		for b := 0; !stop.Load(); b++ {
			tx, err := s.W.BeginTx(ctx, nil)
			if err != nil {
				return
			}
			for i := 0; i < perBatch; i++ {
				id := fmt.Sprintf("rte_%d_%d", b, i)
				tx.Exec(`INSERT INTO routes (id, org_id, name) VALUES (?, 'org_a', ?)`, id, id)
				tx.Exec(`INSERT INTO route_targets (id, org_id, route_id, connector_id, host, port)
					VALUES (?, 'org_a', ?, 'con_a', '10.0.0.1', 80)`, "tgt_"+id, id)
			}
			tx.Commit()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	dir := t.TempDir()
	backup := filepath.Join(dir, "backup.db")
	// A query_only connection refuses VACUUM INTO, so the backup uses its own ordinary
	// connection; VACUUM INTO only reads the source and does not take the write lock.
	ro, err := sql.Open("sqlite", DSN(s.pathOf(t), DefaultOptions, true))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, err := ro.ExecContext(ctx, `VACUUM INTO ?`, filepath.Join(dir, "ro.db")); sqliteCode(err)&0xff != sqlite3.SQLITE_READONLY {
		t.Errorf("VACUUM INTO on a query_only connection: want SQLITE_READONLY, got %v", err)
	}
	b, err := sql.Open("sqlite", DSN(s.pathOf(t), DefaultOptions, false))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	start := time.Now()
	if _, err := b.ExecContext(ctx, `VACUUM INTO ?`, backup); err != nil {
		t.Fatalf("VACUUM INTO: %v", err)
	}
	took := time.Since(start)
	stop.Store(true)
	writes.Wait()

	restored, err := Open(backup, DefaultOptions, 2)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer restored.Close()
	var integrity string
	restored.R.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	if integrity != "ok" {
		t.Fatalf("integrity_check of the backup: %s", integrity)
	}
	var routes, targets int
	restored.R.QueryRow(`SELECT count(*) FROM routes`).Scan(&routes)
	restored.R.QueryRow(`SELECT count(*) FROM route_targets`).Scan(&targets)
	if routes == 0 || routes%perBatch != 0 || routes != targets {
		t.Fatalf("backup is not a consistent commit boundary: %d routes, %d targets", routes, targets)
	}
	// The restored database works as a controller database.
	tx, err := restored.W.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NextRevision(ctx, tx, "restore"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Logf("backup taken under load in %v holds %d routes", took, routes)

	// Failure paths: the target exists, or its directory does not.
	if _, err := b.ExecContext(ctx, `VACUUM INTO ?`, backup); err == nil {
		t.Error("VACUUM INTO an existing file succeeded")
	}
	if _, err := b.ExecContext(ctx, `VACUUM INTO ?`, filepath.Join(dir, "missing", "x.db")); err == nil {
		t.Error("VACUUM INTO a missing directory succeeded")
	}
}

// pathOf returns the database file of the store.
func (s *Store) pathOf(t *testing.T) string {
	t.Helper()
	var seq int
	var name, file string
	if err := s.R.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &file); err != nil {
		t.Fatal(err)
	}
	return file
}
