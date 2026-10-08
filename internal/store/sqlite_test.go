// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"modernc.org/sqlite"

	"github.com/felix-homelab/rpmgr/internal/store"
)

const testTables = `
CREATE TABLE parents (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE children (
  id TEXT PRIMARY KEY,
  parent_id TEXT NOT NULL REFERENCES parents (id) ON DELETE RESTRICT,
  payload TEXT NOT NULL DEFAULT ''
);`

func openTest(t *testing.T, path string, o store.SQLiteOptions) *store.DB {
	t.Helper()
	db, err := store.OpenSQLite(context.Background(), path, o)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newTestDB(t *testing.T, o store.SQLiteOptions) (*store.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.db")
	db := openTest(t, path, o)
	if _, err := db.Writer.Exec(testTables); err != nil {
		t.Fatal(err)
	}
	return db, path
}

func TestOpenSQLite_PragmasOnEveryConnection(t *testing.T) {
	db, _ := newTestDB(t, store.SQLiteOptions{Readers: 8, BusyTimeout: 4 * time.Second})
	ctx := context.Background()
	check := func(pool *sql.DB, who string, n int, readOnly int) {
		conns := make([]*sql.Conn, n)
		for i := range conns {
			c, err := pool.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			conns[i] = c
		}
		defer func() {
			for _, c := range conns {
				_ = c.Close()
			}
		}()
		for i, c := range conns {
			var journal string
			var busy, fk, syncMode, queryOnly int
			for q, dst := range map[string]any{
				"PRAGMA journal_mode": &journal, "PRAGMA busy_timeout": &busy, "PRAGMA foreign_keys": &fk,
				"PRAGMA synchronous": &syncMode, "PRAGMA query_only": &queryOnly,
			} {
				if err := c.QueryRowContext(ctx, q).Scan(dst); err != nil {
					t.Fatalf("%s: %v", q, err)
				}
			}
			if journal != "wal" || busy != 4000 || fk != 1 || syncMode != 2 || queryOnly != readOnly {
				t.Errorf("%s connection %d: journal_mode=%s busy_timeout=%d foreign_keys=%d synchronous=%d query_only=%d",
					who, i, journal, busy, fk, syncMode, queryOnly)
			}
		}
	}
	check(db.Writer, "writer", 1, 0)
	check(db.Reader, "reader", 8, 1)
}

func TestOpenSQLite_ReadersAreReadOnly(t *testing.T) {
	db, _ := newTestDB(t, store.SQLiteOptions{})
	if _, err := db.Reader.Exec(`INSERT INTO parents (id, name) VALUES ('p', 'p')`); err == nil {
		t.Fatal("a write through the read-only pool succeeded")
	}
}

func TestOpenSQLite_InvalidInput(t *testing.T) {
	dir := t.TempDir()
	if !sqlite.StrictPragmasEnabled() {
		t.Error("StrictPragmas is not enabled by the store")
	}
	for _, p := range []string{
		"", filepath.Join(dir, "a.db?_pragma=foreign_keys(0)"), filepath.Join(dir, "b.db#x"),
		filepath.Join(dir, "c%3F.db"),
	} {
		if _, err := store.OpenSQLite(context.Background(), p, store.SQLiteOptions{}); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	if _, err := store.OpenSQLite(context.Background(), filepath.Join(dir, "no", "dir", "x.db"), store.SQLiteOptions{}); err == nil {
		t.Error("a database in a missing directory opened")
	}
	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, []byte(strings.Repeat("not a sqlite file ", 512)), 0o600); err != nil {
		t.Fatal(err)
	}
	if db, err := store.OpenSQLite(context.Background(), garbage, store.SQLiteOptions{}); err == nil {
		_ = db.Close()
		t.Error("a file that is not a database opened")
	}
}

func TestOpenSQLite_ReadersSeeWholeCommits(t *testing.T) {
	db, _ := newTestDB(t, store.SQLiteOptions{Readers: 8})
	ctx := context.Background()
	if _, err := db.Writer.Exec(`INSERT INTO parents (id, name) VALUES ('p', 'p')`); err != nil {
		t.Fatal(err)
	}
	const batches, perBatch = 30, 50
	var done atomic.Bool
	var readerErr atomic.Value
	var reads atomic.Int64
	var wg sync.WaitGroup
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !done.Load() {
				tx, err := db.Reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
				if err != nil {
					readerErr.Store(err)
					return
				}
				var a, b int
				err1 := tx.QueryRowContext(ctx, `SELECT count(*) FROM children`).Scan(&a)
				time.Sleep(time.Millisecond)
				err2 := tx.QueryRowContext(ctx, `SELECT count(*) FROM children`).Scan(&b)
				_ = tx.Rollback()
				switch {
				case err1 != nil || err2 != nil:
					readerErr.Store(fmt.Errorf("read: %w", errors.Join(err1, err2)))
					return
				case a != b || a%perBatch != 0:
					readerErr.Store(fmt.Errorf("inconsistent snapshot: %d then %d", a, b))
					return
				}
				reads.Add(1)
			}
		}()
	}
	for b := 0; b < batches; b++ {
		tx, err := db.Writer.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < perBatch; i++ {
			if _, err := tx.Exec(`INSERT INTO children (id, parent_id) VALUES (?, 'p')`, fmt.Sprintf("c%d_%d", b, i)); err != nil {
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
	if reads.Load() == 0 {
		t.Fatal("readers made no progress")
	}
}

func TestOpenSQLite_BusyTimeout(t *testing.T) {
	first, path := newTestDB(t, store.SQLiteOptions{})
	second := openTest(t, path, store.SQLiteOptions{BusyTimeout: 300 * time.Millisecond})
	tx, err := first.Writer.Begin() // BEGIN IMMEDIATE holds the write lock
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = second.Writer.Exec(`INSERT INTO parents (id, name) VALUES ('x', 'x')`)
	if err == nil || time.Since(start) < 250*time.Millisecond {
		t.Errorf("second writer: %v after %v; want SQLITE_BUSY after the busy timeout", err, time.Since(start))
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = tx.Commit()
	}()
	waiting := openTest(t, path, store.SQLiteOptions{BusyTimeout: 5 * time.Second})
	if _, err := waiting.Writer.Exec(`INSERT INTO parents (id, name) VALUES ('y', 'y')`); err != nil {
		t.Errorf("writer that waits: %v", err)
	}
}

func TestOpenSQLite_ControllerLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	first, err := store.OpenSQLite(context.Background(), path, store.SQLiteOptions{Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenSQLite(context.Background(), path, store.SQLiteOptions{Lock: true}); !errors.Is(err, store.ErrLocked) {
		t.Errorf("second controller: %v, want ErrLocked", err)
	}
	admin := openTest(t, path, store.SQLiteOptions{}) // an administration command next to it
	if err := admin.Reader.Ping(); err != nil {
		t.Errorf("unlocked open next to a controller: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := store.OpenSQLite(context.Background(), path, store.SQLiteOptions{Lock: true})
	if err != nil {
		t.Fatalf("lock not released by Close: %v", err)
	}
	_ = again.Close()
}

func TestVacuumInto(t *testing.T) {
	db, _ := newTestDB(t, store.SQLiteOptions{})
	ctx := context.Background()
	if _, err := db.Writer.Exec(`INSERT INTO parents (id, name) VALUES ('p', 'p')`); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var writes sync.WaitGroup
	writes.Add(1)
	go func() {
		defer writes.Done()
		for i := 0; !stop.Load(); i++ {
			_, _ = db.Writer.Exec(`INSERT INTO children (id, parent_id) VALUES (?, 'p')`, fmt.Sprintf("c%d", i))
		}
	}()
	time.Sleep(50 * time.Millisecond)
	dir := t.TempDir()
	backup := filepath.Join(dir, "backup.db")
	err := db.VacuumInto(ctx, backup)
	stop.Store(true)
	writes.Wait()
	if err != nil {
		t.Fatalf("VacuumInto under write load: %v", err)
	}
	copyDB := openTest(t, backup, store.SQLiteOptions{})
	var integrity string
	if err := copyDB.Reader.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Errorf("backup integrity_check: %q, %v", integrity, err)
	}
	var n int
	if err := copyDB.Reader.QueryRow(`SELECT count(*) FROM parents`).Scan(&n); err != nil || n != 1 {
		t.Errorf("backup content: %d parents, %v", n, err)
	}
	if err := db.VacuumInto(ctx, backup); err == nil {
		t.Error("VacuumInto overwrote an existing file")
	}
	if err := db.VacuumInto(ctx, filepath.Join(dir, "missing", "b.db")); err == nil {
		t.Error("VacuumInto into a missing directory succeeded")
	}
	if err := (&store.DB{Dialect: store.Postgres}).VacuumInto(ctx, filepath.Join(dir, "pg.db")); err == nil {
		t.Error("VacuumInto on PostgreSQL succeeded")
	}
}

func TestErrorMapping(t *testing.T) {
	db, _ := newTestDB(t, store.SQLiteOptions{})
	if _, err := db.Writer.Exec(`INSERT INTO parents (id, name) VALUES ('p', 'p')`); err != nil {
		t.Fatal(err)
	}
	_, err := db.Writer.Exec(`INSERT INTO children (id, parent_id) VALUES ('c1', 'missing')`)
	if !store.IsForeignKeyViolation(err) || store.IsUniqueViolation(err) {
		t.Errorf("missing parent: %v not mapped to a foreign-key violation", err)
	}
	if _, err := db.Writer.Exec(`INSERT INTO children (id, parent_id) VALUES ('c1', 'p')`); err != nil {
		t.Fatal(err)
	}
	_, err = db.Writer.Exec(`DELETE FROM parents WHERE id = 'p'`)
	if !store.IsForeignKeyViolation(err) {
		t.Errorf("ON DELETE RESTRICT: %v not mapped to a foreign-key violation", err)
	}
	_, err = db.Writer.Exec(`INSERT INTO parents (id, name) VALUES ('q', 'p')`)
	if !store.IsUniqueViolation(err) || store.IsForeignKeyViolation(err) {
		t.Errorf("duplicate name: %v not mapped to a unique violation", err)
	}
	_, err = db.Writer.Exec(`INSERT INTO parents (id, name) VALUES ('p', 'other')`)
	if !store.IsUniqueViolation(err) {
		t.Errorf("duplicate primary key: %v not mapped to a unique violation", err)
	}
	for _, other := range []error{nil, errors.New("x"), sql.ErrNoRows} {
		if store.IsForeignKeyViolation(other) || store.IsUniqueViolation(other) {
			t.Errorf("%v mapped to a constraint violation", other)
		}
	}
}

// The crash test kills a writer in a child process (this test binary, run again) inside a large
// uncommitted transaction and during a checkpoint, then reopens the database (S8).
const (
	envCrashChild = "RPMGR_STORE_CRASH_CHILD"
	envCrashDB    = "RPMGR_STORE_CRASH_DB"
)

func TestCrashChild(t *testing.T) {
	mode := os.Getenv(envCrashChild)
	if mode == "" {
		t.Skip("child process only")
	}
	db, err := store.OpenSQLite(context.Background(), os.Getenv(envCrashDB), store.SQLiteOptions{})
	if err != nil {
		fmt.Println("error", err)
		os.Exit(2)
	}
	if _, err := db.Writer.Exec(`PRAGMA cache_size = -256`); err != nil { // spill pages to the WAL early
		fmt.Println("error", err)
		os.Exit(2)
	}
	out := bufio.NewWriter(os.Stdout)
	payload := strings.Repeat("x", 4096)
	for i := 1; ; i++ {
		tx, err := db.Writer.Begin()
		if err != nil {
			fmt.Println("error", err)
			os.Exit(2)
		}
		if _, err := tx.Exec(`INSERT INTO parents (id, name) VALUES (?, ?)`, strconv.Itoa(i), strconv.Itoa(i)); err != nil {
			fmt.Println("error", err)
			os.Exit(2)
		}
		if mode == "commit" && i == 40 {
			for j := 0; j < 5000; j++ {
				if _, err := tx.Exec(`INSERT INTO children (id, parent_id, payload) VALUES (?, ?, ?)`,
					fmt.Sprintf("u%d", j), strconv.Itoa(i), payload); err != nil {
					fmt.Println("error", err)
					os.Exit(2)
				}
			}
			fmt.Fprintln(out, "in-tx")
			_ = out.Flush()
			time.Sleep(time.Hour)
		}
		if err := tx.Commit(); err != nil {
			fmt.Println("error", err)
			os.Exit(2)
		}
		fmt.Fprintf(out, "committed %d\n", i)
		_ = out.Flush()
		if mode == "checkpoint" && i%5 == 0 {
			_, _ = db.Writer.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		}
	}
}

func TestCrashRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("starts child processes")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "checkpoint"} {
		t.Run(mode, func(t *testing.T) {
			db, path := newTestDB(t, store.SQLiteOptions{})
			_ = db.Close()
			cmd := exec.Command(exe, "-test.run=^TestCrashChild$", "-test.v=false")
			cmd.Env = append(os.Environ(), envCrashChild+"="+mode, envCrashDB+"="+path)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.AfterFunc(5*time.Minute, func() { _ = cmd.Process.Kill() })
			defer deadline.Stop()
			last, killed := 0, false
			sc := bufio.NewScanner(stdout)
			for !killed && sc.Scan() {
				line := sc.Text()
				switch {
				case strings.HasPrefix(line, "committed "):
					last, _ = strconv.Atoi(strings.TrimPrefix(line, "committed "))
					if mode == "checkpoint" && last == 60 {
						_ = cmd.Process.Signal(syscall.SIGKILL)
						killed = true
					}
				case line == "in-tx":
					_ = cmd.Process.Signal(syscall.SIGKILL)
					killed = true
				case strings.HasPrefix(line, "error"):
					t.Fatalf("child: %s", line)
				}
			}
			// Reports the child wrote before it died may still be in the pipe: under load the
			// child runs well ahead of this loop. The last of them is its last commit.
			for sc.Scan() {
				if n, ok := strings.CutPrefix(sc.Text(), "committed "); ok {
					last, _ = strconv.Atoi(n)
				}
			}
			_ = cmd.Wait()
			if !killed {
				t.Fatalf("child ended before it was killed (last commit %d)", last)
			}
			re := openTest(t, path, store.SQLiteOptions{})
			var integrity string
			var parents, uncommitted int
			_ = re.Reader.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
			_ = re.Reader.QueryRow(`SELECT count(*) FROM parents`).Scan(&parents)
			_ = re.Reader.QueryRow(`SELECT count(*) FROM children`).Scan(&uncommitted)
			if integrity != "ok" {
				t.Fatalf("integrity_check after the crash: %s", integrity)
			}
			// No reported commit may be lost. The child runs on while its reports are read and the
			// signal is delivered, so it may have committed a few more; under load two were seen.
			if parents < last || parents > last+10 || uncommitted != 0 {
				t.Fatalf("last reported commit %d; after recovery %d parents, %d uncommitted children", last, parents, uncommitted)
			}
			if _, err := re.Writer.Exec(`INSERT INTO parents (id, name) VALUES ('after', 'after')`); err != nil {
				t.Fatalf("database not writable after recovery: %v", err)
			}
		})
	}
}
