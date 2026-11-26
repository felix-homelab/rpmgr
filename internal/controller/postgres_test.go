// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// The controller on PostgreSQL (docs/10-operations.md, "Boot files"; slice 8.6). These tests need
// a server in RPMGR_TEST_PG and skip without one.

// replica returns r's configuration with listeners of its own, as a second controller on the
// same boot file would have if it could start.
func (r *running) replica(t *testing.T) controller.RunOptions {
	t.Helper()
	c := r.cfg
	c.Listen.HTTPS, c.Listen.Admin = freeAddr(t), freeAddr(t)
	none := ""
	c.Listen.HTTP = &none
	return controller.RunOptions{Config: c, Getenv: func(string) string { return "" },
		Listening: func() { t.Error("a second controller started") }}
}

// TestPostgres_SecondControllerRefused: while one controller holds the database, a second one on
// it is refused by the advisory lock, and so is `rpmgr controller init`; commands that run beside
// a controller are not; when the first stops, the lock is free again.
func TestPostgres_SecondControllerRefused(t *testing.T) {
	r := startRunWith(t, runSetup{pg: true})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := controller.Run(ctx, r.replica(t)); !errors.Is(err, store.ErrLocked) {
		t.Errorf("a second controller: %v, want store.ErrLocked", err)
	}
	if _, err := controller.Init(ctx, r.h.opts()); !errors.Is(err, store.ErrLocked) {
		t.Errorf("init beside a controller: %v, want store.ErrLocked", err)
	}
	if _, err := controller.ResetPasswordLink(ctx, r.h.cfg, ""); err != nil {
		t.Errorf("a command beside the controller: %v", err)
	}
	r.stop(t)
	if _, err := controller.Init(ctx, r.h.opts()); !errors.Is(err, controller.ErrInitialised) {
		t.Errorf("init of an initialised database: %v, want ErrInitialised", err)
	}
	r2 := r.replica(t)
	listening := make(chan struct{})
	r2.Listening = func() { close(listening) }
	run, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- controller.Run(run, r2) }()
	select {
	case <-listening:
	case err := <-done:
		t.Fatalf("the controller after the first stopped: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the controller after the first stopped did not start")
	}
	stop()
	if err := <-done; err != nil {
		t.Errorf("stopping it: %v", err)
	}
}

// TestPostgres_DownAtStart: a database that is not there stops Run and init with an error that
// names PostgreSQL, promptly, and nothing listens.
func TestPostgres_DownAtStart(t *testing.T) {
	r := startRunWith(t, runSetup{pg: true})
	r.stop(t)
	down := r.replica(t)
	down.Listening = func() { t.Error("a controller started without its database") }
	down.Config.Database.DSN = "postgres://postgres@" + freeAddr(t) + "/rpmgr" // nothing listens there
	start := time.Now()
	err := controller.Run(context.Background(), down)
	if err == nil || !strings.Contains(err.Error(), "PostgreSQL") {
		t.Errorf("Run: %v, want an error that names PostgreSQL", err)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("Run took %s to give up", d)
	}

	h := newHost(t)
	if err := os.MkdirAll(filepath.Dir(h.db), 0o750); err != nil {
		t.Fatal(err)
	}
	boot := "version: 1\npublic_url: https://panel.example.com\n" + h.fileKEK() +
		"database: {driver: postgres, dsn: '" + down.Config.Database.DSN + "'}\n"
	if err := os.WriteFile(h.cfg, []byte(boot), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Init(context.Background(), h.opts()); err == nil || !strings.Contains(err.Error(), "PostgreSQL") {
		t.Errorf("init: %v, want an error that names PostgreSQL", err)
	}
}

// TestPostgres_PasswordFileRefused: a password file that is no good, or a DSN that carries a
// password, stops the controller before it connects, without naming the password.
func TestPostgres_PasswordFileRefused(t *testing.T) {
	r := startRunWith(t, runSetup{pg: true})
	r.stop(t)
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.WriteFile(loose, []byte("unused\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*controller.RunOptions){
		"a file that others can read": func(o *controller.RunOptions) { o.Config.Database.PasswordFile = loose },
		"a file that is not there":    func(o *controller.RunOptions) { o.Config.Database.PasswordFile += ".missing" },
		"a password in the DSN": func(o *controller.RunOptions) {
			o.Config.Database.DSN = strings.Replace(o.Config.Database.DSN, "postgres@", "postgres:unused@", 1)
		},
	} {
		o := r.replica(t)
		o.Listening = func() { t.Errorf("%s: the controller started", name) }
		edit(&o)
		err := controller.Run(context.Background(), o)
		if err == nil || strings.Contains(err.Error(), "unused") {
			t.Errorf("%s: %v, want an error that does not show the password", name, err)
		}
	}
}

// TestPostgres_LockLostStopsController: when the session that holds the lock ends, the controller
// stops with ErrLockLost (docs/06-data-model.md, "Connecting to PostgreSQL").
func TestPostgres_LockLostStopsController(t *testing.T) {
	r := startRunWith(t, runSetup{pg: true})
	db, err := storetest.OpenPostgres(t, r.cfg.Database.DSN, store.PostgresOptions{PasswordFile: r.cfg.Database.PasswordFile})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.Writer.QueryRow(`SELECT count(pg_terminate_backend(pid)) FROM pg_locks
 WHERE locktype = 'advisory' AND classid::bigint = 1919970663 AND objid::bigint = 2 AND granted`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ending the lock's session: %d %v", n, err)
	}
	select {
	case <-r.ended:
		if !errors.Is(r.err, controller.ErrLockLost) {
			t.Errorf("Run ended with %v, want ErrLockLost", r.err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the controller kept running without its lock")
	}
}

// TestPostgres_WaitsBeforeFirstWrite: a controller that has just taken the lock waits the stop
// bound before it writes anything, so that one that lost it is not writing at the same time.
func TestPostgres_WaitsBeforeFirstWrite(t *testing.T) {
	const settle = 800 * time.Millisecond
	var begin time.Time
	startRunWith(t, runSetup{pg: true, prepare: func(*running) {
		controller.SetLockSettle(t, settle)
		begin = time.Now()
	}})
	if d := time.Since(begin); d < settle {
		t.Errorf("the controller listened after %s, before the wait of %s", d, settle)
	}
}

// TestPostgres_SQLiteOnlyCommands: what works on a SQLite file only is refused with a message that
// says so, and touches nothing.
func TestPostgres_SQLiteOnlyCommands(t *testing.T) {
	r := startRunWith(t, runSetup{pg: true})
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "backup.tar")
	if _, err := controller.Backup(ctx, r.h.cfg, out, "0.1.0", time.Now); !errors.Is(err, controller.ErrSQLiteOnly) {
		t.Errorf("backup: %v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("backup created its output")
	}
	if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: r.h.cfg, Archive: out}); !errors.Is(err, controller.ErrSQLiteOnly) {
		t.Errorf("restore: %v", err)
	}
	if _, err := controller.Migrate(ctx, r.h.cfg, time.Now); !errors.Is(err, controller.ErrSQLiteOnly) {
		t.Errorf("migrate: %v", err)
	}
}
