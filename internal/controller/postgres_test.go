// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/revlog"
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
			u, err := url.Parse(o.Config.Database.DSN)
			if err != nil {
				t.Fatal(err)
			}
			u.User = url.UserPassword(u.User.Username(), "unused")
			o.Config.Database.DSN = u.String()
		},
	} {
		o := r.replica(t)
		ctx, cancel := context.WithCancel(context.Background())
		o.Listening = func() { t.Errorf("%s: the controller started", name); cancel() }
		edit(&o)
		err := controller.Run(ctx, o)
		cancel()
		if err == nil || strings.Contains(err.Error(), "unused") {
			t.Errorf("%s: %v, want an error that does not show the password", name, err)
		}
	}
}

// TestPostgres_LockLostStopsController: when the session that holds the lock ends, the controller
// stops with ErrLockLost (docs/06-data-model.md, "Connecting to PostgreSQL").
func TestPostgres_LockLostStopsController(t *testing.T) {
	w := &warnings{}
	r := startRunWith(t, runSetup{pg: true, logger: slog.New(w)})
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
	// No drain and no final checkpoint: a controller that lost its lock writes nothing more, and
	// does not wait for its sessions or requests.
	for _, m := range w.all() {
		if strings.Contains(m, "final audit checkpoints") {
			t.Errorf("a controller without its lock tried its final checkpoints: %s", m)
		}
	}
}

// auditCount counts the audit entries through a connection that takes no lock.
func auditCount(t *testing.T, db *store.DB) int {
	t.Helper()
	var n int
	if err := db.Writer.QueryRow("SELECT count(*) FROM audit_log").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestPostgres_WaitsBeforeFirstWrite: a controller that has just taken the lock writes nothing for
// the settle time: the first audit entry of its start (a system scope's) lands after it, so that a
// controller that lost the lock is not writing at the same time.
func TestPostgres_WaitsBeforeFirstWrite(t *testing.T) {
	const settle = 1500 * time.Millisecond
	var begin time.Time
	var first atomic.Int64 // when the audit log first grew, unix nanoseconds
	done := make(chan struct{})
	startRunWith(t, runSetup{pg: true, prepare: func(r *running) {
		controller.SetLockSettle(t, settle)
		db, err := storetest.OpenPostgres(t, r.cfg.Database.DSN, store.PostgresOptions{PasswordFile: r.cfg.Database.PasswordFile})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		base := auditCount(t, db)
		begin = time.Now()
		go func() {
			for {
				select {
				case <-done:
					return
				case <-time.After(5 * time.Millisecond):
					var n int
					if db.Writer.QueryRow("SELECT count(*) FROM audit_log").Scan(&n) == nil && n != base {
						first.CompareAndSwap(0, time.Now().UnixNano())
						return
					}
				}
			}
		}()
	}})
	close(done)
	at := first.Load()
	if at == 0 {
		t.Fatal("the controller wrote no audit entry while starting; the test sees nothing")
	}
	if d := time.Unix(0, at).Sub(begin); d < settle {
		t.Errorf("the first write came %s after the start, before the settle time of %s", d, settle)
	}
}

// TestPostgres_StartsOnlyOnTheControllerHost: on PostgreSQL the node ID and the revocation log are
// files of the host, which init made on the controller host. A host without either refuses to
// start the controller, rather than start with an empty revocation log, until `rpmgr controller
// adopt-state` makes them on purpose.
func TestPostgres_StartsOnlyOnTheControllerHost(t *testing.T) {
	r := startRunWith(t, runSetup{pg: true})
	r.stop(t)
	state := r.cfg.State()
	for _, name := range []string{"controller-node.id", "revocations.log"} {
		if _, err := os.Stat(filepath.Join(state, name)); err != nil {
			t.Fatalf("init did not make %s: %v", name, err)
		}
	}
	ctx := context.Background()
	for _, name := range []string{"controller-node.id", "revocations.log"} {
		kept := filepath.Join(t.TempDir(), name)
		if err := os.Rename(filepath.Join(state, name), kept); err != nil {
			t.Fatal(err)
		}
		o := r.replica(t)
		if err := controller.Run(ctx, o); !errors.Is(err, controller.ErrNotControllerHost) {
			t.Errorf("a host without %s: %v, want ErrNotControllerHost", name, err)
		}
		if _, err := os.Stat(filepath.Join(state, name)); err == nil {
			t.Errorf("the refused start created %s", name)
		}
		if err := os.Rename(kept, filepath.Join(state, name)); err != nil {
			t.Fatal(err)
		}
	}
	// A host with neither: adopt-state makes both, an existing one is left alone.
	for _, name := range []string{"controller-node.id", "revocations.log"} {
		if err := os.Remove(filepath.Join(state, name)); err != nil {
			t.Fatal(err)
		}
	}
	made, err := controller.AdoptState(ctx, r.h.cfg)
	if err != nil || len(made) != 2 {
		t.Fatalf("adopt-state: %v %v", made, err)
	}
	if made, err := controller.AdoptState(ctx, r.h.cfg); err != nil || len(made) != 0 {
		t.Errorf("adopt-state again: %v %v", made, err)
	}
	o := r.replica(t)
	listening := make(chan struct{})
	o.Listening = func() { close(listening) }
	run, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- controller.Run(run, o) }()
	select {
	case <-listening:
	case err := <-done:
		t.Fatalf("the controller after adopt-state: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the controller after adopt-state did not start")
	}
	// It runs, so adopt-state is refused: it needs the database to itself.
	if _, err := controller.AdoptState(ctx, r.h.cfg); !errors.Is(err, controller.ErrStopController) {
		t.Errorf("adopt-state beside a controller: %v, want ErrStopController", err)
	}
	stop()
	<-done
}

// TestPostgres_LocalCommandsNeedTheControllerHost: `ca offline-root`, the warnings of `ca status`
// and `release import` use this host's revocation log and mirror, so on PostgreSQL they refuse a
// host that is not the controller's, and create nothing there.
func TestPostgres_LocalCommandsNeedTheControllerHost(t *testing.T) {
	r := startRunWith(t, runSetup{pg: true})
	r.stop(t)
	ctx := context.Background()
	logPath := filepath.Join(r.cfg.State(), "revocations.log")
	kept := logPath + ".moved"
	if err := os.Rename(logPath, kept); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "root.age")
	_, err := controller.OfflineRoot(ctx, controller.OfflineRootOptions{ConfigPath: r.h.cfg, Out: out, Passphrase: suppliedPass, Getenv: noEnv})
	if !errors.Is(err, controller.ErrNotControllerHost) {
		t.Errorf("ca offline-root on another host: %v, want ErrNotControllerHost", err)
	}
	for _, p := range []string{out, logPath} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("the refused command created %s", p)
		}
	}
	if _, err := controller.CAStatusWarnings(ctx, r.h.cfg); !errors.Is(err, controller.ErrNotControllerHost) {
		t.Errorf("ca status warnings on another host: %v, want ErrNotControllerHost", err)
	}
	if _, err := controller.ImportRelease(ctx, r.h.cfg, t.TempDir(), "1.2.3", nil, time.Now); !errors.Is(err, controller.ErrNotControllerHost) {
		t.Errorf("release import on another host: %v, want ErrNotControllerHost", err)
	}
	// On the controller host the ceremony works on PostgreSQL and marks this host's log.
	if err := os.Rename(kept, logPath); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.OfflineRoot(ctx, controller.OfflineRootOptions{ConfigPath: r.h.cfg, Out: out, Passphrase: suppliedPass, Getenv: noEnv}); err != nil {
		t.Fatalf("ca offline-root on the controller host: %v", err)
	}
	entries, err := revlog.Read(logPath)
	if err != nil || len(entries) == 0 || entries[len(entries)-1].Kind != revlog.RootOffline {
		t.Errorf("the log after the ceremony: %v %v", entries, err)
	}
}

// TestPostgres_PasswordCredentialInAShell: a command run from a shell cannot read a systemd
// credential, and says how to run it under systemd-run, as for the KEK; with the credential
// directory set it works, which is what makes `rpmgr user reset-password` usable.
func TestPostgres_PasswordCredentialInAShell(t *testing.T) {
	r := startRunWith(t, runSetup{pg: true})
	pw, err := os.ReadFile(r.cfg.Database.PasswordFile)
	if err != nil {
		t.Fatal(err)
	}
	cred := filepath.Join(r.h.dir, "creds")
	if err := os.MkdirAll(cred, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cred, "dbpw"), pw, 0o600); err != nil { //nolint:gosec // G703: a path under the test's directory
		t.Fatal(err)
	}
	boot := filepath.Join(r.h.dir, "controller-credential.yaml")
	text := "version: 1\npublic_url: " + r.url + "\ndatabase: {driver: postgres, dsn: '" + r.cfg.Database.DSN + "', password_credential: dbpw}\n" + r.h.fileKEK()
	if err := os.WriteFile(boot, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	_, err = controller.ResetPasswordLink(ctx, boot, "")
	if err == nil || !strings.Contains(err.Error(), "systemd-run") || !strings.Contains(err.Error(), "LoadCredentialEncrypted=dbpw:") {
		t.Errorf("reset-password from a shell: %v, want the systemd-run hint", err)
	}
	if _, err := controller.ConfirmRestore(ctx, boot, ""); err == nil || !strings.Contains(err.Error(), "systemd-run") {
		t.Errorf("restore confirm from a shell: %v, want the systemd-run hint", err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", cred)
	if _, err := controller.ResetPasswordLink(ctx, boot, ""); err != nil {
		t.Errorf("reset-password with the credential loaded: %v", err)
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
	// kek rotate needs the controller stopped, which a SQLite file lock ensures and a PostgreSQL
	// database would not: it is refused before it opens anything, controller running or not.
	if _, _, err := controller.RotateKEK(ctx, r.h.cfg, controller.PreviousKEK{File: r.h.kek}, func(string) string { return "" }); !errors.Is(err, controller.ErrSQLiteOnly) {
		t.Errorf("kek rotate beside a running controller: %v", err)
	}
	if _, err := controller.Migrate(ctx, r.h.cfg, time.Now); !errors.Is(err, controller.ErrSQLiteOnly) {
		t.Errorf("migrate: %v", err)
	}
}
