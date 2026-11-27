// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// stoppedPGController starts a controller on PostgreSQL, stops it and backs it up with its own
// boot file: the controller host, whose state directory the commands use.
func stoppedPGController(t *testing.T) (r *running, archive, nodeID string) {
	t.Helper()
	controller.SetLockSettle(t, 0)
	r = startRunWith(t, runSetup{pg: true})
	r.stop(t)
	archive = filepath.Join(t.TempDir(), "rpmgr.backup")
	if _, err := controller.Backup(context.Background(), r.h.cfg, archive, "2.0.0", time.Now); err != nil {
		t.Fatalf("backup of the controller host: %v", err)
	}
	id, err := os.ReadFile(filepath.Join(r.cfg.State(), "controller-node.id"))
	if err != nil {
		t.Fatal(err)
	}
	return r, archive, strings.TrimSpace(string(id))
}

// restoredReplica restores archive into a new PostgreSQL database, with the state directory in
// force, and returns the options of a controller that runs on it, with that directory.
func restoredReplica(t *testing.T, r *running, archive, state string) (controller.RunOptions, string, error) {
	t.Helper()
	boot, _ := pgDatabase(t)
	d, err := config.LoadDatabase(boot)
	if err != nil {
		t.Fatal(err)
	}
	_, err = controller.Restore(context.Background(), controller.RestoreOptions{ConfigPath: boot, Archive: archive,
		RevocationLogs: []string{filepath.Join(r.cfg.State(), "revocations.log")}})
	o := r.replica(t)
	o.Config.Database = d
	o.Config.StateDir = state
	return o, boot, err
}

func activeNode(t *testing.T, boot string) string {
	t.Helper()
	var id *string
	if err := openBoot(t, boot).Reader.QueryRowContext(context.Background(), "SELECT active_node FROM instance").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if id == nil {
		return ""
	}
	return *id
}

func startOnce(t *testing.T, o controller.RunOptions) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rctx, stop := context.WithCancel(ctx)
	o.Listening = func() { stop() } // it started: that is all this looks at
	return controller.Run(rctx, o)
}

// TestRestorePostgres_SameHostThenStart: a restore on the controller host leaves its node ID, names
// it in the database and claims the fence, so that the controller starts on the restored database.
func TestRestorePostgres_SameHostThenStart(t *testing.T) {
	r, archive, id := stoppedPGController(t)
	o, boot, err := restoredReplica(t, r, archive, r.cfg.State())
	if err != nil {
		t.Fatalf("restore on the controller host: %v", err)
	}
	if got := activeNode(t, boot); got != id {
		t.Errorf("active_node after the restore %q, want this host's %q", got, id)
	}
	if now, _ := os.ReadFile(filepath.Join(r.cfg.State(), "controller-node.id")); strings.TrimSpace(string(now)) != id {
		t.Errorf("the restore changed this host's node ID to %q", now)
	}
	var epoch *int64
	if err := openBoot(t, boot).Reader.QueryRowContext(context.Background(), "SELECT fence_epoch FROM instance").Scan(&epoch); err != nil || epoch == nil || *epoch < 1 {
		t.Errorf("the fence epoch after the restore: %v %v", epoch, err)
	}
	if err := startOnce(t, o); err != nil {
		t.Errorf("the controller on the restored database, same host: %v", err)
	}
}

// TestRestorePostgres_NewHostThenStart: a restore on a host with an empty state directory makes it
// the controller host: it gets a node ID and the restored revocation log, the database names it,
// the controller starts there and the host of the backup, with its files intact, is refused.
func TestRestorePostgres_NewHostThenStart(t *testing.T) {
	r, archive, idA := stoppedPGController(t)
	stateB := t.TempDir()
	controller.SetStateDir(t, stateB)
	o, boot, err := restoredReplica(t, r, archive, stateB)
	if err != nil {
		t.Fatalf("restore on a new host: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(stateB, "controller-node.id"))
	if err != nil {
		t.Fatalf("the restore left no node ID on the new host: %v", err)
	}
	idB := strings.TrimSpace(string(b))
	if idB == "" || idB == idA {
		t.Fatalf("the new host's node ID %q, the old host's %q", idB, idA)
	}
	if fi, err := os.Stat(filepath.Join(stateB, "controller-node.id")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("node ID file: %v %v", fi, err)
	}
	if got := activeNode(t, boot); got != idB {
		t.Errorf("active_node after the restore %q, want the new host's %q", got, idB)
	}
	if !bytes.Equal([]byte(fileBytes(t, filepath.Join(stateB, "revocations.log"))), []byte(fileBytes(t, filepath.Join(r.cfg.State(), "revocations.log")))) {
		t.Error("the new host's revocation log is not the restored one")
	}
	if err := startOnce(t, o); err != nil {
		t.Errorf("the controller on the new host: %v", err)
	}
	// Host A comes back with its files intact: the database names B.
	oa := r.replica(t)
	oa.Config.Database = o.Config.Database
	oa.Config.StateDir = r.cfg.State()
	if err := startOnce(t, oa); !errors.Is(err, controller.ErrHostReplaced) {
		t.Errorf("the old host after a restore elsewhere: %v, want ErrHostReplaced", err)
	}
}

// TestRestorePostgres_BadNodeIDRefused: a node ID file that holds no ID, or is no regular file, is
// refused before anything is written.
func TestRestorePostgres_BadNodeIDRefused(t *testing.T) {
	r, archive, _ := stoppedPGController(t)
	for name, plant := range map[string]func(p string) error{
		"garbage": func(p string) error { return os.WriteFile(p, []byte("not an id\n"), 0o600) },
		"link":    func(p string) error { return os.Symlink("/etc/hostname", p) },
	} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			controller.SetStateDir(t, state)
			if err := plant(filepath.Join(state, "controller-node.id")); err != nil {
				t.Fatal(err)
			}
			_, boot, err := restoredReplica(t, r, archive, state)
			if err == nil {
				t.Fatal("restored over a bad node ID file")
			}
			if n := tableCount(t, boot); n != 0 {
				t.Errorf("a refused restore left %d tables", n)
			}
		})
	}
}

// TestRestorePostgres_EndsPreviousSessions: a controller that lost the lock but whose sessions are
// still open does not survive the restore: the opener ends them before the restore writes.
func TestRestorePostgres_EndsPreviousSessions(t *testing.T) {
	r, archive, _ := stoppedPGController(t)
	boot, _ := pgDatabase(t)
	d, err := config.LoadDatabase(boot)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	prev, err := store.OpenPostgres(ctx, d.DSN, store.PostgresOptions{PasswordFile: d.PasswordFile, Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = prev.Close() }()
	admin := openBoot(t, boot)
	sessions := func() int {
		var n int
		if err := admin.Reader.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity
 WHERE datname = current_database() AND application_name LIKE 'rpmgr-controller:%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// The lock session goes, as a partition would end it; the pool's sessions stay.
	if _, err := admin.Writer.ExecContext(ctx, `SELECT pg_terminate_backend(pid) FROM pg_locks
 WHERE locktype = 'advisory' AND classid = 1919970663 AND objid = 2 AND granted
 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`); err != nil {
		t.Fatal(err)
	}
	if sessions() == 0 {
		t.Fatal("the previous controller has no session left to end; the test proves nothing")
	}
	if _, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: boot, Archive: archive,
		RevocationLogs: []string{filepath.Join(r.cfg.State(), "revocations.log")}}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	// The server ends a terminated session a moment after the signal.
	n := sessions()
	for deadline := time.Now().Add(5 * time.Second); n != 0 && time.Now().Before(deadline); n = sessions() {
		time.Sleep(50 * time.Millisecond)
	}
	if n != 0 {
		t.Errorf("%d sessions of a controller are open after the restore", n)
	}
}

// TestRestorePostgres_WaitsForTheLock: the restore waits out the settle time after it took the
// lock, before it writes, as a controller does; a lost lock during the wait ends it.
func TestRestorePostgres_WaitsForTheLock(t *testing.T) {
	r, archive, _ := stoppedPGController(t)
	const settle = 1200 * time.Millisecond
	controller.SetLockSettle(t, settle)
	boot, _ := pgDatabase(t)
	start := time.Now()
	if _, err := controller.Restore(context.Background(), controller.RestoreOptions{ConfigPath: boot, Archive: archive,
		RevocationLogs: []string{filepath.Join(r.cfg.State(), "revocations.log")}}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < settle {
		t.Errorf("the restore took %v, less than the settle time %v", time.Since(start), settle)
	}
	// A context that ends during the wait ends the restore, and nothing is written.
	boot2, _ := pgDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := controller.Restore(ctx, controller.RestoreOptions{ConfigPath: boot2, Archive: archive,
		RevocationLogs: []string{filepath.Join(r.cfg.State(), "revocations.log")}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("restore with an ending context: %v", err)
	}
	if n := tableCount(t, boot2); n != 0 {
		t.Errorf("an ended restore left %d tables", n)
	}
}

// TestBackupPostgres_OnlyTheControllerHost: a host whose state directory lacks the node ID or the
// revocation log is no controller host and does not back up, whichever way the archive goes; it
// creates no output and no file in the state directory.
func TestBackupPostgres_OnlyTheControllerHost(t *testing.T) {
	c := newPGController(t)
	if err := os.WriteFile(filepath.Join(c.state, "controller-node.id"), []byte("ctn_"+strings.Repeat("a", 26)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, remove := range map[string]string{"no node ID": "controller-node.id", "no revocation log": "revocations.log"} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			for _, f := range []string{"controller-node.id", "revocations.log"} {
				if f == remove {
					continue
				}
				b, err := os.ReadFile(filepath.Join(c.state, f))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(state, f), b, 0o600); err != nil { //nolint:gosec // G703: the names are fixed, the directory is the test's own
					t.Fatal(err)
				}
			}
			controller.SetStateDir(t, state)
			out := filepath.Join(t.TempDir(), "backup.tar")
			if _, err := controller.Backup(context.Background(), c.boot, out, "2.0.0", time.Now); !errors.Is(err, controller.ErrNotControllerHost) {
				t.Errorf("backup: %v, want ErrNotControllerHost", err)
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("a refused backup created its output")
			}
			var w bytes.Buffer
			if _, err := controller.BackupTo(context.Background(), c.boot, &w, "2.0.0", time.Now); !errors.Is(err, controller.ErrNotControllerHost) {
				t.Errorf("backup to a stream: %v, want ErrNotControllerHost", err)
			}
			if w.Len() != 0 {
				t.Error("a refused backup wrote to the stream")
			}
		})
	}
}
