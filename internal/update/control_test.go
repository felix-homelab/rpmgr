// SPDX-License-Identifier: Apache-2.0

//go:build linux

package update_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/update"
)

// cmds is a fake `rpmgr` for the backup, the schema probe and the restore of a controller or
// all-in-one: it records each call as "<subcommand>" and fails those it is told to.
type cmds struct {
	mu    sync.Mutex
	calls []string
	bins  []string         // the binary of each call
	fail  map[string]bool  // subcommands that fail
	args  [][]string       // the arguments of each call
	newer bool             // migrate finds a schema a newer release migrated
	inUse func(sub string) // runs at each call, to look at the host
}

func (c *cmds) run(_ context.Context, bin string, args ...string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sub := args[0]
	c.calls, c.bins, c.args = append(c.calls, sub), append(c.bins, bin), append(c.args, args)
	if c.inUse != nil {
		c.inUse(sub)
	}
	if sub == "migrate" && c.newer {
		return []byte("the database has a migration this version does not know"), exitErr(update.ExitUnknownMigration)
	}
	if c.fail[sub] {
		return []byte(sub + " failed (test)"), errors.New("exit status 1")
	}
	if sub == "backup" {
		for i, a := range args {
			if a == "--out" {
				return nil, os.WriteFile(args[i+1], []byte("archive"), 0o600)
			}
		}
	}
	return nil, nil
}

// exitErr is the error of a command that ended with a code.
type exitErr int

func (e exitErr) Error() string { return "exit status " + strconv.Itoa(int(e)) }
func (e exitErr) ExitCode() int { return int(e) }

// controlHost is an installed all-in-one or controller with a fake backup.
func controlHost(t *testing.T, role, running string, ready func([]byte) error) (*installed, *cmds) {
	t.Helper()
	i := newInstalled(t, hostOpts{}, running, []string{role}, ready)
	c := &cmds{fail: map[string]bool{}}
	i.a.Exec = c.run
	i.a.Control = func(string) (update.ControlPlane, error) {
		return update.ControlPlane{Config: "/etc/rpmgr/" + role + ".yaml", Driver: "sqlite"}, nil
	}
	i.svc.notify = map[string]bool{"rpmgr-" + role + ".service": true}
	return i, c
}

func (i *installed) backupKept() bool {
	_, err := os.Stat(i.bin + update.BackupSuffix)
	return err == nil
}

// TestOTA_ControlPlaneBackupAndRestore: a controller or all-in-one is updated after a backup, and a failure
// restores the backup when the migration ran (D158).
func TestOTA_ControlPlaneBackupAndRestore(t *testing.T) {
	t.Run("an all-in-one is backed up, handed over, and the backup is kept", func(t *testing.T) {
		i, c := controlHost(t, "all-in-one", "1.1.0", nil)
		c.inUse = func(sub string) {
			if st, err := update.ReadStatus(i.a.Status); err != nil || st.State != update.Updating || st.Step != update.StepBackingUp {
				t.Errorf("status during the %s: %+v, %v; want updating, backing_up", sub, st, err)
			}
		}
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); err != nil {
			t.Fatalf("Apply = %v", err)
		}
		if !slices.Equal(c.calls, []string{"backup"}) || c.bins[0] != i.bin {
			t.Errorf("calls %v with %v; want the installed binary's backup alone", c.calls, c.bins)
		}
		if !i.backupKept() {
			t.Error("the backup was not kept next to the binary")
		}
		if want := []string{i.bin + " all-in-one"}; !slices.Equal(i.svc.handoffs, want) {
			t.Errorf("hand-offs %v; want %v", i.svc.handoffs, want)
		}
		i.runs("1.2.0")
		i.status(update.Updated)
		if _, err := os.Stat(i.bin + update.BackupSuffix + ".new"); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the backup's temporary file was left: %v", err)
		}
	})

	t.Run("a controller restarts, as it has no hand-off", func(t *testing.T) {
		i, c := controlHost(t, "controller", "1.1.0", nil)
		i.svc.notify = nil
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); err != nil {
			t.Fatalf("Apply = %v", err)
		}
		if len(i.svc.handoffs) != 0 || !slices.Equal(i.svc.restarted(), []string{"rpmgr-controller.service"}) || !slices.Equal(c.calls, []string{"backup"}) {
			t.Errorf("hand-offs %v, restarts %v, calls %v", i.svc.handoffs, i.svc.restarted(), c.calls)
		}
		i.status(update.Updated)
	})

	t.Run("a backup that fails: no update, nothing changed", func(t *testing.T) {
		i, c := controlHost(t, "all-in-one", "1.1.0", nil)
		c.fail["backup"] = true
		i.stage(rel{version: "1.2.0", seq: 6})
		err := i.a.Apply(context.Background())
		if !errors.Is(err, update.ErrRefused) || !strings.Contains(err.Error(), "backup failed (test)") {
			t.Fatalf("Apply = %v; want refused with the backup's message", err)
		}
		i.runs("1.1.0")
		if len(i.svc.handoffs)+len(i.svc.restarted()) != 0 || i.backupKept() || i.pendingLeft() {
			t.Errorf("hand-offs %v, restarts %v, backup %v, pending %v; want none", i.svc.handoffs, i.svc.restarted(), i.backupKept(), i.pendingLeft())
		}
		if st := i.status(update.Refused); !strings.Contains(st.Reason, "nothing was updated") {
			t.Errorf("status %+v", st)
		}
		i.leftovers()
	})

	t.Run("a backup that leaves no file: refused", func(t *testing.T) {
		i, _ := controlHost(t, "all-in-one", "1.1.0", nil)
		i.a.Exec = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
			t.Fatalf("Apply = %v; want refused", err)
		}
		i.runs("1.1.0")
	})

	t.Run("PostgreSQL: refused with the reason, no backup attempted", func(t *testing.T) {
		i, c := controlHost(t, "controller", "1.1.0", nil)
		i.a.Control = func(string) (update.ControlPlane, error) {
			return update.ControlPlane{Config: "/etc/rpmgr/controller.yaml", Driver: "postgres"}, nil
		}
		i.stage(rel{version: "1.2.0", seq: 6})
		err := i.a.Apply(context.Background())
		if !errors.Is(err, update.ErrRefused) || !strings.Contains(err.Error(), "P2-M08") {
			t.Fatalf("Apply = %v; want refused naming P2-M08", err)
		}
		if len(c.calls) != 0 || len(i.svc.restarted()) != 0 {
			t.Errorf("calls %v, restarts %v; want none", c.calls, i.svc.restarted())
		}
		i.runs("1.1.0")
		i.status(update.Refused)
	})

	t.Run("a boot file that cannot be read: refused", func(t *testing.T) {
		i, c := controlHost(t, "controller", "1.1.0", nil)
		i.a.Control = func(string) (update.ControlPlane, error) { return update.ControlPlane{}, errors.New("no such file") }
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) || len(c.calls) != 0 {
			t.Fatalf("Apply = %v, calls %v; want refused before any backup", err, c.calls)
		}
	})

	t.Run("the connector build has no controller; a controller and an all-in-one are one too many", func(t *testing.T) {
		for _, install := range []string{
			`{"method":"script","path":"%s","variant":"connector","roles":["all-in-one"]}`,
			`{"method":"script","path":"%s","variant":"full","roles":["controller","all-in-one"]}`,
		} {
			i, _ := controlHost(t, "all-in-one", "1.1.0", nil)
			writeAll(t, i.u.State+"/install.json", strings.ReplaceAll(install, "%s", i.bin))
			if err := os.Chmod(i.u.State+"/install.json", 0o600); err != nil {
				t.Fatal(err)
			}
			i.stage(rel{version: "1.2.0", seq: 6})
			if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
				t.Errorf("Apply = %v; want refused", err)
			}
		}
	})

	t.Run("a hand-off that fails before the migration: the old process serves on, nothing restored", func(t *testing.T) {
		i, c := controlHost(t, "all-in-one", "1.1.0", nil) // ready at once: the old process answers
		i.svc.handoffErr = map[string]error{"all-in-one": errors.New("the new process did not become ready")}
		i.stage(rel{version: "1.2.0", seq: 6})
		err := i.a.Apply(context.Background())
		if !errors.Is(err, update.ErrRolledBack) || !strings.Contains(err.Error(), "the old process serves on") {
			t.Fatalf("Apply = %v; want rolled back, the old process serving", err)
		}
		i.runs("1.1.0")
		if len(i.svc.stops) != 0 || len(i.svc.restarted()) != 0 || !slices.Equal(c.calls, []string{"backup"}) {
			t.Errorf("stops %v, restarts %v, calls %v; want only the backup", i.svc.stops, i.svc.restarted(), c.calls)
		}
		i.status(update.RolledBack)
	})

	t.Run("a hand-off that fails after the migration: the backup is restored, the previous binary started", func(t *testing.T) {
		i, c := controlHost(t, "all-in-one", "1.1.0", notReady("1.2.0")) // the old process does not come back
		i.svc.handoffErr = map[string]error{"all-in-one": errors.New("the new process ended after the migration")}
		c.newer = true // the previous binary finds a newer schema
		i.stage(rel{version: "1.2.0", seq: 6})
		err := i.a.Apply(context.Background())
		if !errors.Is(err, update.ErrRolledBack) || !strings.Contains(err.Error(), "restored from "+i.bin+update.BackupSuffix) {
			t.Fatalf("Apply = %v; want rolled back with the restore", err)
		}
		i.runs("1.1.0")
		if want := []string{"backup", "migrate", "restore"}; !slices.Equal(c.calls, want) {
			t.Errorf("calls %v; want %v", c.calls, want)
		}
		if c.bins[1] != i.bin || c.bins[2] != i.bin {
			t.Errorf("probe and restore ran %v; want the previous binary, put back at %s", c.bins, i.bin)
		}
		if !slices.Equal(i.svc.stops, []string{"rpmgr-all-in-one.service"}) || !slices.Equal(i.svc.restarted(), []string{"rpmgr-all-in-one.service"}) {
			t.Errorf("stops %v, restarts %v; want stop, restore, start", i.svc.stops, i.svc.restarted())
		}
		if st := i.status(update.RolledBack); !strings.Contains(st.Reason, "restored from") {
			t.Errorf("status %+v; want the restore in the reason", st)
		}
	})

	t.Run("a controller not ready after its migration: the backup is restored", func(t *testing.T) {
		i, c := controlHost(t, "controller", "1.1.0", notReady("1.2.0"))
		i.svc.notify = nil
		c.newer = true
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRolledBack) {
			t.Fatalf("Apply = %v; want rolled back", err)
		}
		if want := []string{"backup", "migrate", "restore"}; !slices.Equal(c.calls, want) {
			t.Errorf("calls %v; want %v", c.calls, want)
		}
		i.runs("1.1.0")
	})

	t.Run("the restore stages in the updater's own directory, when the previous release has the flag", func(t *testing.T) {
		for running, want := range map[string]bool{"1.1.0": true, "0.2.0": false} {
			i, c := controlHost(t, "controller", running, notReady("1.2.0"))
			i.svc.notify = nil
			c.newer = true
			i.stage(rel{version: "1.2.0", seq: 6, floor: "0.1.0"})
			if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRolledBack) {
				t.Fatalf("%s: Apply = %v; want rolled back", running, err)
			}
			got := c.args[len(c.args)-1]
			has := slices.Contains(got, "--stage-dir")
			if has != want || (want && got[len(got)-1] != filepath.Join(i.u.State, "restore")) {
				t.Errorf("previous %s: restore ran with %v; stage-dir %v, want %v", running, got, has, want)
			}
		}
	})

	t.Run("a controller that fails before any migration: the previous binary runs on the database as it is", func(t *testing.T) {
		i, c := controlHost(t, "controller", "1.1.0", notReady("1.2.0"))
		i.svc.notify = nil // the probe succeeds: the schema is the previous release's
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRolledBack) {
			t.Fatalf("Apply = %v; want rolled back", err)
		}
		if want := []string{"backup", "migrate"}; !slices.Equal(c.calls, want) {
			t.Errorf("calls %v; want %v: no restore of a database nothing migrated", c.calls, want)
		}
		if st := i.status(update.RolledBack); !strings.Contains(st.Reason, "backup was not needed") {
			t.Errorf("status %+v", st)
		}
	})

	t.Run("a restore that fails: rollback failed, the role stays stopped", func(t *testing.T) {
		i, c := controlHost(t, "controller", "1.1.0", notReady("1.2.0"))
		i.svc.notify = nil
		c.newer, c.fail["restore"] = true, true
		i.stage(rel{version: "1.2.0", seq: 6})
		err := i.a.Apply(context.Background())
		if !errors.Is(err, update.ErrRollbackFailed) || !strings.Contains(err.Error(), "rpmgr restore --in "+i.bin+update.BackupSuffix) {
			t.Fatalf("Apply = %v; want rollback failed naming the restore command", err)
		}
		if len(i.svc.restarted()) != 1 { // only the update's own restart: never the old binary on a newer schema
			t.Errorf("restarts %v; want the update's restart only", i.svc.restarted())
		}
		i.status(update.RollbackFailed)
	})

	t.Run("a probe that fails for another reason: no restore, the role stays stopped, rollback failed", func(t *testing.T) {
		i, c := controlHost(t, "controller", "1.1.0", notReady("1.2.0"))
		i.svc.notify = nil
		c.fail["migrate"] = true // exit 1: nothing says the schema is newer
		i.stage(rel{version: "1.2.0", seq: 6})
		err := i.a.Apply(context.Background())
		if !errors.Is(err, update.ErrRollbackFailed) || !strings.Contains(err.Error(), "could not check the database") {
			t.Fatalf("Apply = %v; want rollback failed", err)
		}
		if slices.Contains(c.calls, "restore") || len(i.svc.restarted()) != 1 {
			t.Errorf("calls %v, restarts %v; want no restore and no start of the previous binary", c.calls, i.svc.restarted())
		}
		i.status(update.RollbackFailed)
	})

	t.Run("a role that cannot be stopped: rollback failed, no restore", func(t *testing.T) {
		i, c := controlHost(t, "controller", "1.1.0", notReady("1.2.0"))
		i.svc.notify = nil
		i.svc.stopErr = errors.New("unit is masked")
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRollbackFailed) {
			t.Fatalf("Apply = %v; want rollback failed", err)
		}
		if slices.Contains(c.calls, "restore") {
			t.Errorf("calls %v; a restore under a running controller", c.calls)
		}
	})
}
