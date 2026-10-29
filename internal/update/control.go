// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ControlPlane is what the updater needs to know of the controller or all-in-one of its host.
type ControlPlane struct {
	// Config is the role's boot file, which `rpmgr backup`, `migrate` and `restore` read.
	Config string
	// Driver is the database driver of the boot file, "sqlite" or "postgres".
	Driver string
}

// BackupSuffix is added to the binary's path for the backup taken before an update of a
// controller or all-in-one, which stays next to the binary and its .prev (D158).
const BackupSuffix = ".backup"

// isControl reports whether a role is the controller or an all-in-one, which own the database.
func isControl(role string) bool { return role == "controller" || role == "all-in-one" }

// controlRole returns the controller or all-in-one among roles, or "".
func controlRole(roles []string) string {
	for _, r := range roles {
		if isControl(r) {
			return r
		}
	}
	return ""
}

// step reports the step of an update of a controller or all-in-one in the status file; the
// outcome replaces it, and a status file that cannot be written fails the outcome's write too.
func (a *Applier) step(p *pending, step string) {
	_ = a.report(Status{State: Updating, Step: step, Version: p.Version, Previous: a.Previous}, nil)
}

func (a *Applier) exec(ctx context.Context, bin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, backupWindow)
	defer cancel()
	if a.Exec != nil {
		return a.Exec(ctx, bin, args...)
	}
	return exec.CommandContext(ctx, bin, args...).CombinedOutput() //nolint:gosec // G204: the installed binary, fixed subcommands
}

// backUp takes the backup of the controller's database with the installed binary, `rpmgr backup`,
// before anything is replaced, and keeps it next to the binary as <bin>.backup, replacing the one
// of an earlier update only once the new one is complete. Any failure is a refusal: nothing was
// changed. A PostgreSQL controller is refused until a backup method exists (D158).
func (a *Applier) backUp(ctx context.Context, role, bin string) (string, error) {
	if a.Control == nil {
		return "", fmt.Errorf("%w: this updater cannot back up a %s, so it does not update one", ErrRefused, role)
	}
	cp, err := a.Control(role)
	switch {
	case err != nil:
		return "", fmt.Errorf("%w: reading the boot file of the %s: %w", ErrRefused, role, err)
	case cp.Driver != "sqlite":
		return "", fmt.Errorf("%w: the %s runs on %s, and a self-update needs a backup it can restore; "+
			"only SQLite has one until the PostgreSQL backup method (P2-M08) exists (D158); update it by hand", ErrRefused, role, cp.Driver)
	}
	out := bin + BackupSuffix
	tmp := out + ".new"
	_ = os.Remove(tmp)
	if b, err := a.exec(ctx, bin, "backup", "--config", cp.Config, "--out", tmp); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("%w: the backup of the %s failed, so nothing was updated: %w: %s", ErrRefused, role, err, strings.TrimSpace(string(b)))
	}
	if fi, err := os.Lstat(tmp); err != nil || !fi.Mode().IsRegular() {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("%w: the backup of the %s left no file, so nothing was updated", ErrRefused, role)
	}
	if err := os.Rename(tmp, out); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("%w: keeping the backup as %s: %w", ErrRefused, out, err)
	}
	_ = syncDir(filepath.Dir(out))
	return out, nil
}

// restoreDatabase runs in a rollback, after the previous binary is back and before the role is
// started again. It stops the role, asks the previous binary whether the database is still at its
// schema (`migrate` applies nothing then and refuses a newer one, store.ErrUnknownMigration), and
// when it is not restores the backup with `rpmgr restore`. An error means the database is left as
// it is and the role must not start: the previous binary would refuse that schema.
func (a *Applier) restoreDatabase(ctx context.Context, p *pending, role string) error {
	cp, err := a.Control(role)
	if err != nil {
		return fmt.Errorf("update: rolling back: reading the boot file of the %s: %w; restore %s by hand", role, err, p.Backup)
	}
	if err := a.Services.Stop(ctx, unitOf(role)); err != nil {
		return fmt.Errorf("update: rolling back: %w; restore %s by hand", err, p.Backup)
	}
	probe, err := a.exec(ctx, p.Path, "migrate", "--config", cp.Config)
	if err == nil {
		a.restored = "the database is as the previous release left it; the backup was not needed"
		return nil
	}
	if b, rerr := a.exec(ctx, p.Path, "restore", "--in", p.Backup, "--config", cp.Config); rerr != nil {
		return fmt.Errorf("update: rolling back: the database was migrated (%s) and restoring %s failed: %w: %s; "+
			"the %s is stopped: run `rpmgr restore --in %s` and start it", strings.TrimSpace(string(probe)), p.Backup, rerr, strings.TrimSpace(string(b)), role, p.Backup)
	}
	a.restored = "the database was migrated by " + p.Version + " and restored from " + p.Backup
	return nil
}

// serves reports whether a role's process answers again after a failed hand-off, waiting for it
// for servesAgain at most (the Window if shorter): the old process opens the database and starts
// again within seconds, or refuses a schema the new one migrated and stays down.
func (a *Applier) serves(ctx context.Context, role string) bool {
	window, interval := a.Window, a.Interval
	if window <= 0 || window > servesAgain {
		window = servesAgain
	}
	if interval <= 0 {
		interval = readyInterval
	}
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if a.Ready(ctx, role) == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
	}
}
