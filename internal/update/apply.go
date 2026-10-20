// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
)

// The readiness window after a restart (docs/03-connections.md, "Timeouts, keepalive and
// backoff"): each role's /readyz is polled every readyInterval for up to readyWindow, and a role
// whose service fails, or restarts maxRestarts times, within it is rolled back at once.
const (
	readyInterval = 2 * time.Second
	readyWindow   = 5 * time.Minute
	maxRestarts   = 3
)

// StatusFile is where the updater writes its last outcome, which the agent reports
// (docs/04-security.md, "Over-the-air updates", step 7).
const StatusFile = "/run/rpmgr-update/status.json"

// Outcomes in the status file.
const (
	Updated    = "updated"
	RolledBack = "rolled_back"
	Refused    = "refused"
)

// ErrRolledBack means the new release was installed but a role did not become ready, so the
// previous binary was put back.
var ErrRolledBack = errors.New("update: rolled back")

// Status is the updater's last outcome (/run/rpmgr-update/status.json).
type Status struct {
	State    string    `json:"state"`
	Version  string    `json:"version,omitempty"`
	Previous string    `json:"previous,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	At       time.Time `json:"at"`
}

// Services restarts the role services and reports their state; Systemd is the real one.
type Services interface {
	// Restart restarts a unit, such as rpmgr-connector.service.
	Restart(ctx context.Context, unit string) error
	// State reports whether a unit has failed and how often systemd has restarted it.
	State(ctx context.Context, unit string) (failed bool, restarts int, err error)
}

// Applier installs a staged release: it stages and verifies it (Updater.Stage), swaps the binary,
// restarts the roles and rolls back when one does not become ready (docs/04-security.md,
// "Over-the-air updates", steps 5 to 7).
type Applier struct {
	Updater
	// Services restarts and watches the role services.
	Services Services
	// Ready reports whether a role's admin /readyz answers ready; nil error means ready.
	Ready func(ctx context.Context, role string) error
	// Status is the status file; empty means StatusFile.
	Status string
	// Previous is the version the installed binary reports, the running one.
	Previous string
	// Interval, Window and MaxRestarts default to the values of 03.
	Interval, Window time.Duration
	MaxRestarts      int
	// Clock is for the status file's time; nil means time.Now.
	Clock func() time.Time
}

// beforeSwap, if set, runs after the new binary is written beside the installed one and before it
// is synced and checked; tests use it to make that step fail.
var beforeSwap func(path string)

// Apply installs the staged release and reports the outcome in the status file. It returns nil
// when the release is installed and every role is ready, an error wrapping ErrRefused or
// ErrHostile when the release may not be installed (nothing changed), and one wrapping
// ErrRolledBack when a role did not become ready and the previous binary was put back.
func (a *Applier) Apply(ctx context.Context) error {
	s, in, err := a.stage()
	if err != nil {
		return a.report(Status{State: Refused, Previous: a.Previous, Reason: err.Error()}, err)
	}
	defer func() { _ = os.Remove(s.Path) }()
	version := s.Manifest.Version
	prev, err := a.swap(s, in.Path)
	if err != nil {
		return a.report(Status{State: Refused, Version: version, Previous: a.Previous, Reason: err.Error()}, err)
	}
	if err := a.restartAndWait(ctx, in.roles()); err != nil {
		rerr := a.rollback(ctx, in, prev)
		reason := err.Error()
		if rerr != nil {
			reason += "; the rollback failed too: " + rerr.Error()
		}
		st, serr := ReadState(a.State)
		if serr == nil {
			st.Failed = &Failed{Version: version, Seq: s.Manifest.Seq}
			serr = WriteState(a.State, st)
		}
		if serr != nil {
			reason += "; recording the failed version: " + serr.Error()
		}
		return a.report(Status{State: RolledBack, Version: version, Previous: a.Previous, Reason: reason},
			fmt.Errorf("%w: %s", ErrRolledBack, reason))
	}
	st, err := ReadState(a.State)
	if err == nil {
		st.Seq, st.Floor = s.Next.Seq, s.Next.Floor
		err = WriteState(a.State, st)
	}
	if err != nil {
		err = fmt.Errorf("update: %s is installed and ready, but the floor was not raised: %w", version, err)
		return a.report(Status{State: Updated, Version: version, Previous: a.Previous, Reason: err.Error()}, err)
	}
	return a.report(Status{State: Updated, Version: version, Previous: a.Previous}, nil)
}

// stage stages the release and reads the installation record once more for the swap.
func (a *Applier) stage() (*Staged, Install, error) {
	s, err := a.Stage()
	if err != nil {
		return nil, Install{}, err
	}
	in, err := a.install()
	if err != nil {
		_ = os.Remove(s.Path)
		return nil, Install{}, err
	}
	return s, in, nil
}

// swap installs the verified copy at path: it writes .rpmgr.new beside the binary (the same
// filesystem, so the rename is atomic), syncs and re-hashes it, keeps the installed binary as
// <path>.prev and renames the new one over it. It returns the path of .prev. Before the rename
// nothing the roles run has changed, so any failure leaves the installed binary as it was.
func (a *Applier) swap(s *Staged, path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: install.json names the binary %q, which is not an absolute path", ErrRefused, path)
	}
	dir := filepath.Dir(path)
	next := filepath.Join(dir, ".rpmgr.new")
	prev := path + ".prev"
	_ = os.Remove(next) // one an interrupted run left; O_EXCL below refuses anything else
	if err := writeNew(s.Path, next, s.Artifact); err != nil {
		_ = os.Remove(next)
		return "", err
	}
	if err := keep(path, prev); err != nil {
		_ = os.Remove(next)
		return "", err
	}
	if err := os.Rename(next, path); err != nil {
		_ = os.Remove(next)
		return "", fmt.Errorf("update: installing %s: %w", path, err)
	}
	if err := syncDir(dir); err != nil {
		return prev, fmt.Errorf("update: %w", err)
	}
	return prev, nil
}

// writeNew copies the verified copy to next, a new executable file, syncs it and checks it once
// more against the manifest, so that what is renamed over the binary is what was verified.
func writeNew(src, next string, art release.Artifact) error {
	in, err := os.Open(src) //nolint:gosec // G304: the updater's own staging directory
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(next, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755) //nolint:gosec // G302,G304: a binary beside the installed one
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	_, err = io.Copy(out, io.LimitReader(in, art.Size+1))
	if err == nil {
		err = out.Chmod(0o755) // whatever the umask
	}
	if err == nil {
		if beforeSwap != nil {
			beforeSwap(next)
		}
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("update: writing %s: %w", next, err)
	}
	return checkCopy(next, art)
}

// keep makes prev a copy of the installed binary: a hard link, renamed into place, so the binary
// is never without a copy and prev is replaced atomically.
func keep(path, prev string) error {
	tmp := prev + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Link(path, tmp); err != nil {
		return fmt.Errorf("update: keeping %s as %s: %w", path, prev, err)
	}
	if err := os.Rename(tmp, prev); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("update: keeping %s as %s: %w", path, prev, err)
	}
	return nil
}

// rollback puts .prev back over the binary and restarts the roles. The previous binary is
// exempt from the floor: floor and seq were not raised.
func (a *Applier) rollback(ctx context.Context, in Install, prev string) error {
	dir := filepath.Dir(in.Path)
	tmp := filepath.Join(dir, ".rpmgr.rollback")
	_ = os.Remove(tmp)
	if err := os.Link(prev, tmp); err != nil {
		return fmt.Errorf("update: rolling back: %w", err)
	}
	if err := os.Rename(tmp, in.Path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("update: rolling back: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("update: rolling back: %w", err)
	}
	var errs []error
	for _, role := range in.roles() {
		if err := a.Services.Restart(ctx, unitOf(role)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// restartAndWait restarts each role and waits until all are ready, within the readiness window.
// A role whose service fails, or restarts too often, ends the wait at once.
func (a *Applier) restartAndWait(ctx context.Context, roles []string) error {
	base := make(map[string]int, len(roles))
	for _, role := range roles {
		if err := a.Services.Restart(ctx, unitOf(role)); err != nil {
			return fmt.Errorf("restarting %s: %w", unitOf(role), err)
		}
		_, n, err := a.Services.State(ctx, unitOf(role))
		if err != nil {
			return fmt.Errorf("%s: %w", unitOf(role), err)
		}
		base[role] = n
	}
	interval, window, limit := a.Interval, a.Window, a.MaxRestarts
	if interval <= 0 {
		interval = readyInterval
	}
	if window <= 0 {
		window = readyWindow
	}
	if limit <= 0 {
		limit = maxRestarts
	}
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	t := time.NewTicker(interval)
	defer t.Stop()
	pending := append([]string(nil), roles...)
	var last error
	for {
		var still []string
		for _, role := range pending {
			failed, n, err := a.Services.State(ctx, unitOf(role))
			switch {
			case err != nil && ctx.Err() == nil:
				return fmt.Errorf("%s: %w", unitOf(role), err)
			case failed:
				return fmt.Errorf("%s failed after the restart", unitOf(role))
			case n-base[role] >= limit:
				return fmt.Errorf("%s restarted %d times after the update", unitOf(role), n-base[role])
			}
			if err := a.Ready(ctx, role); err != nil {
				last = fmt.Errorf("%s: %w", role, err)
				still = append(still, role)
			}
		}
		if pending = still; len(pending) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("not ready within %s: %w", window, last)
		case <-t.C:
		}
	}
}

// report writes the status file and returns err; a status file that cannot be written is added
// to err.
func (a *Applier) report(st Status, err error) error {
	now := time.Now
	if a.Clock != nil {
		now = a.Clock
	}
	st.At = now().UTC()
	path := a.Status
	if path == "" {
		path = StatusFile
	}
	if werr := writeStatus(path, st); werr != nil {
		return errors.Join(err, werr)
	}
	return err
}

// writeStatus replaces the status file atomically, readable by the service user (0644).
func writeStatus(path string, st Status) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: the agent reads the status
		return fmt.Errorf("update: status: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".status-*.json")
	if err != nil {
		return fmt.Errorf("update: status: %w", err)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename
	_, err = tmp.Write(append(b, '\n'))
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		return fmt.Errorf("update: status: %w", err)
	}
	return nil
}

// ReadStatus reads the status file; the agent reports it at start.
func ReadStatus(path string) (Status, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the updater's status file
	if err != nil {
		return Status{}, err
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil {
		return Status{}, fmt.Errorf("update: status: %w", err)
	}
	return st, nil
}

// syncDir syncs a directory, so a rename in it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the binary's directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// unitOf is the systemd unit of a role.
func unitOf(role string) string { return "rpmgr-" + role + ".service" }
