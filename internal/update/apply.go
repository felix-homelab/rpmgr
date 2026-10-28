// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/units"
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

// pendingFile, in the updater's state directory, records an install from just before the binary
// is replaced until the outcome is known, so that a run that was interrupted is finished by the
// next one, also after a reboot.
const pendingFile = "pending.json"

// Outcomes in the status file.
const (
	Updated        = "updated"
	RolledBack     = "rolled_back"
	RollbackFailed = "rollback_failed"
	Refused        = "refused"
)

// ErrRolledBack means the new release was installed but a role did not become ready, so the
// previous binary was put back. ErrRollbackFailed means putting it back failed too.
var (
	ErrRolledBack     = errors.New("update: rolled back")
	ErrRollbackFailed = errors.New("update: the rollback failed")
)

// Status is the updater's last outcome (/run/rpmgr-update/status.json).
type Status struct {
	State    string    `json:"state"`
	Version  string    `json:"version,omitempty"`
	Previous string    `json:"previous,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	At       time.Time `json:"at"`
}

// Unit is what systemd says about a role's unit.
type Unit struct {
	// Active is its ActiveState: active, activating, deactivating, inactive or failed.
	Active string
	// Restarts is its NRestarts, how often systemd restarted it by Restart=.
	Restarts int
	// MainPID is its main process, 0 when none runs.
	MainPID int
}

// Services restarts the role services and reports their state; Systemd is the real one.
type Services interface {
	// Restart restarts a unit, such as rpmgr-connector.service.
	Restart(ctx context.Context, unit string) error
	// State reports a unit's state.
	State(ctx context.Context, unit string) (Unit, error)
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
	// Units is the directory of the role units; empty means /etc/systemd/system.
	Units string
	// Clock is for the status file's time; nil means time.Now.
	Clock func() time.Time

	reported bool // the last Apply wrote the status file
}

// Reported reports whether the last Apply wrote an outcome to the status file. It did not when
// nothing was staged, or when the staged release was installed already.
func (a *Applier) Reported() bool { return a.reported }

// pending is an install in progress (pendingFile).
type pending struct {
	Version  string   `json:"version"`
	Seq      uint64   `json:"seq"`
	SHA256   string   `json:"sha256"` // of the new binary, to tell whether it was put in place
	Previous string   `json:"previous,omitempty"`
	Path     string   `json:"path"`
	Prev     string   `json:"prev"`
	Roles    []string `json:"roles"`
	Next     State    `json:"next"` // the state to persist after success
}

// Test hooks: beforeSwap runs after the new binary is written beside the installed one and before
// it is synced and checked; afterRename runs right after it was renamed over the installed one,
// before the roles restart, and ends the run when it returns false, as a crash would; syncDirHook
// can make syncing a directory fail.
var (
	beforeSwap  func(path string)
	afterRename func() bool
	syncDirHook func(dir string) error
)

// errInterrupted ends a run in tests, as a crash after the rename would.
var errInterrupted = errors.New("update: interrupted (test)")

// Apply first finishes an install that an earlier run left unfinished. Otherwise it installs the
// staged release and reports the outcome in the status file. With nothing staged (no manifest, as
// at the run at every boot, or while the agent is still staging) it does nothing and reports
// nothing, so an earlier outcome stays. It returns nil when the release is installed and every
// role is ready, when nothing is staged, or when the staged release is the installed binary already;
// an error wrapping ErrRefused or ErrHostile when the release may not be installed (nothing
// changed); one wrapping ErrRolledBack when a role did not become ready and the previous binary was
// put back; and one wrapping ErrRollbackFailed when that failed too.
func (a *Applier) Apply(ctx context.Context) error {
	a.reported = false
	p, err := a.readPending()
	switch {
	case err == nil:
		return a.resume(ctx, p)
	case !errors.Is(err, fs.ErrNotExist):
		return a.report(Status{State: Refused, Previous: a.Previous, Reason: err.Error()}, err)
	}
	// The agent writes the manifest last. Without it nothing is staged; a manifest that is a link
	// or no regular file is staged and refused below.
	if _, err := os.Lstat(filepath.Join(a.Staged, manifestFile)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	s, in, err := a.stage()
	if err != nil {
		return a.report(Status{State: Refused, Previous: a.Previous, Reason: err.Error()}, err)
	}
	defer func() { _ = os.Remove(s.Path) }()
	if same, err := sameFile(in.Path, s.Artifact.SHA256); err == nil && same {
		return nil // installed already, as at a boot after a successful update: nothing to report
	}
	p = &pending{Version: s.Manifest.Version, Seq: s.Manifest.Seq, SHA256: s.Artifact.SHA256, Previous: a.Previous,
		Path: in.Path, Prev: in.Path + ".prev", Roles: in.roles(), Next: s.Next}
	warning, err := a.swap(s, p)
	if err != nil {
		return a.report(Status{State: Refused, Version: p.Version, Previous: a.Previous, Reason: err.Error()}, err)
	}
	if afterRename != nil && !afterRename() {
		return errInterrupted
	}
	return a.finish(ctx, p, warning)
}

// resume finishes an install that an earlier run left: if the new binary is in place, it restarts
// the roles and waits for them as finish does; if the run ended before the rename, nothing
// changed.
func (a *Applier) resume(ctx context.Context, p *pending) error {
	same, err := sameFile(p.Path, p.SHA256)
	if err != nil || !same {
		reason := "an earlier run ended before the binary was replaced; nothing changed"
		if cerr := a.clearPending(); cerr != nil {
			reason += "; " + cerr.Error()
		}
		return a.report(Status{State: Refused, Version: p.Version, Previous: p.Previous, Reason: reason},
			fmt.Errorf("%w: %s", ErrRefused, reason))
	}
	return a.finish(ctx, p, "resumed an install that an earlier run did not finish")
}

// finish restarts the roles and waits until they are ready. Then it raises the floor and seq; if
// a role is not ready, it puts the previous binary back and records the version as failed. Either
// way the pending install is cleared and the outcome reported.
func (a *Applier) finish(ctx context.Context, p *pending, note string) error {
	status := func(state, reason string) Status {
		parts := slices.DeleteFunc([]string{note, reason}, func(s string) bool { return s == "" })
		return Status{State: state, Version: p.Version, Previous: p.Previous, Reason: strings.Join(parts, "; ")}
	}
	if err := a.restartAndWait(ctx, p.Roles); err != nil {
		reason := err.Error()
		state, werr := RolledBack, ErrRolledBack
		if rerr := a.rollback(ctx, p); rerr != nil {
			state, werr = RollbackFailed, ErrRollbackFailed
			reason += "; " + rerr.Error()
		}
		if serr := a.recordFailed(p); serr != nil {
			reason += "; recording the failed version: " + serr.Error()
		}
		if cerr := a.clearPending(); cerr != nil {
			reason += "; " + cerr.Error()
		}
		return a.report(status(state, reason), fmt.Errorf("%w: %s", werr, reason))
	}
	st, err := ReadState(a.State)
	if err == nil {
		st.Seq, st.Floor = p.Next.Seq, p.Next.Floor
		err = WriteState(a.State, st)
	}
	if err == nil {
		err = a.clearPending()
	}
	if err != nil {
		err = fmt.Errorf("update: %s is installed and ready, but the state was not updated: %w", p.Version, err)
		return a.report(status(Updated, err.Error()), err)
	}
	return a.report(status(Updated, ""), nil)
}

// recordFailed records the version as rolled back, so that only a manifest with a higher seq
// offers it again (D120).
func (a *Applier) recordFailed(p *pending) error {
	st, err := ReadState(a.State)
	if err != nil {
		return err
	}
	st.Failed = &Failed{Version: p.Version, Seq: p.Seq}
	return WriteState(a.State, st)
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

// swap installs the verified copy at p.Path: it writes .rpmgr.new beside the binary (the same
// filesystem, so the rename is atomic), syncs and re-hashes it, keeps the installed binary as
// p.Prev, records the install as pending and renames the new binary over the installed one.
// Before the rename nothing the roles run has changed, so a failure there is a refusal and leaves
// the installed binary as it was. After the rename the install goes on: a directory that cannot be
// synced is only a warning.
func (a *Applier) swap(s *Staged, p *pending) (warning string, err error) {
	if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path {
		return "", fmt.Errorf("%w: install.json names the binary %q, which is no clean absolute path", ErrRefused, p.Path)
	}
	if fi, err := os.Lstat(p.Path); err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%w: the installed binary %s is no regular file (a symbolic link is refused)", ErrRefused, p.Path)
	}
	dir := filepath.Dir(p.Path)
	next := filepath.Join(dir, ".rpmgr.new")
	_ = os.Remove(next) // one an interrupted run left, or a link; O_EXCL below refuses anything else
	if err := writeNew(s.Path, next, s.Artifact); err != nil {
		_ = os.Remove(next)
		return "", err
	}
	if err := keep(p.Path, p.Prev); err != nil {
		_ = os.Remove(next)
		return "", err
	}
	if err := a.writePending(p); err != nil {
		_ = os.Remove(next)
		return "", err
	}
	if err := os.Rename(next, p.Path); err != nil {
		_ = os.Remove(next)
		_ = a.clearPending()
		return "", fmt.Errorf("update: installing %s: %w", p.Path, err)
	}
	if err := syncDir(dir); err != nil {
		return "the new binary is in place, but its directory could not be synced: " + err.Error(), nil
	}
	return "", nil
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
// is never without a copy and prev is replaced atomically. When prev is the installed binary
// already, as after a rollback, the rename does nothing and the link is removed.
func keep(path, prev string) error {
	tmp := prev + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Link(path, tmp); err != nil {
		return fmt.Errorf("update: keeping %s as %s: %w", path, prev, err)
	}
	err := os.Rename(tmp, prev)
	_ = os.Remove(tmp) // left when tmp and prev were the same file
	if err != nil {
		return fmt.Errorf("update: keeping %s as %s: %w", path, prev, err)
	}
	return nil
}

// rollback puts p.Prev back over the binary and restarts the roles. The previous binary is exempt
// from the floor: floor and seq were not raised.
func (a *Applier) rollback(ctx context.Context, p *pending) error {
	if fi, err := os.Lstat(p.Prev); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("update: rolling back: %s is no regular file", p.Prev)
	}
	dir := filepath.Dir(p.Path)
	tmp := filepath.Join(dir, ".rpmgr.rollback")
	_ = os.Remove(tmp)
	if err := os.Link(p.Prev, tmp); err != nil {
		return fmt.Errorf("update: rolling back: %w", err)
	}
	err := os.Rename(tmp, p.Path)
	_ = os.Remove(tmp)
	if err != nil {
		return fmt.Errorf("update: rolling back: %w", err)
	}
	_ = syncDir(dir) // the binary is back; a sync error changes nothing about it
	var errs []error
	if !units.HasHandoff(p.Previous) {
		// The release put back never sends READY=1: its units must not be Type=notify (D155).
		errs = append(errs, a.removeDropIns(p.Roles)...)
	}
	for _, role := range p.Roles {
		if err := a.Services.Restart(ctx, unitOf(role)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// removeDropIns removes the hand-off drop-in of each role, which the restart that follows reads
// (Systemd.Restart reloads systemd first). One that is not there is no error.
func (a *Applier) removeDropIns(roles []string) []error {
	dir := a.Units
	if dir == "" {
		dir = "/etc/systemd/system"
	}
	var errs []error
	for _, role := range roles {
		f := filepath.Join(dir, unitOf(role)+".d", units.DropIn)
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("update: rolling back: %w", err))
		}
	}
	return errs
}

// restartAndWait restarts each role and waits until all are active and ready, within the
// readiness window. A role whose service fails, or restarts too often, ends the wait at once.
func (a *Applier) restartAndWait(ctx context.Context, roles []string) error {
	base := make(map[string]int, len(roles))
	for _, role := range roles {
		if err := a.Services.Restart(ctx, unitOf(role)); err != nil {
			return fmt.Errorf("restarting %s: %w", unitOf(role), err)
		}
		u, err := a.Services.State(ctx, unitOf(role))
		if err != nil {
			return fmt.Errorf("%s: %w", unitOf(role), err)
		}
		base[role] = u.Restarts
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
	// check judges a role: fatal ends the wait, otherwise ready says whether it is ready and why
	// not.
	check := func(role string) (ready bool, why, fatal error) {
		u, err := a.Services.State(ctx, unitOf(role))
		switch {
		case err != nil && ctx.Err() == nil:
			return false, nil, fmt.Errorf("%s: %w", unitOf(role), err)
		case err != nil:
			return false, err, nil
		case u.Active == "failed":
			return false, nil, fmt.Errorf("%s failed after the restart", unitOf(role))
		case u.Restarts-base[role] >= limit:
			return false, nil, fmt.Errorf("%s restarted %d times after the update", unitOf(role), u.Restarts-base[role])
		case u.Active != "active":
			return false, fmt.Errorf("%s is %s", unitOf(role), u.Active), nil
		}
		if err := a.Ready(ctx, role); err != nil {
			return false, fmt.Errorf("%s: %w", role, err), nil
		}
		return true, nil, nil
	}
	waiting := slices.Clone(roles)
	var last error
	for {
		var still []string
		for _, role := range waiting {
			ok, why, fatal := check(role)
			if fatal != nil {
				return fatal
			}
			if !ok {
				last = why
				still = append(still, role)
			}
		}
		if waiting = still; len(waiting) == 0 {
			// Every role was ready once: one that has failed, restarted or stopped since still
			// counts against the release.
			for _, role := range roles {
				if ok, why, fatal := check(role); fatal != nil || !ok {
					return errors.Join(fatal, why)
				}
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("not ready within %s: %w", window, last)
		case <-t.C:
		}
	}
}

// readPending reads the pending install; fs.ErrNotExist means none.
func (a *Applier) readPending() (*pending, error) {
	b, err := readOwn(filepath.Join(a.State, pendingFile))
	if err != nil {
		return nil, err
	}
	var p pending
	if err := strictJSON(b, &p); err != nil {
		return nil, fmt.Errorf("update: %s: %w", pendingFile, err)
	}
	if !filepath.IsAbs(p.Path) || p.Prev != p.Path+".prev" || len(p.Roles) == 0 || !full(p.Version) || len(p.SHA256) != 64 {
		return nil, fmt.Errorf("update: %s is malformed", pendingFile)
	}
	for _, r := range p.Roles {
		if !updatable(r) {
			return nil, fmt.Errorf("update: %s names the role %q", pendingFile, r)
		}
	}
	return &p, nil
}

func (a *Applier) writePending(p *pending) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return writeAtomic(a.State, pendingFile, b, 0o600)
}

func (a *Applier) clearPending() error {
	if err := os.Remove(filepath.Join(a.State, pendingFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("update: clearing %s: %w", pendingFile, err)
	}
	return syncDir(a.State)
}

// report writes the status file and returns err; a status file that cannot be written is added
// to err.
func (a *Applier) report(st Status, err error) error {
	a.reported = true
	now := time.Now
	if a.Clock != nil {
		now = a.Clock
	}
	st.At = now().UTC()
	path := a.Status
	if path == "" {
		path = StatusFile
	}
	b, merr := json.Marshal(st)
	if merr != nil {
		return errors.Join(err, merr)
	}
	if merr := os.MkdirAll(filepath.Dir(path), 0o755); merr != nil { //nolint:gosec // G301: the agent reads the status
		return errors.Join(err, fmt.Errorf("update: status: %w", merr))
	}
	if werr := writeAtomic(filepath.Dir(path), filepath.Base(path), b, 0o644); werr != nil {
		return errors.Join(err, werr)
	}
	return err
}

// writeAtomic replaces dir/name: a new file, synced, renamed over the old one, and the directory
// synced, so a crash leaves the old file or the new one.
func writeAtomic(dir, name string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename
	_, err = tmp.Write(append(b, '\n'))
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(dir, name))
	}
	if err == nil {
		err = syncDir(dir)
	}
	if err != nil {
		return fmt.Errorf("update: writing %s: %w", name, err)
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

// sameFile reports whether the file at path has the SHA-256 sum.
func sameFile(path, sum string) (bool, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the installed binary
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, MaxArtifact+1)); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == sum, nil
}

// syncDir syncs a directory, so a rename in it survives a crash.
func syncDir(dir string) error {
	if syncDirHook != nil {
		if err := syncDirHook(dir); err != nil {
			return err
		}
	}
	d, err := os.Open(dir) //nolint:gosec // G304: the binary's directory or the updater's own
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// updatable reports whether the updater replaces a role's binary: gateways and connectors only
// (D102).
func updatable(role string) bool { return role == "gateway" || role == "connector" }

// unitOf is the systemd unit of a role.
func unitOf(role string) string { return "rpmgr-" + role + ".service" }
