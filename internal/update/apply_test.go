// SPDX-License-Identifier: Apache-2.0

//go:build linux

package update_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/units"
	"github.com/felix-homelab/rpmgr/internal/update"
)

// services is a fake systemd: it records restarts; a unit is active unless it is listed as
// failed or in another state, and a looping one gains a restart at each look.
type services struct {
	mu       sync.Mutex
	restarts []string
	active   map[string]string // a unit's ActiveState other than active
	looping  map[string]bool   // units that systemd keeps restarting
	counts   map[string]int
	// A unit in notify runs as Type=notify with a main process: a hand-off may restart it.
	notify     map[string]bool
	handoffs   []string         // "<bin> <role>" of each hand-off
	handoffErr map[string]error // a role whose hand-off fails
}

func (s *services) Handoff(_ context.Context, bin, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handoffs = append(s.handoffs, bin+" "+role)
	return s.handoffErr[role]
}

func (s *services) Restart(_ context.Context, unit string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restarts = append(s.restarts, unit)
	return nil
}

func (s *services) State(_ context.Context, unit string) (update.Unit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counts == nil {
		s.counts = map[string]int{}
	}
	if s.looping[unit] {
		s.counts[unit]++
	}
	active := "active"
	if a := s.active[unit]; a != "" {
		active = a
	}
	u := update.Unit{Active: active, Restarts: s.counts[unit]}
	if s.notify[unit] {
		u.Notify, u.MainPID = true, 4242
	}
	return u, nil
}

func (s *services) restarted() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.restarts)
}

// installed is a host whose binary, at a path install.json records, runs version running.
type installed struct {
	*host
	a   *update.Applier
	svc *services
	bin string
}

// newInstalled returns a host that runs version running for roles, ready unless ready says
// otherwise: ready is called with the binary's content at each poll.
func newInstalled(t *testing.T, o hostOpts, running string, roles []string, ready func(bin []byte) error) *installed {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "rpmgr")
	mustWrite(t, bin, string(binary(running, "full")), 0o755)
	if o.install == "" {
		o.install = `{"method":"script","path":"` + bin + `","variant":"full","roles":["` + strings.Join(roles, `","`) + `"]}`
	}
	h := newHost(t, o)
	svc := &services{}
	a := &update.Applier{Updater: *h.u, Services: svc, Previous: running, Units: t.TempDir(), Status: filepath.Join(t.TempDir(), "run", "status.json"),
		Interval: 5 * time.Millisecond, Window: 200 * time.Millisecond, Clock: func() time.Time { return now }}
	a.Ready = func(context.Context, string) error {
		b, err := os.ReadFile(bin) //nolint:gosec // G304: under t.TempDir
		if err != nil {
			return err
		}
		if ready == nil {
			return nil
		}
		return ready(b)
	}
	return &installed{host: h, a: a, svc: svc, bin: bin}
}

// writeAll writes a file and the directories above it.
func writeAll(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // G301: under t.TempDir
		t.Fatal(err)
	}
	mustWrite(t, path, body, 0o644)
}

// notReady is a readiness check that fails for the binary of version v.
func notReady(v string) func([]byte) error {
	return func(b []byte) error {
		if bytes.Equal(b, binary(v, "full")) {
			return errors.New("not ready: no control session")
		}
		return nil
	}
}

func (i *installed) runs(version string) {
	i.t.Helper()
	if got, err := os.ReadFile(i.bin); err != nil || !bytes.Equal(got, binary(version, "full")) {
		i.t.Fatalf("the binary holds %q, %v; want %s", got, err, version)
	}
}

func (i *installed) status(want string) update.Status {
	i.t.Helper()
	st, err := update.ReadStatus(i.a.Status)
	if err != nil {
		i.t.Fatalf("status file: %v", err)
	}
	if st.State != want {
		i.t.Fatalf("status %+v; want %s", st, want)
	}
	if fi, err := os.Stat(i.a.Status); err != nil || fi.Mode().Perm() != 0o644 {
		i.t.Errorf("status file mode %v, %v; want 0644", fi.Mode(), err)
	}
	return st
}

func (i *installed) state() update.State {
	i.t.Helper()
	st, err := update.ReadState(i.u.State)
	if err != nil {
		i.t.Fatal(err)
	}
	return st
}

// pendingLeft reports whether a pending install is recorded.
func (i *installed) pendingLeft() bool {
	_, err := os.Lstat(filepath.Join(i.u.State, "pending.json"))
	return err == nil
}

// leftovers fails on files the updater must not leave beside the binary.
func (i *installed) leftovers() {
	i.t.Helper()
	dir := filepath.Dir(i.bin)
	for _, name := range []string{".rpmgr.new", "rpmgr.prev.tmp", ".rpmgr.rollback"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			i.t.Errorf("%s was left", name)
		}
	}
}

func TestApply_InstallsAndRaisesTheFloor(t *testing.T) {
	i := newInstalled(t, hostOpts{}, "1.1.0", []string{"gateway", "connector"}, nil)
	i.stage(rel{version: "1.2.0", floor: "1.1.0", seq: 6})
	if err := i.a.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	i.runs("1.2.0")
	if prev, err := os.ReadFile(i.bin + ".prev"); err != nil || !bytes.Equal(prev, binary("1.1.0", "full")) {
		t.Errorf(".prev holds %q, %v; want the previous binary", prev, err)
	}
	if fi, err := os.Stat(i.bin); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("binary mode %v, %v", fi.Mode(), err)
	}
	if st := i.state(); st.Seq != 6 || st.Floor != "1.1.0" {
		t.Errorf("state %+v; want seq 6, floor 1.1.0 after success", st)
	}
	st := i.status(update.Updated)
	if st.Version != "1.2.0" || st.Previous != "1.1.0" || st.Reason != "" || !st.At.Equal(now) {
		t.Errorf("status %+v", st)
	}
	if got := i.svc.restarted(); !slices.Equal(got, []string{"rpmgr-connector.service", "rpmgr-gateway.service"}) {
		t.Errorf("restarted %v; want each role of install.json", got)
	}
	i.leftovers()
	if i.pendingLeft() {
		t.Error("pending.json was left after a finished install")
	}
	if entries, _ := os.ReadDir(filepath.Join(i.u.State, "staging")); len(entries) > 0 {
		t.Errorf("the verified copy was left in staging/: %d files", len(entries))
	}
	// Run again, as at the next boot: the staged release is the installed binary, so nothing is
	// restarted and the status stays.
	if err := i.a.Apply(context.Background()); err != nil {
		t.Fatalf("Apply with the installed release staged: %v", err)
	}
	if got := i.svc.restarted(); len(got) != 2 {
		t.Errorf("restarted %v; the installed release must not be installed again", got)
	}
}

// TestOTA_UpdaterHonoursPolicy (docs/12): the root updater decides from the local policy itself
// and refuses what the policy refuses, even if the agent staged it; a role that is not ready
// within the window, or whose service fails or restarts in a loop, is rolled back; a version
// rolled back is refused until a manifest with a higher seq offers it.
func TestOTA_UpdaterHonoursPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		policy string
		mode   os.FileMode
	}{
		"off":                {policy: "version: 1\nauto_update: off\nupdate_channel: stable\n", mode: 0o644},
		"notify":             {policy: "version: 1\nauto_update: notify\nupdate_channel: stable\n", mode: 0o644},
		"does not parse":     {policy: "version: 1\nauto_update: [\n", mode: 0o644},
		"writable by others": {policy: "version: 1\nauto_update: auto\nupdate_channel: stable\n", mode: 0o646},
	} {
		t.Run("refused: "+name, func(t *testing.T) {
			i := newInstalled(t, hostOpts{policy: tc.policy}, "1.1.0", []string{"connector"}, nil)
			if err := os.Chmod(i.u.Policy, tc.mode); err != nil {
				t.Fatal(err)
			}
			i.stage(rel{version: "1.2.0", seq: 6})
			if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
				t.Fatalf("Apply = %v; want refused", err)
			}
			i.runs("1.1.0")
			i.status(update.Refused)
			if got := i.svc.restarted(); len(got) > 0 {
				t.Errorf("restarted %v for a refused release", got)
			}
			if st := i.state(); st.Seq != 5 {
				t.Errorf("state %+v changed", st)
			}
		})
	}

	t.Run("not ready within the window: rolled back", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"gateway", "connector"}, notReady("1.2.0"))
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRolledBack) {
			t.Fatalf("Apply = %v; want rolled back", err)
		}
		i.runs("1.1.0")
		st := i.status(update.RolledBack)
		if st.Version != "1.2.0" || !strings.Contains(st.Reason, "not ready") {
			t.Errorf("status %+v", st)
		}
		if s := i.state(); s.Seq != 5 || s.Floor != "1.0.0" || s.Failed == nil || *s.Failed != (update.Failed{Version: "1.2.0", Seq: 6}) {
			t.Errorf("state %+v; want seq and floor unchanged and 1.2.0 recorded as failed", s)
		}
		// Restarted for the update, then again for the rollback.
		if got := i.svc.restarted(); len(got) != 4 {
			t.Errorf("restarted %v; want both roles twice", got)
		}
		i.leftovers()
		if i.pendingLeft() {
			t.Error("pending.json was left after a rollback")
		}
	})

	t.Run("rolled back to a release without the hand-off: the drop-ins go (D155)", func(t *testing.T) {
		for _, tc := range []struct {
			previous string
			removed  bool
		}{{"0.2.0", true}, {"dev", true}, {"1.1.0", false}} {
			i := newInstalled(t, hostOpts{}, tc.previous, []string{"gateway", "connector"}, notReady("1.2.0"))
			i.a.Units = t.TempDir()
			dropIn := func(role string) string {
				return filepath.Join(i.a.Units, "rpmgr-"+role+".service.d", units.DropIn)
			}
			for _, role := range []string{"gateway", "connector"} {
				writeAll(t, dropIn(role), "[Service]\nType=notify\n")
			}
			i.stage(rel{version: "1.2.0", seq: 6})
			if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRolledBack) {
				t.Fatalf("%s: Apply = %v; want rolled back", tc.previous, err)
			}
			for _, role := range []string{"gateway", "connector"} {
				_, err := os.Stat(dropIn(role))
				if gone := errors.Is(err, fs.ErrNotExist); gone != tc.removed {
					t.Errorf("rolled back to %s: drop-in of %s removed = %v, want %v", tc.previous, role, gone, tc.removed)
				}
			}
		}
	})

	t.Run("a drop-in that cannot be removed: the rollback failed", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "0.2.0", []string{"gateway"}, notReady("1.2.0"))
		i.a.Units = t.TempDir()
		// A non-empty directory in the drop-in's place: removing it fails.
		writeAll(t, filepath.Join(i.a.Units, "rpmgr-gateway.service.d", units.DropIn, "x"), "")
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRollbackFailed) {
			t.Fatalf("Apply = %v; want rollback failed", err)
		}
	})

	t.Run("active but not ready, or ready but not active: rolled back", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, nil)
		i.svc.active = map[string]string{"rpmgr-connector.service": "activating"}
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRolledBack) {
			t.Fatalf("Apply = %v; want rolled back: a unit that is still activating is not ready", err)
		}
		if st := i.status(update.RolledBack); !strings.Contains(st.Reason, "activating") {
			t.Errorf("status %+v; want the unit's state as the reason", st)
		}
	})

	for name, svc := range map[string]*services{
		"failed unit":  {active: map[string]string{"rpmgr-connector.service": "failed"}},
		"restart loop": {looping: map[string]bool{"rpmgr-connector.service": true}},
	} {
		t.Run(name+": rolled back before the window ends", func(t *testing.T) {
			i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, notReady("1.2.0"))
			i.svc, i.a.Services = svc, svc
			i.a.Window = time.Minute
			i.stage(rel{version: "1.2.0", seq: 6})
			start := time.Now()
			if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRolledBack) {
				t.Fatalf("Apply = %v; want rolled back", err)
			}
			if d := time.Since(start); d > 10*time.Second {
				t.Errorf("rolled back after %v; a failed or looping unit must end the wait at once", d)
			}
			i.runs("1.1.0")
			i.status(update.RolledBack)
		})
	}

	t.Run("a unit that restarts after it was ready: rolled back", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, nil)
		i.a.MaxRestarts = 1
		var once sync.Once
		ready := i.a.Ready
		i.a.Ready = func(ctx context.Context, role string) error {
			once.Do(func() { i.svc.looping = map[string]bool{"rpmgr-connector.service": true} })
			return ready(ctx, role)
		}
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRolledBack) {
			t.Fatalf("Apply = %v; want rolled back: the final check sees the restart", err)
		}
	})

	t.Run("a rolled-back version waits for a higher seq", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, notReady("1.2.0"))
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRolledBack) {
			t.Fatalf("first Apply = %v", err)
		}
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
			t.Fatalf("the same manifest again: %v; want refused", err)
		}
		i.runs("1.1.0")
		i.status(update.Refused)
		i.a.Ready = func(context.Context, string) error { return nil }
		i.stage(rel{version: "1.2.0", seq: 7})
		if err := i.a.Apply(context.Background()); err != nil {
			t.Fatalf("a newer manifest offering it again: %v", err)
		}
		i.runs("1.2.0")
		i.leftovers() // .prev was the installed binary after the rollback: no .prev.tmp may stay
	})
}

// TestOTA_SignedDowngradeAccepted (docs/12): a newly signed manifest with a higher seq that lowers
// the floor installs an older version; a replayed older manifest is refused; the automatic
// rollback to .prev works although .prev is below the floor of the manifest it rolls back from.
func TestOTA_SignedDowngradeAccepted(t *testing.T) {
	t.Run("a higher seq lowers the floor", func(t *testing.T) {
		i := newInstalled(t, hostOpts{state: `{"seq":9,"floor":"1.3.0"}`}, "1.3.0", []string{"connector"}, nil)
		i.stage(rel{version: "1.2.0", floor: "1.1.0", seq: 10})
		if err := i.a.Apply(context.Background()); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		i.runs("1.2.0")
		if st := i.state(); st.Seq != 10 || st.Floor != "1.1.0" {
			t.Errorf("state %+v; want seq 10, floor 1.1.0", st)
		}
	})
	t.Run("a replayed older manifest is refused", func(t *testing.T) {
		i := newInstalled(t, hostOpts{state: `{"seq":9,"floor":"1.3.0"}`}, "1.3.0", []string{"connector"}, nil)
		i.stage(rel{version: "1.2.0", floor: "1.1.0", seq: 8})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
			t.Fatalf("Apply = %v; want refused", err)
		}
		i.runs("1.3.0")
	})
	t.Run("the rollback ignores the floor", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.2.0", []string{"connector"}, notReady("1.4.0"))
		i.stage(rel{version: "1.4.0", floor: "1.4.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRolledBack) {
			t.Fatalf("Apply = %v; want rolled back", err)
		}
		i.runs("1.2.0") // below the floor 1.4.0 that the failed manifest named
		if st := i.state(); st.Floor != "1.0.0" || st.Seq != 5 {
			t.Errorf("state %+v; the floor is raised only after success", st)
		}
	})
}

// TestPolicy_AutoUpdateAndChannelDefaults (root-updater clause; docs/12): with no policy file the
// root updater behaves as auto_update auto and update_channel stable.
func TestPolicy_AutoUpdateAndChannelDefaults(t *testing.T) {
	i := newInstalled(t, hostOpts{policy: "-"}, "1.1.0", []string{"connector"}, nil)
	i.stage(rel{version: "1.2.0-rc.1", channel: release.Prerelease, seq: 6})
	if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
		t.Fatalf("a prerelease without a policy file: %v; want refused (stable)", err)
	}
	i.runs("1.1.0")
	i.stage(rel{version: "1.2.0", seq: 7})
	if err := i.a.Apply(context.Background()); err != nil {
		t.Fatalf("a stable release without a policy file: %v; want installed (auto)", err)
	}
	i.runs("1.2.0")
}

func TestApply_FailureBeforeTheRenameKeepsTheBinary(t *testing.T) {
	i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, nil)
	i.stage(rel{version: "1.2.0", seq: 6})
	update.BeforeSwap(t, func(path string) {
		if err := os.WriteFile(path, []byte("rpmgr 1.2.0 fuLL"), 0o755); err != nil { //nolint:gosec // G306: a binary under t.TempDir
			t.Error(err)
		}
	})
	if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
		t.Fatalf("Apply = %v; want refused: the new binary did not match", err)
	}
	i.runs("1.1.0")
	i.status(update.Refused)
	i.leftovers()
	if got := i.svc.restarted(); len(got) > 0 {
		t.Errorf("restarted %v", got)
	}
	if i.pendingLeft() {
		t.Error("pending.json was left by a refused install")
	}
}

// TestApply_AfterTheRename: once the new binary is in place the install is finished, whatever
// happens: a directory that cannot be synced is a warning, an interrupted run is finished by the
// next one, and a rollback that cannot put the old binary back is reported as such.
func TestApply_AfterTheRename(t *testing.T) {
	t.Run("a sync error is a warning", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, nil)
		update.SyncDirFails(t, filepath.Dir(i.bin))
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); err != nil {
			t.Fatalf("Apply = %v; a sync error after the rename must not refuse", err)
		}
		i.runs("1.2.0")
		if st := i.status(update.Updated); !strings.Contains(st.Reason, "could not be synced") {
			t.Errorf("status %+v; want the warning", st)
		}
		if got := i.svc.restarted(); len(got) != 1 {
			t.Errorf("restarted %v; the roles must restart and be checked", got)
		}
	})
	for name, ready := range map[string]func([]byte) error{
		"ready":     nil,
		"not ready": notReady("1.2.0"),
	} {
		t.Run("interrupted, then resumed: "+name, func(t *testing.T) {
			i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, ready)
			i.stage(rel{version: "1.2.0", seq: 6})
			update.AfterRename(t, func() bool { return false })
			if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrInterrupted) {
				t.Fatalf("Apply = %v; want interrupted", err)
			}
			if !i.pendingLeft() {
				t.Fatal("no pending install recorded before the rename")
			}
			i.runs("1.2.0")
			update.AfterRename(t, func() bool { return true })
			err := i.a.Apply(context.Background())
			if ready == nil {
				if err != nil {
					t.Fatalf("resumed Apply: %v", err)
				}
				i.runs("1.2.0")
				if st := i.status(update.Updated); !strings.Contains(st.Reason, "resumed") {
					t.Errorf("status %+v", st)
				}
				if st := i.state(); st.Seq != 6 {
					t.Errorf("state %+v; the resumed install raises seq", st)
				}
			} else {
				if !errors.Is(err, update.ErrRolledBack) {
					t.Fatalf("resumed Apply = %v; want rolled back", err)
				}
				i.runs("1.1.0")
				i.status(update.RolledBack)
			}
			if i.pendingLeft() {
				t.Error("pending.json was left after the resumed run")
			}
		})
	}
	t.Run("a pending install whose binary was never replaced", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, nil)
		sum := sha256.Sum256(binary("1.2.0", "full"))
		pending := `{"version":"1.2.0","seq":6,"sha256":"` + hex.EncodeToString(sum[:]) + `","path":"` + i.bin +
			`","prev":"` + i.bin + `.prev","roles":["connector"],"next":{"seq":6,"floor":"1.0.0"}}`
		mustWrite(t, filepath.Join(i.u.State, "pending.json"), pending, 0o600)
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
			t.Fatalf("Apply = %v; want refused: nothing changed", err)
		}
		i.runs("1.1.0")
		if i.pendingLeft() || len(i.svc.restarted()) > 0 {
			t.Error("a pending install that never replaced the binary restarted roles or stayed")
		}
	})
	t.Run("a malformed pending install", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, nil)
		mustWrite(t, filepath.Join(i.u.State, "pending.json"), `{"version":"1.2.0","roles":["controller"]}`, 0o600)
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); err == nil {
			t.Fatal("Apply went on past a malformed pending.json")
		}
		i.runs("1.1.0")
	})
	t.Run("the rollback fails", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, notReady("1.2.0"))
		i.stage(rel{version: "1.2.0", seq: 6})
		update.AfterRename(t, func() bool {
			if err := os.Remove(i.bin + ".prev"); err != nil {
				t.Error(err)
			}
			return true
		})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRollbackFailed) {
			t.Fatalf("Apply = %v; want the rollback failed", err)
		}
		if st := i.status(update.RollbackFailed); st.Version != "1.2.0" {
			t.Errorf("status %+v", st)
		}
		if st := i.state(); st.Failed == nil || st.Failed.Version != "1.2.0" {
			t.Errorf("state %+v; the version is recorded as failed", st)
		}
	})
}

func TestApply_RefusedHosts(t *testing.T) {
	for name, roles := range map[string][]string{
		"a controller host":  {"controller"},
		"an all-in-one host": {"all-in-one", "connector"},
		"an unknown role":    {"connector", "importer"},
	} {
		t.Run(name, func(t *testing.T) {
			i := newInstalled(t, hostOpts{}, "1.1.0", roles, nil)
			i.stage(rel{version: "1.2.0", seq: 6})
			if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
				t.Fatalf("Apply = %v; want refused", err)
			}
			i.runs("1.1.0")
		})
	}
	t.Run("a role listed twice restarts once", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector", "connector"}, nil)
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := i.svc.restarted(); len(got) != 1 {
			t.Errorf("restarted %v", got)
		}
	})
	t.Run("a relative binary path", func(t *testing.T) {
		i := newInstalled(t, hostOpts{install: `{"method":"script","path":"rpmgr","variant":"full","roles":["connector"]}`},
			"1.1.0", []string{"connector"}, nil)
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
			t.Fatalf("Apply = %v; want refused", err)
		}
	})
	t.Run("a binary path that is a symbolic link", func(t *testing.T) {
		real := filepath.Join(t.TempDir(), "rpmgr-real")
		mustWrite(t, real, string(binary("1.1.0", "full")), 0o755)
		link := filepath.Join(t.TempDir(), "rpmgr")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		i := newInstalled(t, hostOpts{install: `{"method":"script","path":"` + link + `","variant":"full","roles":["connector"]}`},
			"1.1.0", []string{"connector"}, nil)
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
			t.Fatalf("Apply = %v; want refused", err)
		}
		if b, _ := os.ReadFile(real); !bytes.Equal(b, binary("1.1.0", "full")) { //nolint:gosec // G304: under t.TempDir
			t.Errorf("the link's target was changed: %q", b)
		}
	})
}

// TestApply_PlantedLinks: links where the updater writes, .rpmgr.new and .prev, are replaced, never
// followed.
func TestApply_PlantedLinks(t *testing.T) {
	i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, nil)
	victim := filepath.Join(t.TempDir(), "victim")
	mustWrite(t, victim, "keep me", 0o644)
	for _, name := range []string{filepath.Join(filepath.Dir(i.bin), ".rpmgr.new"), i.bin + ".prev", i.bin + ".prev.tmp"} {
		if err := os.Symlink(victim, name); err != nil {
			t.Fatal(err)
		}
	}
	i.stage(rel{version: "1.2.0", seq: 6})
	if err := i.a.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	i.runs("1.2.0")
	if b, _ := os.ReadFile(victim); string(b) != "keep me" { //nolint:gosec // G304: under t.TempDir
		t.Errorf("a planted link was followed: the victim holds %q", b)
	}
	if fi, err := os.Lstat(i.bin + ".prev"); err != nil || !fi.Mode().IsRegular() {
		t.Errorf(".prev is %v, %v; want a regular file", fi.Mode(), err)
	}
	i.leftovers()
}

func TestSystemd_State(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "systemctl")
	mustWrite(t, script, "#!/bin/sh\nif [ \"$1\" = show ]; then printf 'ActiveState=activating\\nNRestarts=4\\nMainPID=812\\nType=notify\\n'; fi\n", 0o755)
	s := update.Systemd{Systemctl: script}
	if err := s.Restart(context.Background(), "rpmgr-connector.service"); err != nil {
		t.Fatal(err)
	}
	u, err := s.State(context.Background(), "rpmgr-connector.service")
	if err != nil || u != (update.Unit{Active: "activating", Restarts: 4, MainPID: 812, Notify: true}) {
		t.Fatalf("State = %+v, %v", u, err)
	}
	log := filepath.Join(dir, "calls")
	mustWrite(t, script, "#!/bin/sh\necho \"$@\" >> "+log+"\n", 0o755)
	if err := s.Restart(context.Background(), "rpmgr-connector.service"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(log); string(b) != "daemon-reload\nrestart rpmgr-connector.service\n" { //nolint:gosec // G304: under t.TempDir
		t.Errorf("systemctl was called with %q; want a daemon-reload, then the restart", b)
	}
	mustWrite(t, script, "#!/bin/sh\necho 'Job failed' >&2\nexit 1\n", 0o755)
	if err := s.Restart(context.Background(), "rpmgr-connector.service"); err == nil || !strings.Contains(err.Error(), "Job failed") {
		t.Errorf("Restart of a failing unit: %v", err)
	}
	if _, err := s.State(context.Background(), "rpmgr-connector.service"); err == nil {
		t.Error("State succeeded although systemctl failed")
	}
	mustWrite(t, script, "#!/bin/sh\necho 'NRestarts=0'\n", 0o755)
	if _, err := s.State(context.Background(), "rpmgr-connector.service"); err == nil {
		t.Error("State succeeded without an ActiveState")
	}
}

// TestSystemd_Handoff runs `<bin> handoff <role>` of the binary it is given, and returns what a
// failed hand-off says.
func TestSystemd_Handoff(t *testing.T) {
	dir := t.TempDir()
	bin, log := filepath.Join(dir, "rpmgr"), filepath.Join(dir, "calls")
	mustWrite(t, bin, "#!/bin/sh\necho \"$@\" >> "+log+"\n", 0o755)
	if err := (update.Systemd{}).Handoff(context.Background(), bin, "gateway"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(log); string(b) != "handoff gateway\n" { //nolint:gosec // G304: under t.TempDir
		t.Errorf("the binary was called with %q", b)
	}
	mustWrite(t, bin, "#!/bin/sh\necho 'hand-off failed: not ready; process 7 serves on' >&2\nexit 1\n", 0o755)
	if err := (update.Systemd{}).Handoff(context.Background(), bin, "gateway"); err == nil || !strings.Contains(err.Error(), "serves on") {
		t.Errorf("Handoff of a failing binary: %v", err)
	}
	if err := (update.Systemd{}).Handoff(context.Background(), filepath.Join(dir, "none"), "gateway"); err == nil {
		t.Error("Handoff succeeded without a binary")
	}
}

// TestApply_NothingStaged: the run at every boot, and a start of the path unit while the agent is
// still staging, find no manifest: the updater does nothing and reports nothing, so the outcome of
// an earlier run stays for the agent, also on a host that the updater refuses. A staged set that
// does not verify is still refused and reported.
func TestApply_NothingStaged(t *testing.T) {
	earlier := `{"state":"updated","version":"1.1.0","previous":"1.0.0","at":"2026-10-19T08:00:00Z"}`
	for _, tc := range []struct {
		name    string
		install string
		prepare func(i *installed)
	}{
		{name: "empty staging directory", prepare: func(*installed) {}},
		{name: "no staging directory", prepare: func(i *installed) {
			if err := os.Remove(i.u.Staged); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "manifest not written yet", prepare: func(i *installed) {
			i.stage(rel{version: "1.2.0", seq: 6})
			if err := os.Remove(filepath.Join(i.u.Staged, "manifest.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "controller host", install: `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full","roles":["controller"]}`,
			prepare: func(*installed) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := newInstalled(t, hostOpts{install: tc.install}, "1.1.0", []string{"connector"}, nil)
			tc.prepare(i)
			mustMkdir(t, filepath.Dir(i.a.Status), 0o755)
			mustWrite(t, i.a.Status, earlier, 0o644)
			if err := i.a.Apply(context.Background()); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if i.a.Reported() {
				t.Error("Reported with nothing staged")
			}
			if got, err := os.ReadFile(i.a.Status); err != nil || string(got) != earlier {
				t.Errorf("the status file became %q, %v; the earlier outcome must stay", got, err)
			}
			if r := i.svc.restarted(); len(r) > 0 {
				t.Errorf("restarted %q", r)
			}
			if tc.install == "" {
				i.runs("1.1.0")
			}
		})
	}
	t.Run("staged but invalid", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, nil)
		i.stage(rel{version: "1.2.0", seq: 6})
		mustWrite(t, filepath.Join(i.u.Staged, "manifest.json"), `{"seq":6}`, 0o640)
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
			t.Fatalf("Apply = %v; want a refusal", err)
		}
		if !i.a.Reported() {
			t.Error("a refusal was not reported")
		}
		i.status(update.Refused)
		i.runs("1.1.0")
	})
}
