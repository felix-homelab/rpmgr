// SPDX-License-Identifier: Apache-2.0

//go:build linux

package update_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/update"
)

// services is a fake systemd: it records restarts, and each unit fails, restarts in a loop or runs.
type services struct {
	mu       sync.Mutex
	restarts []string
	failed   map[string]bool // units whose state is failed
	looping  map[string]bool // units that systemd keeps restarting
	counts   map[string]int
}

func (s *services) Restart(_ context.Context, unit string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restarts = append(s.restarts, unit)
	return nil
}

func (s *services) State(_ context.Context, unit string) (bool, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counts == nil {
		s.counts = map[string]int{}
	}
	if s.looping[unit] {
		s.counts[unit]++
	}
	return s.failed[unit], s.counts[unit], nil
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
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "rpmgr")
	mustWrite(t, bin, string(binary(running, "full")), 0o755)
	if o.install == "" {
		o.install = `{"method":"script","path":"` + bin + `","variant":"full","roles":["` + strings.Join(roles, `","`) + `"]}`
	}
	h := newHost(t, o)
	svc := &services{}
	a := &update.Applier{Updater: *h.u, Services: svc, Previous: running, Status: filepath.Join(t.TempDir(), "run", "status.json"),
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
	if st.Version != "1.2.0" || st.Previous != "1.1.0" || !st.At.Equal(now) {
		t.Errorf("status %+v", st)
	}
	if got := i.svc.restarted(); !slices.Equal(got, []string{"rpmgr-gateway.service", "rpmgr-connector.service"}) {
		t.Errorf("restarted %v; want each role of install.json", got)
	}
	for _, leftover := range []string{filepath.Join(filepath.Dir(i.bin), ".rpmgr.new"), i.bin + ".prev.tmp"} {
		if _, err := os.Lstat(leftover); err == nil {
			t.Errorf("%s was left", leftover)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(i.u.State, "staging")); len(entries) > 0 {
		t.Errorf("the verified copy was left in staging/: %d files", len(entries))
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
	})

	for name, svc := range map[string]*services{
		"failed unit":  {failed: map[string]bool{"rpmgr-connector.service": true}},
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
	if _, err := os.Lstat(filepath.Join(filepath.Dir(i.bin), ".rpmgr.new")); err == nil {
		t.Error(".rpmgr.new was left")
	}
	if got := i.svc.restarted(); len(got) > 0 {
		t.Errorf("restarted %v", got)
	}
}

func TestApply_RefusedHosts(t *testing.T) {
	t.Run("a controller host", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"controller"}, nil)
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
			t.Fatalf("Apply = %v; want refused", err)
		}
		i.runs("1.1.0")
	})
	t.Run("nothing staged", func(t *testing.T) {
		i := newInstalled(t, hostOpts{}, "1.1.0", []string{"connector"}, nil)
		if err := i.a.Apply(context.Background()); err == nil {
			t.Fatal("Apply succeeded with nothing staged")
		}
		i.status(update.Refused)
	})
	t.Run("a relative binary path", func(t *testing.T) {
		i := newInstalled(t, hostOpts{install: `{"method":"script","path":"rpmgr","variant":"full","roles":["connector"]}`},
			"1.1.0", []string{"connector"}, nil)
		i.stage(rel{version: "1.2.0", seq: 6})
		if err := i.a.Apply(context.Background()); !errors.Is(err, update.ErrRefused) {
			t.Fatalf("Apply = %v; want refused", err)
		}
	})
}

func TestSystemd_State(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "systemctl")
	mustWrite(t, script, "#!/bin/sh\nif [ \"$1\" = show ]; then printf 'ActiveState=failed\\nNRestarts=4\\n'; fi\n", 0o755)
	s := update.Systemd{Systemctl: script}
	if err := s.Restart(context.Background(), "rpmgr-connector.service"); err != nil {
		t.Fatal(err)
	}
	failed, n, err := s.State(context.Background(), "rpmgr-connector.service")
	if err != nil || !failed || n != 4 {
		t.Fatalf("State = %v, %d, %v", failed, n, err)
	}
	mustWrite(t, script, "#!/bin/sh\necho 'Job failed' >&2\nexit 1\n", 0o755)
	if err := s.Restart(context.Background(), "rpmgr-connector.service"); err == nil || !strings.Contains(err.Error(), "Job failed") {
		t.Errorf("Restart of a failing unit: %v", err)
	}
	if _, _, err := s.State(context.Background(), "rpmgr-connector.service"); err == nil {
		t.Error("State succeeded although systemctl failed")
	}
}
