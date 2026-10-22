// SPDX-License-Identifier: Apache-2.0

package update_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/units"
	"github.com/felix-homelab/rpmgr/internal/update"
)

// connector is what an install script records for a connector of the full build.
func connector(seq uint64, floor string) update.Installed {
	return update.Installed{Install: update.Install{Method: "script", Path: "/usr/local/bin/rpmgr", Variant: "full",
		Roles: []string{"connector"}}, Seq: seq, Floor: floor}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: a test file
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRecord_FreshHost: an installer on a host without the updater creates its directory, root's
// with mode 0700, the record and the state from the release, both 0600; running it again changes
// nothing.
func TestRecord_FreshHost(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "var", "lib", "rpmgr-update")
	rec, st, err := update.Record(dir, connector(87, "1.4.2"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Method != "script" || rec.Variant != "full" || strings.Join(rec.Roles, ",") != "connector" || st != (update.State{Seq: 87, Floor: "1.4.2"}) {
		t.Errorf("record %+v, state %+v", rec, st)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("directory %v, %v; want 0700", fi.Mode(), err)
	}
	install, state := filepath.Join(dir, "install.json"), filepath.Join(dir, "state.json")
	for _, f := range []string{install, state} {
		if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v; want 0600", f, fi.Mode(), err)
		}
	}
	wantInstall := `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full","roles":["connector"]}` + "\n"
	if got := readFile(t, install); got != wantInstall {
		t.Errorf("install.json %q, want %q", got, wantInstall)
	}
	if got, err := update.ReadState(dir); err != nil || got != (update.State{Seq: 87, Floor: "1.4.2"}) {
		t.Errorf("state.json %+v, %v", got, err)
	}
	before := readFile(t, install) + readFile(t, state)
	if _, _, err := update.Record(dir, connector(87, "1.4.2")); err != nil {
		t.Fatal(err)
	}
	if after := readFile(t, install) + readFile(t, state); after != before {
		t.Errorf("a second run changed the files:\n%s\n%s", before, after)
	}
}

// TestRecord_KeepsTheRecord: the roles recorded stay, the single role of v0.1.0 becomes a list, new
// roles join them, and an installer that names no method keeps the recorded one; another variant
// is refused and changes nothing.
func TestRecord_KeepsTheRecord(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "install.json"), `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full","role":"gateway"}`, 0o600)
	in := connector(0, "")
	in.Method = ""
	rec, st, err := update.Record(dir, in)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Method != "script" || strings.Join(rec.Roles, ",") != "connector,gateway" || rec.Role != "" {
		t.Errorf("record %+v", rec)
	}
	if st != (update.State{}) {
		t.Errorf("state %+v without a seq and without a state file", st)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a state was written without a release seq: %v", err)
	}
	read, err := update.ReadInstall(dir)
	if err != nil || strings.Join(read.Roles, ",") != "connector,gateway" || read.Role != "" {
		t.Errorf("read back %+v, %v", read, err)
	}
	before := readFile(t, filepath.Join(dir, "install.json"))
	other := connector(0, "")
	other.Variant = "connector"
	if _, _, err := update.Record(dir, other); err == nil || !strings.Contains(err.Error(), "records the full build") {
		t.Errorf("another variant: %v", err)
	}
	if after := readFile(t, filepath.Join(dir, "install.json")); after != before {
		t.Errorf("a refused variant changed the record: %s", after)
	}
}

// TestRecord_RaisesNeverLowers: an installer raises the seq and the floor to its release's and
// never lowers either; a version rolled back stays recorded; without a seq the state stays.
func TestRecord_RaisesNeverLowers(t *testing.T) {
	failed := &update.Failed{Version: "1.3.1", Seq: 9}
	for _, tc := range []struct {
		name       string
		seq        uint64
		floor      string
		want       update.State
		unchanged  bool
		stateAfter string
	}{
		{name: "older release", seq: 8, floor: "1.2.0", want: update.State{Seq: 9, Floor: "1.3.0", Failed: failed}, unchanged: true},
		{name: "same release", seq: 9, floor: "1.3.0", want: update.State{Seq: 9, Floor: "1.3.0", Failed: failed}, unchanged: true},
		{name: "newer seq, older version", seq: 10, floor: "1.2.0", want: update.State{Seq: 10, Floor: "1.3.0", Failed: failed}},
		{name: "same seq, newer version", seq: 9, floor: "1.4.0", want: update.State{Seq: 9, Floor: "1.4.0", Failed: failed}},
		{name: "newer release", seq: 12, floor: "1.5.0-rc.1", want: update.State{Seq: 12, Floor: "1.5.0-rc.1", Failed: failed}},
		{name: "no seq", want: update.State{Seq: 9, Floor: "1.3.0", Failed: failed}, unchanged: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			old := `{"seq":9,"floor":"1.3.0","failed":{"version":"1.3.1","seq":9}}`
			mustWrite(t, filepath.Join(dir, "state.json"), old, 0o600)
			_, st, err := update.Record(dir, connector(tc.seq, tc.floor))
			if err != nil {
				t.Fatal(err)
			}
			got, err := update.ReadState(dir)
			if err != nil || got.Seq != tc.want.Seq || got.Floor != tc.want.Floor || got.Failed == nil || *got.Failed != *failed {
				t.Errorf("state %+v, %v; want %+v", got, err, tc.want)
			}
			if st.Seq != got.Seq || st.Floor != got.Floor {
				t.Errorf("returned %+v, wrote %+v", st, got)
			}
			if tc.unchanged && readFile(t, filepath.Join(dir, "state.json")) != old {
				t.Errorf("the state was rewritten although nothing rose")
			}
		})
	}
}

// TestRecord_Refusals: what an installer refuses, leaving the files as they were: a path, variant,
// role or floor it cannot use, a record or state it cannot read (which may hide a higher seq), and
// a directory that is a symbolic link. A directory with a wider mode is narrowed to 0700.
func TestRecord_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(in *update.Installed)
		files map[string]string // in the directory before the run, mode 0600
		mode  os.FileMode       // of state.json, if not 0600
		want  string
	}{
		{name: "relative path", edit: func(in *update.Installed) { in.Path = "rpmgr" }, want: "no clean absolute path"},
		{name: "unclean path", edit: func(in *update.Installed) { in.Path = "/usr/local/bin/../bin/rpmgr" }, want: "no clean absolute path"},
		{name: "no variant", edit: func(in *update.Installed) { in.Variant = "" }, want: "no variant"},
		{name: "unknown role", edit: func(in *update.Installed) { in.Roles = []string{"importer"} }, want: `no role "importer"`},
		{name: "no method", edit: func(in *update.Installed) { in.Method = "" }, want: "names no method"},
		{name: "floor not semver", edit: func(in *update.Installed) { in.Floor = "v1.4" }, want: "no full semantic version"},
		{name: "malformed record", files: map[string]string{"install.json": `{"method":`}, want: "install.json"},
		{name: "unknown key in record", files: map[string]string{"install.json": `{"method":"script","channel":"x"}`}, want: "unknown field"},
		{name: "malformed state", files: map[string]string{"state.json": `{"seq":"high"}`}, want: "remove it to initialise"},
		{name: "state others may write", files: map[string]string{"state.json": `{"seq":1,"floor":"1.0.0"}`}, mode: 0o666, want: "only its owner may write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tc.files {
				mode := os.FileMode(0o600)
				if tc.mode != 0 && name == "state.json" {
					mode = tc.mode
				}
				mustWrite(t, filepath.Join(dir, name), body, mode)
			}
			in := connector(87, "1.4.2")
			if tc.edit != nil {
				tc.edit(&in)
			}
			if _, _, err := update.Record(dir, in); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Record = %v; want an error with %q", err, tc.want)
			}
			for _, name := range []string{"install.json", "state.json"} {
				body, ok := tc.files[name]
				if !ok {
					if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
						t.Errorf("a refusal wrote %s", name)
					}
				} else if got := readFile(t, filepath.Join(dir, name)); got != body {
					t.Errorf("%s was changed to %q", name, got)
				}
			}
		})
	}
	t.Run("symbolic link", func(t *testing.T) {
		base := t.TempDir()
		real, link := filepath.Join(base, "real"), filepath.Join(base, "rpmgr-update")
		mustMkdir(t, real, 0o700)
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := update.Record(link, connector(87, "1.4.2")); err == nil {
			t.Fatal("a symbolically linked directory was used")
		}
		if entries, _ := os.ReadDir(real); len(entries) > 0 {
			t.Errorf("wrote %d files through the link", len(entries))
		}
	})
	t.Run("wide directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "rpmgr-update")
		mustMkdir(t, dir, 0o755)
		if _, _, err := update.Record(dir, connector(87, "1.4.2")); err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("mode %v, %v; want 0700", fi.Mode(), err)
		}
	})
}

// TestOTA_FreshHostReplayRejected (docs/12): on a host freshly installed with release 1.4.2 of
// manifest 87, which never updated, an old, genuinely signed manifest is refused: one with a lower
// seq whatever its version, and one below the floor with the same seq, because the installer
// initialised the floor and seq from the release. A newer manifest is taken.
func TestOTA_FreshHostReplayRejected(t *testing.T) {
	fresh := func(t *testing.T) *host {
		t.Helper()
		base := t.TempDir()
		staged := filepath.Join(base, "update")
		mustMkdir(t, staged, 0o750)
		state := filepath.Join(base, "rpmgr-update") // the installer creates it
		if _, _, err := update.Record(state, connector(87, "1.4.2")); err != nil {
			t.Fatal(err)
		}
		root, err := release.ParsePublicKey(testRoot.Public())
		if err != nil {
			t.Fatal(err)
		}
		return &host{t: t, u: &update.Updater{Staged: staged, State: state, Policy: filepath.Join(base, "policy.yaml"),
			Roots: []release.PublicKey{root}, Now: func() time.Time { return now }, OS: "linux", Arch: "amd64"}}
	}
	t.Run("lower seq", func(t *testing.T) {
		h := fresh(t)
		h.stage(rel{version: "1.4.5", floor: "1.0.0", seq: 80})
		h.refused(update.ErrRefused)
	})
	t.Run("same seq below the floor", func(t *testing.T) {
		h := fresh(t)
		h.stage(rel{version: "1.3.0", floor: "1.0.0", seq: 87})
		h.refused(update.ErrRefused)
	})
	t.Run("newer manifest", func(t *testing.T) {
		h := fresh(t)
		h.stage(rel{version: "1.4.3", floor: "1.4.0", seq: 88})
		if s := h.staged(); s.Next != (update.State{Seq: 88, Floor: "1.4.0"}) {
			t.Errorf("next state %+v", s.Next)
		}
	})
}

// TestWriteUnits: the updater's units go into their files as `rpmgr systemd-unit update` prints
// them, with the recorded binary in ExecStart, readable by all; a binary path systemd would read
// differently is refused.
func TestWriteUnits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "systemd", "system")
	written, err := update.WriteUnits(dir, "/opt/rpmgr/bin/rpmgr")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join(dir, "rpmgr-update.path"), filepath.Join(dir, "rpmgr-update.service")}; strings.Join(written, " ") != strings.Join(want, " ") {
		t.Errorf("written %q, want %q", written, want)
	}
	printed, err := units.RenderUpdater("/opt/rpmgr/bin/rpmgr")
	if err != nil {
		t.Fatal(err)
	}
	var both []byte
	for _, f := range written {
		if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o644 {
			t.Errorf("%s: %v, %v; want 0644", f, fi.Mode(), err)
		}
		both = append(both, readFile(t, f)...)
	}
	if !bytes.Equal(both, printed) {
		t.Errorf("the files differ from systemd-unit update:\n%s\n---\n%s", both, printed)
	}
	if svc := readFile(t, written[1]); !strings.Contains(svc, "ExecStart=/opt/rpmgr/bin/rpmgr updater apply ") ||
		!strings.HasPrefix(svc, "# /etc/systemd/system/rpmgr-update.service\n") {
		t.Errorf("service:\n%s", svc)
	}
	if _, err := update.WriteUnits(t.TempDir(), "/opt/my rpmgr"); err == nil {
		t.Error("a binary path with a space was written into ExecStart")
	}
}
