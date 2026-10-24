// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/policy"
)

// TestSetUpdateKeys: each value of auto_update and update_channel is written and read back; the
// same value again changes nothing; a missing file is written new with the defaults besides.
func TestSetUpdateKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	changed, err := policy.SetUpdateChannel(path, "prerelease")
	mustChange(t, changed, err, true)
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
	p := load(t, path)
	if p.UpdateChannel != "prerelease" || p.AutoUpdate != "auto" || allows(p, "10.0.0.5:80") {
		t.Fatalf("a new file: channel %q, auto_update %q", p.UpdateChannel, p.AutoUpdate)
	}
	changed, err = policy.SetUpdateChannel(path, "prerelease")
	mustChange(t, changed, err, false)
	for _, v := range []string{"notify", "off", "auto"} {
		changed, err = policy.SetAutoUpdate(path, v)
		mustChange(t, changed, err, true)
		if p := load(t, path); p.AutoUpdate != v || p.UpdateChannel != "prerelease" {
			t.Fatalf("auto_update %s: read back %q, channel %q", v, p.AutoUpdate, p.UpdateChannel)
		}
		changed, err = policy.SetAutoUpdate(path, v)
		mustChange(t, changed, err, false)
	}
	changed, err = policy.SetUpdateChannel(path, "stable")
	mustChange(t, changed, err, true)
	if p := load(t, path); p.UpdateChannel != "stable" {
		t.Fatalf("channel %q", p.UpdateChannel)
	}
}

// TestSetUpdateKeys_KeepsTheFile: comments, targets and the order of the keys stay; a key the file
// does not have yet is added.
func TestSetUpdateKeys_KeepsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	in := "# the NAS only\nversion: 1\nallow_targets:\n  - 10.0.0.5:445 # smb\nauto_update: notify # auto | notify | off\n"
	if err := os.WriteFile(path, []byte(in), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := policy.SetUpdateChannel(path, "prerelease")
	mustChange(t, changed, err, true)
	changed, err = policy.SetAutoUpdate(path, "auto")
	mustChange(t, changed, err, true)
	b, _ := os.ReadFile(path)
	for _, want := range []string{"# the NAS only", "# smb", "auto_update: auto # auto | notify | off", "update_channel: prerelease"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("lost %q:\n%s", want, b)
		}
	}
	if strings.Index(string(b), "allow_targets") > strings.Index(string(b), "auto_update") {
		t.Errorf("keys reordered:\n%s", b)
	}
	if p := load(t, path); !allows(p, "10.0.0.5:445") || p.AutoUpdate != "auto" || p.UpdateChannel != "prerelease" {
		t.Fatalf("read back: %+v", p)
	}
}

// TestSetUpdateKeys_Refused: a value outside the allowed ones, a file that does not parse, and a
// file the root updater would not trust are refused, and the file stays as it was.
func TestSetUpdateKeys_Refused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	good := "version: 1\nauto_update: auto\nupdate_channel: stable\n"
	write := func(t *testing.T, data string, mode fs.FileMode) {
		t.Helper()
		_ = os.Remove(path)
		if err := os.WriteFile(path, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil { // past the umask
			t.Fatal(err)
		}
	}
	unchanged := func(t *testing.T, want string) {
		t.Helper()
		if b, err := os.ReadFile(path); err != nil || string(b) != want {
			t.Fatalf("the file changed: %q, %v", b, err)
		}
	}
	refused := func(t *testing.T, changed bool, err error, want string) {
		t.Helper()
		if err == nil || changed || !strings.Contains(err.Error(), want) {
			t.Fatalf("changed %v, %v; want an error with %q", changed, err, want)
		}
	}

	write(t, good, 0o644)
	for _, v := range []string{"", "Off", "never", "auto "} {
		changed, err := policy.SetAutoUpdate(path, v)
		refused(t, changed, err, "want auto, notify, off")
	}
	for _, v := range []string{"", "beta", "Stable"} {
		changed, err := policy.SetUpdateChannel(path, v)
		refused(t, changed, err, "want stable, prerelease")
	}
	unchanged(t, good)

	bad := "version: 1\nauto_update: sometimes\n"
	write(t, bad, 0o644)
	changed, err := policy.SetUpdateChannel(path, "prerelease")
	refused(t, changed, err, "fix the file first")
	unchanged(t, bad)
	notYAML := "version: [1\n"
	write(t, notYAML, 0o644)
	changed, err = policy.SetAutoUpdate(path, "off")
	refused(t, changed, err, "fix the file first")
	unchanged(t, notYAML)

	write(t, good, 0o664)
	changed, err = policy.SetAutoUpdate(path, "off")
	refused(t, changed, err, "chmod go-w")
	unchanged(t, good)
	write(t, good, 0o646)
	changed, err = policy.SetUpdateChannel(path, "prerelease")
	refused(t, changed, err, "chmod go-w")
	unchanged(t, good)

	write(t, good, 0o644)
	t.Run("another owner", func(t *testing.T) {
		policy.SetOwner(t.Cleanup, func(fs.FileInfo) int { return os.Geteuid() + 1 })
		changed, err := policy.SetAutoUpdate(path, "off")
		refused(t, changed, err, "chown it to root")
		unchanged(t, good)
	})

	real := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(real, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	changed, err = policy.SetAutoUpdate(link, "off")
	refused(t, changed, err, "symbolic link")
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatal("the link was replaced")
	}
	if b, _ := os.ReadFile(real); string(b) != good {
		t.Fatalf("the link's target changed: %q", b)
	}

	sub := filepath.Join(dir, "dir.yaml")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	changed, err = policy.SetUpdateChannel(sub, "stable")
	refused(t, changed, err, "no regular file")

	if os.Geteuid() != 0 { // root reads a file of mode 000 all the same
		write(t, good, 0o200)
		changed, err = policy.SetAutoUpdate(path, "off")
		if err == nil || changed {
			t.Fatalf("an unreadable file: changed %v, %v", changed, err)
		}
		_ = os.Chmod(path, 0o644) //nolint:gosec // G302: the mode a policy file has
		unchanged(t, good)
	}
}
