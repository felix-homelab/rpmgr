// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/policy"
)

func load(t *testing.T, path string) *policy.Policy {
	t.Helper()
	p, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustChange(t *testing.T, changed bool, err error, want bool) {
	t.Helper()
	if err != nil || changed != want {
		t.Fatalf("changed %v, %v; want changed %v", changed, err, want)
	}
}

func TestAllowAndRemoveTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	changed, err := policy.AllowTarget(path, "10.0.0.5:5432")
	mustChange(t, changed, err, true)
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "auto_update: auto") || !strings.Contains(string(b), "update_channel: stable") {
		t.Fatalf("a new file without explicit update keys:\n%s", b)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
	if !allows(load(t, path), "10.0.0.5:5432") || allows(load(t, path), "10.0.0.5:5433") {
		t.Fatal("not exactly the target was allowed")
	}
	changed, err = policy.AllowTarget(path, "10.0.0.5:5432")
	mustChange(t, changed, err, false)
	changed, err = policy.AllowTarget(path, "10.0.0.5:6432")
	mustChange(t, changed, err, true)
	changed, err = policy.AllowTarget(path, "[::1]:22")
	mustChange(t, changed, err, true)
	changed, err = policy.AllowTarget(path, "/run/app/app.sock")
	mustChange(t, changed, err, true)
	changed, err = policy.AllowTarget(path, "[::ffff:10.0.0.6]:80")
	mustChange(t, changed, err, true)
	p := load(t, path)
	for _, target := range []string{"10.0.0.5:5432", "10.0.0.5:6432", "[::1]:22", "10.0.0.6:80"} {
		if !allows(p, target) {
			t.Errorf("%s not allowed", target)
		}
	}
	if !p.AllowsUnix("/run/app/app.sock") {
		t.Error("the socket is not allowed")
	}

	changed, err = policy.RemoveTarget(path, "10.0.0.5:5432")
	mustChange(t, changed, err, true)
	changed, err = policy.RemoveTarget(path, "10.0.0.5:6432")
	mustChange(t, changed, err, true)
	changed, err = policy.RemoveTarget(path, "/run/app/app.sock")
	mustChange(t, changed, err, true)
	changed, err = policy.RemoveTarget(path, "10.9.9.9:1")
	mustChange(t, changed, err, false)
	p = load(t, path)
	if allows(p, "10.0.0.5:5432") || allows(p, "10.0.0.5:6432") || p.AllowsUnix("/run/app/app.sock") || !allows(p, "[::1]:22") {
		t.Fatal("not exactly the targets were removed")
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "10.0.0.5") {
		t.Fatalf("an entry without ports stayed:\n%s", b)
	}
}

// TestEdit_KeepsTheFile: an edit keeps comments and the other keys; a port that only a range
// allows is not split; a file that does not parse is not touched.
func TestEdit_KeepsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	orig := `# managed by hand
version: 1
allow_targets:
  - cidr: 192.168.10.0/24   # the lab
    ports: [80, "8000-8099"]
auto_update: notify
update_channel: prerelease
`
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := policy.AllowTarget(path, "192.168.10.7:9000")
	mustChange(t, changed, err, true)
	b, _ := os.ReadFile(path)
	for _, keep := range []string{"# managed by hand", "# the lab", "auto_update: notify", "update_channel: prerelease", "8000-8099"} {
		if !strings.Contains(string(b), keep) {
			t.Errorf("the edit lost %q:\n%s", keep, b)
		}
	}
	if _, err := policy.RemoveTarget(path, "192.168.10.0:8050"); err != nil {
		t.Fatalf("an address the CIDR entry does not name exactly: %v", err)
	}
	if _, err := policy.RemoveTarget(path, "192.168.10.0/24:8050"); err == nil {
		t.Fatal("a CIDR as a target was accepted")
	}

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\nallow_targets: nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.AllowTarget(bad, "10.0.0.1:80"); err == nil {
		t.Fatal("an invalid file was edited")
	}
	if b, _ := os.ReadFile(bad); string(b) != "version: 1\nallow_targets: nope\n" {
		t.Fatal("an invalid file was changed")
	}
}

func TestEdit_RangeAndBadTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nallow_targets: [{cidr: 10.0.0.1/32, ports: [\"80-90\"]}]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.RemoveTarget(path, "10.0.0.1:85"); !errors.Is(err, policy.ErrInRange) {
		t.Fatalf("a port inside a range: %v", err)
	}
	changed, err := policy.AllowTarget(path, "10.0.0.1:85")
	mustChange(t, changed, err, false) // already allowed by the range
	for _, target := range []string{"10.0.0.1", "host.example:80", "10.0.0.1:0", "10.0.0.1:65536", "run/app.sock",
		"/run/../app.sock", "", "[fe80::1%eth0]:80"} {
		if _, err := policy.AllowTarget(path, target); err == nil {
			t.Errorf("%q accepted", target)
		}
	}
}

// TestEdit_Concurrent: edits from several processes at once, serialised by the lock file, lose
// nothing.
func TestEdit_Concurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			if _, err := policy.AllowTarget(path, fmt.Sprintf("10.0.0.%d:80", i+1)); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	p := load(t, path)
	for i := range 20 {
		if !allows(p, fmt.Sprintf("10.0.0.%d:80", i+1)) {
			t.Errorf("10.0.0.%d:80 lost", i+1)
		}
	}
}
