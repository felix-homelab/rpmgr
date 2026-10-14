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
	for _, target := range []string{"192.168.10.0:8050", "192.168.10.0/24:8050"} {
		if _, err := policy.RemoveTarget(path, target); !errors.Is(err, policy.ErrInRange) {
			t.Fatalf("%s, inside the subnet's port range: %v", target, err)
		}
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
	for _, target := range []string{"host.example:80", "10.0.0.1:0", "10.0.0.1:65536", "run/app.sock", "/run/../app.sock", "",
		"[fe80::1%eth0]:80", "10.0.0.1:500-200", "10.0.0.1:", "10.0.0.1:80-", "10.0.0.0/33", "fd00::1:80", "[fd00::1", "[fd00::1]80",
		"[fd00::1]:", "10.0.0.1:http"} {
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

// TestEdit_SubnetsRangesAndDeny (D84): the editing commands take subnets, which are normalised,
// port ranges and targets without a port; a covered target is not added twice; deny-target writes
// deny_targets, which then wins; a target inside a broader entry is not removed but named.
func TestEdit_SubnetsRangesAndDeny(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	steps := []struct {
		do      func(path, target string) (bool, error)
		target  string
		changed bool
	}{
		{policy.AllowTarget, "10.0.0.1/16", true},
		{policy.AllowTarget, "10.0.7.7:22", false}, // inside 10.0.0.0/16, all ports
		{policy.AllowTarget, "127.0.0.1:200-500", true},
		{policy.AllowTarget, "127.0.0.1:300-400", false},
		{policy.AllowTarget, "127.0.0.1:600", true}, // to the same entry
		{policy.AllowTarget, "[fd00::/64]:8000-8099", true},
		{policy.DenyTarget, "127.0.0.1:345", true},
		{policy.DenyTarget, "127.0.0.1:345", false},
		{policy.DenyTarget, "/run/app.sock", true},
		{policy.DenyTarget, "10.0.9.0/24", true},
	}
	for _, s := range steps {
		changed, err := s.do(path, s.target)
		if err != nil || changed != s.changed {
			t.Fatalf("%s: changed %v, %v; want %v", s.target, changed, err, s.changed)
		}
	}
	b, _ := os.ReadFile(path)
	for _, want := range []string{"cidr: 10.0.0.0/16}", "cidr: 127.0.0.1/32, ports: [200-500, 600]}", "deny_targets:"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the file lacks %q:\n%s", want, b)
		}
	}
	p := load(t, path)
	for target, want := range map[string]bool{"10.0.200.1:443": true, "10.0.9.1:443": false, "127.0.0.1:344": true,
		"127.0.0.1:345": false, "127.0.0.1:600": true, "[fd00::1]:8000": true} {
		if allows(p, target) != want {
			t.Errorf("%s: allowed %v, want %v", target, !want, want)
		}
	}
	if _, err := policy.RemoveTarget(path, "10.0.7.7:22"); !errors.Is(err, policy.ErrInRange) {
		t.Fatalf("a target inside a subnet entry: %v", err)
	}
	if _, err := policy.RemoveTarget(path, "127.0.0.1:250"); !errors.Is(err, policy.ErrInRange) {
		t.Fatalf("a port inside a range: %v", err)
	}
	changed, err := policy.RemoveTarget(path, "127.0.0.1:200-500")
	mustChange(t, changed, err, true)
	changed, err = policy.RemoveDenyTarget(path, "127.0.0.1:345")
	mustChange(t, changed, err, true)
	changed, err = policy.AllowTarget(path, "127.0.0.1") // all ports: the entry loses its ports
	mustChange(t, changed, err, true)
	changed, err = policy.RemoveTarget(path, "10.0.0.0/16") // all ports: the whole entry
	mustChange(t, changed, err, true)
	p = load(t, path)
	if !allows(p, "127.0.0.1:1") || allows(p, "10.0.200.1:443") || p.AllowsUnix("/run/app.sock") {
		t.Fatalf("after the removals:\n%s", p.Describe())
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), "200-500") || strings.Contains(string(b), "345") {
		t.Fatalf("removed entries stayed:\n%s", b)
	}
	// Into a file without deny_targets the key is added; a protected address a broad entry does not
	// let through is still added for allow_targets.
	old := filepath.Join(t.TempDir(), "old.yaml")
	if err := os.WriteFile(old, []byte("version: 1\nallow_targets: [0.0.0.0/0]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err = policy.AllowTarget(old, "169.254.169.254:80")
	mustChange(t, changed, err, true)
	changed, err = policy.DenyTarget(old, "192.0.2.1")
	mustChange(t, changed, err, true)
	p = load(t, old)
	if !allows(p, "169.254.169.254:80") || allows(p, "192.0.2.1:1") || !allows(p, "192.0.2.2:1") {
		t.Fatalf("the old file:\n%s", p.Describe())
	}
}

// TestEdit_DuplicateKey: a file whose entry gives a key twice is invalid and not edited, so that an
// edit never reads the first value while the connector would read another.
func TestEdit_DuplicateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	orig := "version: 1\nallow_targets: [{cidr: 10.0.0.0/8, ports: [80], cidr: 192.168.0.0/16}]\n"
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.AllowTarget(path, "10.0.0.0/8:443"); err == nil {
		t.Fatal("a file with a duplicate key was edited")
	}
	if b, _ := os.ReadFile(path); string(b) != orig {
		t.Fatalf("the file changed:\n%s", b)
	}
}
