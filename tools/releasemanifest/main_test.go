// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
)

var at = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

// releaseDir writes the artifacts of version into a new directory, with the files a release holds
// besides them.
func releaseDir(t *testing.T, version string, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for i, n := range append(names, "SHA256SUMS", "rpmgr-"+version+".spdx.json", "rpmgr-"+version+"-linux-amd64.sigstore.json") {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(strings.Repeat("x", i+1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runDraft(t *testing.T, args ...string) (*release.Manifest, []byte, error) {
	t.Helper()
	var out bytes.Buffer
	if err := draft(args, &out, func() time.Time { return at }); err != nil {
		return nil, nil, err
	}
	var m release.Manifest
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return &m, out.Bytes(), nil
}

func writeFile(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestDraft: the first release gets seq 1 and its own version as the floor; a later one the next
// seq and the previous floor; the channel follows the version; only the artifacts are listed.
func TestDraft(t *testing.T) {
	dir := releaseDir(t, "0.1.0", "rpmgr-0.1.0-linux-amd64", "rpmgr-0.1.0-linux-arm", "rpmgr-0.1.0-linux-arm64-connector")
	first, b, err := runDraft(t, "-version", "0.1.0", "-dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq != 1 || first.Floor != "0.1.0" || first.Channel != release.Stable || !first.IssuedAt.Equal(at) || len(first.Artifacts) != 3 {
		t.Fatalf("first manifest %+v", first)
	}
	if a := first.Artifacts[2]; a.OS != "linux" || a.Arch != "arm64" || a.Variant != "connector" || a.Size != 3 || len(a.SHA256) != 64 {
		t.Errorf("artifact %+v", a)
	}
	if !bytes.HasPrefix(b, []byte(`{"seq":1,"version":"0.1.0","floor":"0.1.0","channel":"stable",`)) || bytes.HasSuffix(b, []byte("\n")) {
		t.Errorf("not compact: %s", b)
	}
	prev := writeFile(t, b)

	dir2 := releaseDir(t, "0.2.0-rc.1", "rpmgr-0.2.0-rc.1-linux-amd64")
	next, _, err := runDraft(t, "-version", "0.2.0-rc.1", "-dir", dir2, "-previous", prev, "-issued", "2026-11-01T08:00:00+01:00")
	if err != nil {
		t.Fatal(err)
	}
	if next.Seq != 2 || next.Floor != "0.1.0" || next.Channel != release.Prerelease || !next.IssuedAt.Equal(time.Date(2026, 11, 1, 7, 0, 0, 0, time.UTC)) {
		t.Errorf("next manifest %+v", next)
	}
	if m, _, err := runDraft(t, "-version", "0.2.0-rc.1", "-dir", dir2, "-previous", prev, "-seq", "9", "-floor", "0.2.0-rc.1"); err != nil ||
		m.Seq != 9 || m.Floor != "0.2.0-rc.1" {
		t.Errorf("explicit seq and floor: %+v %v", m, err)
	}
}

// TestDraftRefusals: no artifact, a misnamed one, a floor above the version, a bad version, a
// broken previous manifest.
func TestDraftRefusals(t *testing.T) {
	dir := releaseDir(t, "1.0.0", "rpmgr-1.0.0-linux-amd64")
	high, _, err := runDraft(t, "-version", "1.0.0", "-dir", dir, "-floor", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(high)
	prev := writeFile(t, b)
	for name, args := range map[string][]string{
		"no artifact":             {"-version", "1.1.0", "-dir", dir},
		"a variant named full":    {"-version", "1.0.0", "-dir", releaseDir(t, "1.0.0", "rpmgr-1.0.0-linux-amd64-full")},
		"an upper-case arch":      {"-version", "1.0.0", "-dir", releaseDir(t, "1.0.0", "rpmgr-1.0.0-linux-AMD64")},
		"a floor above it":        {"-version", "0.9.0", "-dir", releaseDir(t, "0.9.0", "rpmgr-0.9.0-linux-amd64"), "-previous", prev},
		"a leading v":             {"-version", "v1.0.0", "-dir", releaseDir(t, "v1.0.0", "rpmgr-v1.0.0-linux-amd64")},
		"a previous not there":    {"-version", "1.0.0", "-dir", dir, "-previous", filepath.Join(t.TempDir(), "none.json")},
		"a broken previous":       {"-version", "1.0.0", "-dir", dir, "-previous", writeFile(t, []byte(`{"seq":0}`))},
		"no directory":            {"-version", "1.0.0"},
		"an argument":             {"-version", "1.0.0", "-dir", dir, "extra"},
		"a bad issue time":        {"-version", "1.0.0", "-dir", dir, "-issued", "yesterday"},
		"an explicit floor above": {"-version", "1.0.0", "-dir", dir, "-floor", "2.0.0"},
	} {
		if _, _, err := runDraft(t, args...); err == nil {
			t.Errorf("%s: drafted", name)
		}
	}
}

// TestCheck: a draft checks out against its artifacts; a changed, missing or extra artifact, a
// manifest edited out of its compact form, and a seq not above the previous one are refused.
func TestCheck(t *testing.T) {
	dir := releaseDir(t, "1.0.0", "rpmgr-1.0.0-linux-amd64", "rpmgr-1.0.0-linux-riscv64")
	_, b, err := runDraft(t, "-version", "1.0.0", "-dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	manifest := writeFile(t, b)
	var warn bytes.Buffer
	if err := check([]string{"-dir", dir, manifest}, &warn); err != nil {
		t.Fatal(err)
	}
	if err := check([]string{"-dir", dir, writeFile(t, append(b, '\n'))}, &warn); err != nil {
		t.Errorf("with a final newline: %v", err)
	}
	_, older, _ := runDraft(t, "-version", "0.9.0", "-dir", releaseDir(t, "0.9.0", "rpmgr-0.9.0-linux-amd64"), "-seq", "4")
	if err := check([]string{"-dir", dir, "-previous", writeFile(t, older), manifest}, &warn); err == nil {
		t.Error("seq 1 after seq 4")
	}
	_, lower, _ := runDraft(t, "-version", "1.0.0", "-dir", dir, "-seq", "5", "-floor", "0.8.0")
	if err := check([]string{"-dir", dir, "-previous", writeFile(t, older), writeFile(t, lower)}, &warn); err != nil ||
		!strings.Contains(warn.String(), "lowered from 0.9.0 to 0.8.0") {
		t.Errorf("a lowered floor: %v %q", err, warn.String())
	}

	spaced := bytes.Replace(b, []byte(`"seq":1,`), []byte(`"seq": 1,`), 1)
	if err := check([]string{"-dir", dir, writeFile(t, spaced)}, &warn); err == nil {
		t.Error("a manifest with spaces")
	}
	changed := releaseDir(t, "1.0.0", "rpmgr-1.0.0-linux-amd64", "rpmgr-1.0.0-linux-riscv64")
	if err := os.WriteFile(filepath.Join(changed, "rpmgr-1.0.0-linux-riscv64"), []byte("yy"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]string{
		"a changed artifact": changed,
		"a missing artifact": releaseDir(t, "1.0.0", "rpmgr-1.0.0-linux-amd64"),
		"an extra artifact":  releaseDir(t, "1.0.0", "rpmgr-1.0.0-linux-amd64", "rpmgr-1.0.0-linux-riscv64", "rpmgr-1.0.0-linux-arm"),
	} {
		if err := check([]string{"-dir", d, manifest}, &warn); err == nil {
			t.Errorf("%s: checked out", name)
		}
	}
	if err := check([]string{manifest}, &warn); err == nil {
		t.Error("no directory")
	}
}
