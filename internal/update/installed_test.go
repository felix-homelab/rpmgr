// SPDX-License-Identifier: Apache-2.0

//go:build linux

package update_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/update"
)

// TestInstalled: the updater counts as installed only where its directory is a directory, also
// one the caller cannot read, and the link that enables its path unit leads to the unit file; a
// missing directory, as in the container image, a file there, or a directory without the enabled
// unit, as the v0.1.0 install script and rpmgr setup --no-unit leave it, is not an updater.
func TestInstalled(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "rpmgr-update")
	unit, wants := filepath.Join(base, "rpmgr-update.path"), filepath.Join(base, "multi-user.target.wants")
	enabled := filepath.Join(wants, "rpmgr-update.path")
	if err := os.WriteFile(unit, nil, 0o644); err != nil { //nolint:gosec // G306: a unit file is world-readable
		t.Fatal(err)
	}
	if err := os.Mkdir(wants, 0o755); err != nil { //nolint:gosec // G301: as systemd's directory
		t.Fatal(err)
	}
	if err := os.Symlink(unit, enabled); err != nil {
		t.Fatal(err)
	}
	if update.InstalledAt(dir, enabled) {
		t.Fatal("a missing directory counts as an installed updater")
	}
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if update.InstalledAt(dir, enabled) {
		t.Fatal("a file counts as an installed updater")
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: the directory's mode again
	if !update.InstalledAt(dir, enabled) {
		t.Fatal("an unreadable updater directory does not count as installed")
	}

	// Without its enabled path unit, nothing would install a staged release.
	if update.InstalledAt(dir, filepath.Join(wants, "missing.path")) {
		t.Fatal("an updater whose path unit is not enabled counts as installed")
	}
	if err := os.Remove(unit); err != nil {
		t.Fatal(err)
	}
	if update.InstalledAt(dir, enabled) {
		t.Fatal("a link to a removed unit file counts as an installed updater")
	}
	if err := os.Mkdir(unit, 0o755); err != nil { //nolint:gosec // G301: only a stand-in for a unit
		t.Fatal(err)
	}
	if update.InstalledAt(dir, enabled) {
		t.Fatal("a link to a directory counts as an installed updater")
	}
}
