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
// one the caller cannot read; a missing directory, as in the container image, or a file there is
// not an updater.
func TestInstalled(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "rpmgr-update")
	if update.InstalledAt(dir) {
		t.Fatal("a missing directory counts as an installed updater")
	}
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if update.InstalledAt(dir) {
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
	if !update.InstalledAt(dir) {
		t.Fatal("an unreadable updater directory does not count as installed")
	}
}
