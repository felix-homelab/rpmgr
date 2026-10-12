// SPDX-License-Identifier: Apache-2.0

//go:build unix

package controller

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

// TestOwnLike: as root, ownLike gives the directory and everything below it to the owner of the
// reference, and does not follow a symlink out of it; as another user it changes nothing.
func TestOwnLike(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(dir, "a"), filepath.Join(dir, "sub", "b"), filepath.Join(outside, "c")} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	owner := st.Sys().(*syscall.Stat_t)
	var got []string
	euid, chown := geteuid, lchown
	t.Cleanup(func() { geteuid, lchown = euid, chown })
	lchown = func(_ *os.Root, name string, uid, gid int) error {
		if uid != int(owner.Uid) || gid != int(owner.Gid) {
			t.Errorf("%s to %d:%d, want the reference's %d:%d", name, uid, gid, owner.Uid, owner.Gid)
		}
		got = append(got, name)
		return nil
	}

	geteuid = func() int { return 1000 }
	if err := ownLike(dir, dir); err != nil || len(got) != 0 {
		t.Fatalf("not as root: %v, changed %v", err, got)
	}
	geteuid = func() int { return 0 }
	if err := ownLike(dir, dir); err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if want := []string{".", "a", "link", "sub", "sub/b"}; !slices.Equal(got, want) {
		t.Errorf("changed %v, want %v", got, want)
	}
	if err := ownLike(filepath.Join(dir, "missing"), dir); err == nil {
		t.Error("a missing directory: no error")
	}
}
