// SPDX-License-Identifier: Apache-2.0

//go:build unix

package revlog_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// TestDirBackendHostileFiles (finding S3): a symlink, a FIFO, a directory and an oversized file
// in the sink are refused and do not hang or exhaust memory.
func TestDirBackendHostileFiles(t *testing.T) {
	dir := t.TempDir()
	d := revlog.DirBackend{Dir: dir}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, revlog.Key(1))); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, revlog.Key(2)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, revlog.Key(3)), 0o750); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, revlog.Key(4))
	if err := os.WriteFile(big, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, revlog.MaxObject+1); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, revlog.Key(5)), make([]byte, revlog.MaxObject), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for n := uint64(1); n <= 4; n++ {
			if _, err := d.Get(revlog.Key(n)); err == nil {
				t.Errorf("key %d: a hostile file was read", n)
			}
		}
		if _, err := d.Get(revlog.Key(4)); !errors.Is(err, revlog.ErrBroken) {
			t.Errorf("an oversized file: %v, want ErrBroken", err)
		}
		if b, err := d.Get(revlog.Key(5)); err != nil || len(b) != revlog.MaxObject {
			t.Errorf("a file of exactly the limit: %d bytes, %v", len(b), err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Get hangs on a FIFO")
	}
}
