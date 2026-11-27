// SPDX-License-Identifier: Apache-2.0

//go:build unix

package secret_test

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

// TestReadFile_FIFODoesNotHang: a named pipe where a secret file should be is refused at once;
// opening it for reading would wait for a writer for ever.
func TestReadFile_FIFODoesNotHang(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("no FIFOs here:", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := secret.ReadFile(p, "database password file", false, 4096)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("ReadFile of a FIFO: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFile of a FIFO hangs")
	}
}
