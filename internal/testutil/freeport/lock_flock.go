// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package freeport

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// lock takes an exclusive flock on a file named after port in a directory every test binary of
// the run shares, and reports false while another process holds it. The kernel releases the lock
// when the process ends, so a crashed test binary leaves no port blocked. Without the directory
// or the file, the port goes unlocked, as before.
func lock(port int) (unlock func(), ok bool) {
	none := func() {}
	dir := filepath.Join(os.TempDir(), "rpmgr-freeport")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return none, true
	}
	f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(port)), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: a port number in a directory of our own
	if err != nil {
		return none, true
	}
	fd := int(f.Fd()) //nolint:gosec // G115: a file descriptor fits an int
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false
		}
		return none, true
	}
	// The file stays: removed while another process has it open, a third process would create and
	// lock a new file of the same name.
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, true
}
