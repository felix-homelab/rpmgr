// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package store

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockFile takes an exclusive, non-blocking flock on path, creating it with mode 0600. The lock is
// released when the returned function runs, or when the process ends, also by SIGKILL.
func lockFile(path string) (func() error, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: next to the operator's database
	if err != nil {
		return nil, fmt.Errorf("store: lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a file descriptor fits in an int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("store: lock %s: %w", path, err)
	}
	return f.Close, nil // closing the file releases the lock
}
