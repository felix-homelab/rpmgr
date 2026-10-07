// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package policy

import (
	"os"
	"syscall"
)

// lockPolicy serialises edits of the policy file between processes with a lock file.
func lockPolicy(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: next to the policy file
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { //nolint:gosec // G115: a file descriptor fits in an int
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil // closing releases the lock
}
