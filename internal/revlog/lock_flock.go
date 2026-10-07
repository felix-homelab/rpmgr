// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package revlog

import (
	"os"
	"syscall"
)

// lock takes an exclusive flock on f, waiting for another process's append to finish.
func lock(f *os.File) (func(), error) {
	fd := int(f.Fd()) //nolint:gosec // G115: a file descriptor fits in an int
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return nil, err
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }, nil
}
