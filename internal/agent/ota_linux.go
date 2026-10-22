// SPDX-License-Identifier: Apache-2.0

package agent

import "golang.org/x/sys/unix"

// freeSpace returns the bytes an unprivileged user may still write on dir's filesystem.
func freeSpace(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil //nolint:gosec // G115: the block size is positive
}
