// SPDX-License-Identifier: Apache-2.0

//go:build unix

package secret

import (
	"io/fs"
	"os"
	"syscall"
)

// ownGroup reports whether a file belongs to this process's group, or to root's.
func ownGroup(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return st.Gid == 0 || int(st.Gid) == os.Getegid()
}
