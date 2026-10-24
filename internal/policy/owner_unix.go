// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package policy

import (
	"io/fs"
	"syscall"
)

// owner returns the user ID that owns a file; tests replace it.
var owner = func(fi fs.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
