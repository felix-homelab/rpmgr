// SPDX-License-Identifier: Apache-2.0

//go:build unix

package controller

import (
	"os"
	"syscall"
)

func hardLinks(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink > 1
}

func dirOwner(dir string) (uid, gid int, ok bool) {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
