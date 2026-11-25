// SPDX-License-Identifier: Apache-2.0

//go:build unix

package controller_test

import (
	"os"
	"syscall"
)

func sameOwner(a, b os.FileInfo) bool {
	x, ok1 := a.Sys().(*syscall.Stat_t)
	y, ok2 := b.Sys().(*syscall.Stat_t)
	return ok1 && ok2 && x.Uid == y.Uid && x.Gid == y.Gid
}
