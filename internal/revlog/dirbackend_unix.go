// SPDX-License-Identifier: Apache-2.0

//go:build unix

package revlog

import "syscall"

// openExtra keeps a symlink from being followed and a FIFO from blocking the open.
const openExtra = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
