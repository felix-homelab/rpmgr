// SPDX-License-Identifier: Apache-2.0

//go:build unix

package gateway

import "syscall"

// killProcess signals a process; the new process of a hand-off ends a lingering old one with it.
func killProcess(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }
