// SPDX-License-Identifier: Apache-2.0

package controller

import "syscall"

// hostMemory returns the host's total memory in bytes.
func hostMemory() (uint64, bool) {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return 0, false
	}
	return uint64(info.Totalram) * uint64(info.Unit), true // Totalram is a uint32 on 32-bit platforms
}
