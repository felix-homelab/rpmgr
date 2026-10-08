// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package controller

// hostMemory does not know the host's memory outside Linux, where the controller runs.
func hostMemory() (uint64, bool) { return 0, false }
