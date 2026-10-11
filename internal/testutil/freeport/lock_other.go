// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package freeport

// lock locks nothing where there is no flock: only one process's ports are kept apart there.
func lock(int) (unlock func(), ok bool) { return func() {}, true }
