// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package agent

import "sync/atomic"

var rootsFaultHook atomic.Pointer[func(point string) error]

// SetRootsFault makes the write of roots.pem fail with the error h returns for a point
// ("before-rename", "after-rename"), as a crash would; nil removes the hook. Only rpmgrtest builds
// have it.
func SetRootsFault(h func(point string) error) {
	if h == nil {
		rootsFaultHook.Store(nil)
		return
	}
	rootsFaultHook.Store(&h)
}

func rootsFault(point string) error {
	if h := rootsFaultHook.Load(); h != nil {
		return (*h)(point)
	}
	return nil
}
