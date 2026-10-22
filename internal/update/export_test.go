// SPDX-License-Identifier: Apache-2.0

//go:build linux

package update

import (
	"errors"
	"testing"
)

// OnOpen runs f after each staged file is opened, until the test ends.
func OnOpen(t testing.TB, f func(name string)) {
	t.Helper()
	afterOpen = f
	t.Cleanup(func() { afterOpen = nil })
}

// AfterCopy runs f after the artifact is copied and before the copy is verified, until the test
// ends.
func AfterCopy(t testing.TB, f func()) {
	t.Helper()
	afterCopy = f
	t.Cleanup(func() { afterCopy = nil })
}

// BeforeSwap runs f after the new binary is written beside the installed one and before it is
// synced and checked, until the test ends.
func BeforeSwap(t testing.TB, f func(path string)) {
	t.Helper()
	beforeSwap = f
	t.Cleanup(func() { beforeSwap = nil })
}

// AfterRename runs f right after the new binary was renamed over the installed one; the run ends
// there, as a crash would, when f returns false. Until the test ends.
func AfterRename(t testing.TB, f func() bool) {
	t.Helper()
	afterRename = f
	t.Cleanup(func() { afterRename = nil })
}

// SyncDirFails makes syncing dir fail, until the test ends.
func SyncDirFails(t testing.TB, dir string) {
	t.Helper()
	syncDirHook = func(d string) error {
		if d == dir {
			return errors.New("sync failed (test)")
		}
		return nil
	}
	t.Cleanup(func() { syncDirHook = nil })
}

// ErrInterrupted is what Apply returns when AfterRename ends the run.
var ErrInterrupted = errInterrupted

// InstalledAt is exported for the test of Installed.
var InstalledAt = installedAt
