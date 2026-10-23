// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"io/fs"
	"time"
)

// SetEvery shortens the watcher's interval, for tests.
func (w *Watcher) SetEvery(d time.Duration) { w.every = d }

// SetOwner replaces how the edits read a file's owner, until the test ends.
func SetOwner(cleanup func(func()), f func(fs.FileInfo) int) {
	old := owner
	owner = f
	cleanup(func() { owner = old })
}
