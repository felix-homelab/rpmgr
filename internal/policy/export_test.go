// SPDX-License-Identifier: Apache-2.0

package policy

import "time"

// SetEvery shortens the watcher's interval, for tests.
func (w *Watcher) SetEvery(d time.Duration) { w.every = d }
