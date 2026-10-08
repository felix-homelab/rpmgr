// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"testing"
	"time"
)

// SetRetireAfter shortens how long a retired session keeps its streams, for one test that must
// not run in parallel with others.
func SetRetireAfter(t testing.TB, d time.Duration) {
	old := retireAfter
	retireAfter = d
	t.Cleanup(func() { retireAfter = old })
}
