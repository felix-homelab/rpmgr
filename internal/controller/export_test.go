// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"
	"time"
)

// SetRunTimers shortens the drain wait and the certificate reload interval of Run for one test,
// which must not run in parallel with others.
func SetRunTimers(t testing.TB, drain, reload time.Duration) {
	oldDrain, oldReload := drainWait, webCertReload
	drainWait, webCertReload = drain, reload
	t.Cleanup(func() { drainWait, webCertReload = oldDrain, oldReload })
}

// SealedColumns lists the sealed columns `rpmgr kek rotate` re-wraps, as "table.column".
func SealedColumns() []string {
	out := make([]string, len(sealedColumns))
	for i, c := range sealedColumns {
		out[i] = c.table + "." + c.column
	}
	return out
}
