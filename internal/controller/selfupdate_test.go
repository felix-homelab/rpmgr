// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/release"
)

// TestHostUpdaterBlocked: the controller names why its host cannot take an update over the air: no
// root updater, a database other than SQLite (no backup method before P2-M08), and a state
// directory the updater's path unit does not watch (D158).
func TestHostUpdaterBlocked(t *testing.T) {
	yes, no := func() bool { return true }, func() bool { return false }
	for name, tc := range map[string]struct {
		state, driver string
		installed     func() bool
		want          string // "" means none
	}{
		"a host that can":      {"/var/lib/rpmgr", "sqlite", yes, ""},
		"no root updater":      {"/var/lib/rpmgr", "sqlite", no, "no root updater"},
		"PostgreSQL":           {"/var/lib/rpmgr", "postgres", yes, "P2-M08"},
		"another state folder": {"/srv/rpmgr", "sqlite", yes, "/var/lib/rpmgr"},
	} {
		got := hostUpdater(tc.state, tc.driver, &release.Mirror{Dir: t.TempDir()}, tc.installed).Blocked()
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: blocked = %q; want %q", name, got, tc.want)
		}
	}
}
