// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"path/filepath"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/release"
)

// StagedDir is the directory the root updater's path unit watches, where an agent stages a
// release and the controller stages its own (docs/04-security.md, "Over-the-air updates").
const StagedDir = "/var/lib/rpmgr/update"

// hostUpdater is the controller's way to update its own host over the air (D158): it stages a
// release of its mirror for the root updater and says why that cannot be done on this host. The
// updater's own checks decide; the reasons here only keep the Instance Admin from starting what
// would be refused.
func hostUpdater(stateDir, driver string, mirror *release.Mirror, installed func() bool) *apisvc.SelfUpdate {
	return &apisvc.SelfUpdate{
		Blocked: func() string {
			switch {
			case !installed():
				return "this host has no root updater: install.sh --upgrade --restart or rpmgr setup installs it"
			case driver != "sqlite":
				return "the controller runs on " + driver + ", and the update needs a backup it can restore; only SQLite has one until the " +
					"PostgreSQL backup method (P2-M08) exists. Update it by hand"
			case stateDir != filepath.Dir(StagedDir):
				return "the state directory is " + stateDir + ", not " + filepath.Dir(StagedDir) + ", which the root updater watches"
			}
			return ""
		},
		Stage: func(ctx context.Context, version string) error {
			return agent.StageRelease(ctx, agent.UpdateOptions{Dir: StagedDir, Variant: "full"},
				release.Dir(filepath.Join(mirror.Dir, version)), version)
		},
	}
}
