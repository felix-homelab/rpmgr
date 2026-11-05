// SPDX-License-Identifier: Apache-2.0

package policy

import "fmt"

// UpdateRefusal says whether a host whose policy has the given auto_update and update_channel
// refuses to take an offered release (docs/04-security.md, "Over-the-air updates"), as the agent
// and the root updater decide it: auto_update notify or off, and a pre-release on the stable
// channel. It returns the reason, for the operator, and the command that makes the host take the
// release, to run there as root; both are empty when the host takes it. Values the policy file
// never yields are not judged: the host is left to decide.
func UpdateRefusal(autoUpdate, channel string, prerelease bool) (reason, command string) {
	switch {
	case autoUpdate == AutoUpdateOff || autoUpdate == AutoUpdateNotify:
		return fmt.Sprintf("the host's local policy sets auto_update: %s", autoUpdate), "sudo rpmgr policy set-auto-update auto"
	case autoUpdate == AutoUpdateAuto && channel == ChannelStable && prerelease:
		return "the release is a pre-release and the host's update_channel is stable", "sudo rpmgr policy set-update-channel prerelease"
	}
	return "", ""
}
