// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package agent

import "errors"

// freeSpace is not needed off Linux: OTA covers Linux hosts with systemd only, so agents elsewhere
// never announce the capability ota.
func freeSpace(string) (uint64, error) { return 0, errors.ErrUnsupported }
