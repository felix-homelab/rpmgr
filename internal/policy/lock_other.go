// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package policy

import "errors"

// lockPolicy is not available yet: Windows and macOS connectors come in Phase 2.
func lockPolicy(string) (func(), error) {
	return nil, errors.New("policy: editing the policy needs Linux or macOS")
}
