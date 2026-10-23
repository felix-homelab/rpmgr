// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package policy

import (
	"io/fs"
	"os"
)

// owner has no user ID to read here; editing the policy needs Linux or macOS (lockPolicy).
var owner = func(fs.FileInfo) int { return os.Geteuid() }
