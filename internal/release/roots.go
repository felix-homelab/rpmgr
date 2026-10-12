// SPDX-License-Identifier: Apache-2.0

//go:build !rpmgrtest

package release

// rootKeys are the release root keys compiled into release builds, as minisign public keys: the
// interim keys of Phase 1 (D48, RELEASING.md, "Interim signing keys"). Either one signs a
// signing-key statement.
var rootKeys = []string{
	"RWQHGtnjCdWFdPvZeuywSw5/cVCITz37J5OJpW8a6b3o1IrSSH3WUJ+/", // root 1, key ID 7485D509E3D91A07
	"RWTVWJoC8Y/G5IVKcNOsIcd8gTy0nJ6IgiOGgljo7tK8OcUjnwz8BnDM", // root 2, key ID E4C68FF1029A58D5
}

// TestBuild reports whether this is an rpmgrtest build, whose roots are test keys (D60).
const TestBuild = false
