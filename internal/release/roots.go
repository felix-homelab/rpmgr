// SPDX-License-Identifier: Apache-2.0

//go:build !rpmgrtest

package release

// rootKeys are the release root keys compiled into release builds, as minisign public keys. The
// interim keys of Phase 1 are added before v0.1.0, when the maintainer has made them offline
// (D48, RELEASING.md, "Roles"); until then a build verifies no release.
var rootKeys = []string{}

// TestBuild reports whether this is an rpmgrtest build, whose roots are test keys (D60).
const TestBuild = false
