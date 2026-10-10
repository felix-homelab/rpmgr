// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package release

import "github.com/felix-homelab/rpmgr/internal/release/releasetest"

// rootKeys are the test roots of rpmgrtest builds, whose private keys releasetest derives (D60).
var rootKeys = []string{releasetest.Key("root 1").Public(), releasetest.Key("root 2").Public()}

// TestBuild reports whether this is an rpmgrtest build, whose roots are test keys (D60).
const TestBuild = true
