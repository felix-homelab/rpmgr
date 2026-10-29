// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package connector

import (
	"os"
	"time"
)

// ReprobeEnv names a duration, such as "15s", that the rpmgrtest build uses instead of the
// 10 min after which a connector on TCP tries QUIC again, so that the hand-off test sees a
// connector come back to QUIC (docs/12-testing-and-quality.md; D60).
const ReprobeEnv = "RPMGR_TEST_REPROBE"

func init() {
	if d, err := time.ParseDuration(os.Getenv(ReprobeEnv)); err == nil && d > 0 {
		reprobeEvery = d
	}
}
