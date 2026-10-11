// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package main

import (
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// ClockFileEnv names the file whose duration, such as "90s" or "-2m", the roles of the rpmgrtest
// build add to their clock, for the clock jumps of the chaos tests (docs/12-testing-and-quality.md,
// "End-to-end topology matrix"; D60). The file is read again every clockPoll.
const ClockFileEnv = "RPMGR_TEST_CLOCK_FILE"

const clockPoll = 200 * time.Millisecond

func init() {
	if path := os.Getenv(ClockFileEnv); path != "" {
		clock = offsetClock(path, clockPoll)
	}
}

// offsetClock returns a clock ahead of time.Now by the duration in the file at path, read every
// poll; a missing, empty or unreadable file is no offset.
func offsetClock(path string, poll time.Duration) func() time.Time {
	var offset atomic.Int64
	read := func() {
		b, err := os.ReadFile(path) //nolint:gosec // G304: the test's own file, rpmgrtest builds only
		d, perr := time.ParseDuration(strings.TrimSpace(string(b)))
		if err != nil || perr != nil {
			d = 0
		}
		offset.Store(int64(d))
	}
	read()
	go func() {
		for range time.Tick(poll) {
			read()
		}
	}()
	return func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
}
