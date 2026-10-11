// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestOffsetClock: the clock follows the file's duration forwards and backwards, and a missing or
// malformed file is no offset.
func TestOffsetClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock")
	now := offsetClock(path, 10*time.Millisecond)
	near := func(want time.Duration) bool {
		for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
			if d := time.Until(now()) - want; d > -time.Second && d < time.Second {
				return true
			}
		}
		return false
	}
	if !near(0) {
		t.Error("a missing file shifts the clock")
	}
	for _, c := range []struct {
		text string
		want time.Duration
	}{{"90m\n", 90 * time.Minute}, {"-2h", -2 * time.Hour}, {"not a duration", 0}, {"", 0}} {
		if err := os.WriteFile(path, []byte(c.text), 0o600); err != nil {
			t.Fatal(err)
		}
		if !near(c.want) {
			t.Errorf("%q: the clock is %s ahead", c.text, time.Until(now()))
		}
	}
}
