// SPDX-License-Identifier: Apache-2.0

//go:build !rpmgrtest

package main

import (
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
)

// TestNoTestCommands: a build without the rpmgrtest tag, as every release is, has no test-only
// command (D60).
func TestNoTestCommands(t *testing.T) {
	walk(commands(), nil, func(c *cli.Command, path []string) {
		if c.Name == "testseed" {
			t.Errorf("rpmgr %s exists without the rpmgrtest tag", strings.Join(path, " "))
		}
	})
	if len(testCommands) != 0 {
		t.Errorf("%d test commands", len(testCommands))
	}
}
