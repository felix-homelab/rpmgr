// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
)

// asUser runs the test as the given effective user and records reloads.
func asUser(t *testing.T, uid int) *int {
	t.Helper()
	reloads := 0
	oldUID, oldReload := geteuid, reloadConnector
	geteuid = func() int { return uid }
	reloadConnector = func(context.Context) error { reloads++; return errors.New("no systemd here") }
	t.Cleanup(func() { geteuid, reloadConnector = oldUID, oldReload })
	return &reloads
}

func TestPolicyCommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	reloads := asUser(t, 0)

	code, out, _ := runRpmgr("policy", "show", "--file", path)
	if code != 0 || !strings.Contains(out, "no file, the defaults apply") || !strings.Contains(out, "allowed targets: none") ||
		!strings.Contains(out, "auto_update: auto") {
		t.Fatalf("show without a file: %d %q", code, out)
	}
	code, out, errOut := runRpmgr("policy", "allow-target", "--file", path, "10.0.0.5:5432")
	if code != 0 || !strings.Contains(out, "updated") || !strings.Contains(errOut, "could not reload") || *reloads != 1 {
		t.Fatalf("allow-target: %d %q %q, %d reloads", code, out, errOut, *reloads)
	}
	code, out, _ = runRpmgr("policy", "allow-target", "--file", path, "--no-reload", "10.0.0.5:5432")
	if code != 0 || !strings.Contains(out, "nothing to change") || *reloads != 1 {
		t.Fatalf("the same target again: %d %q, %d reloads", code, out, *reloads)
	}
	code, out, _ = runRpmgr("policy", "show", "--file", path)
	if code != 0 || !strings.Contains(out, "10.0.0.5/32 ports 5432") {
		t.Fatalf("show: %d %q", code, out)
	}
	if code, _, errOut := runRpmgr("policy", "allow-target", "--file", path, "host.example:80"); code != cli.ExitError ||
		!strings.Contains(errOut, "not an IP address") {
		t.Fatalf("a host name: %d %q", code, errOut)
	}
	if code, _, _ := runRpmgr("policy", "allow-target", "--file", path); code != cli.ExitUsage {
		t.Fatalf("no target: %d", code)
	}
	code, out, _ = runRpmgr("policy", "remove-target", "--file", path, "--no-reload", "10.0.0.5:5432")
	if code != 0 || !strings.Contains(out, "updated") {
		t.Fatalf("remove-target: %d %q", code, out)
	}

	if err := os.WriteFile(path, []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runRpmgr("policy", "show", "--file", path); code != cli.ExitError || !strings.Contains(out, "invalid, nothing is allowed") {
		t.Fatalf("show with an invalid file: %d %q", code, out)
	}
}

// TestPolicyCommands_NotRoot: only root edits the policy; anyone may show it.
func TestPolicyCommands_NotRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	asUser(t, 1000)
	for _, cmd := range []string{"allow-target", "remove-target"} {
		code, _, errOut := runRpmgr("policy", cmd, "--file", path, "10.0.0.5:5432")
		if code != cli.ExitError || !strings.Contains(errOut, "run this as root") {
			t.Errorf("%s as a user: %d %q", cmd, code, errOut)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a user created the policy file")
	}
	if code, _, _ := runRpmgr("policy", "show", "--file", path); code != 0 {
		t.Fatalf("show as a user: %d", code)
	}
}
