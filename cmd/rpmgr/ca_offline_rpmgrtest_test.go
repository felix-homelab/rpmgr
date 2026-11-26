// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/controller"
)

// A ceremony that fails after the marker was logged keeps the file and shows the generated
// passphrase, which exists nowhere else; `ca status` warns about the marker.
func TestCAOfflineRootFailureShowsPassphrase(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "controller.yaml")
	boot := "version: 1\npublic_url: https://panel.example.com\ndatabase: {dsn: " + filepath.Join(dir, "controller.db") +
		"}\nkek: {source: file, path: " + filepath.Join(dir, "kek") + "}\n"
	if err := os.WriteFile(cfg, []byte(boot), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runRpmgr("controller", "init", "--config", cfg); code != cli.ExitOK {
		t.Fatalf("init: %q", stderr)
	}
	controller.CeremonyFault = func(stage, _ string) error {
		if stage == "commit" {
			return errors.New("injected")
		}
		return nil
	}
	t.Cleanup(func() { controller.CeremonyFault = nil })
	out := filepath.Join(dir, "root.age")
	code, _, stderr := runRpmgr("ca", "offline-root", "--out", out, "--config", cfg)
	if code != cli.ExitError || !regexp.MustCompile(`\n  [A-Z2-7]{4}(-[A-Z2-7]{1,4})+\n`).MatchString(stderr) ||
		!strings.Contains(stderr, "kept") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("the file is gone: %v", err)
	}
	controller.CeremonyFault = nil
	if code, stdout, _ := runRpmgr("ca", "status", "--config", cfg); code != cli.ExitOK || !strings.Contains(stdout, "key is still in the database") {
		t.Errorf("status: %d %q", code, stdout)
	}
}
