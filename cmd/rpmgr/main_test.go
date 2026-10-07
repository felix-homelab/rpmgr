// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
)

func runRpmgr(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := cli.Main(context.Background(), commands(), args, &cli.Env{
		Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" },
	})
	return code, out.String(), errOut.String()
}

// walk calls fn for every command of the tree with its path.
func walk(c *cli.Command, path []string, fn func(*cli.Command, []string)) {
	fn(c, path)
	for _, s := range c.Sub {
		walk(s, append(append([]string(nil), path...), s.Name), fn)
	}
}

func TestEveryCommandHasHelp(t *testing.T) {
	walk(commands(), nil, func(c *cli.Command, path []string) {
		if c.Summary == "" {
			t.Errorf("rpmgr %s: no summary", strings.Join(path, " "))
		}
		if strings.HasSuffix(c.Summary, ".") || strings.ToLower(c.Summary[:1]) != c.Summary[:1] {
			t.Errorf("rpmgr %s: summary %q must start lower-case and have no period", strings.Join(path, " "), c.Summary)
		}
		seen := map[string]bool{}
		for _, s := range c.Sub {
			if seen[s.Name] {
				t.Errorf("rpmgr %s: duplicate sub-command %q", strings.Join(path, " "), s.Name)
			}
			seen[s.Name] = true
		}
		code, stdout, stderr := runRpmgr(append(path, "--help")...)
		if code != cli.ExitOK || !strings.HasPrefix(stdout, "Usage: rpmgr") {
			t.Errorf("rpmgr %s --help: exit %d, stdout %q, stderr %q", strings.Join(path, " "), code, stdout, stderr)
		}
	})
}

func TestUnimplementedCommandsReportIt(t *testing.T) {
	for _, args := range [][]string{
		{"controller"}, {"controller", "--config", "/tmp/c.yaml"}, {"all-in-one", "init"},
		{"gateway"}, {"connector"}, {"all-in-one"}, {"enroll"}, {"policy", "show"}, {"ca", "status"},
	} {
		code, _, stderr := runRpmgr(args...)
		if code != cli.ExitUsage || !strings.Contains(stderr, "not available in this build") {
			t.Errorf("rpmgr %s: exit %d, stderr %q; want exit 2, not available", strings.Join(args, " "), code, stderr)
		}
	}
}

// TestControllerInit runs `rpmgr controller init` against a boot file in a temporary directory.
// The initialisation itself is tested in internal/controller.
func TestControllerInit(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "controller.yaml")
	boot := "version: 1\npublic_url: https://panel.example.com\n" +
		"database: {dsn: " + filepath.Join(dir, "controller.db") + "}\n" +
		"kek: {source: file, path: " + filepath.Join(dir, "kek") + "}\n"
	if err := os.WriteFile(cfg, []byte(boot), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runRpmgr("controller", "init", "--config", cfg)
	if code != cli.ExitOK || !strings.Contains(stdout, "trust domain: rpmgr-") || !strings.Contains(stdout, "CA pin:       sha256:") {
		t.Fatalf("first init: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, _, stderr = runRpmgr("controller", "init", "--config", cfg, "--public-url", "https://other.example.com")
	if code != cli.ExitError || !strings.Contains(stderr, "public_url") {
		t.Errorf("init with another public URL: exit %d, stderr %q", code, stderr)
	}
	code, _, stderr = runRpmgr("controller", "init", "--config", cfg)
	if code != cli.ExitError || !strings.Contains(stderr, "already initialised") {
		t.Errorf("second init: exit %d, stderr %q", code, stderr)
	}
	code, _, stderr = runRpmgr("controller", "init", "--config", filepath.Join(dir, "missing.yaml"))
	if code != cli.ExitError || !strings.Contains(stderr, "--public-url is needed") {
		t.Errorf("init without boot file or URL: exit %d, stderr %q", code, stderr)
	}
}

func TestCommandLineErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,                          // no command
		{"bogus"},                    // unknown command
		{"ca"},                       // group without command
		{"ca", "bogus"},              // unknown sub-command
		{"gateway", "--bogus"},       // unknown flag
		{"gateway", "--config"},      // flag without value
		{"version", "extra"},         // unexpected argument
		{"controller", "positional"}, // a role takes no arguments
	} {
		code, stdout, stderr := runRpmgr(args...)
		if code != cli.ExitUsage || stdout != "" || !strings.Contains(stderr, "Usage:") {
			t.Errorf("rpmgr %q: exit %d, stdout %q, stderr %q; want exit 2 with usage on stderr", args, code, stdout, stderr)
		}
	}
}

func TestVersion(t *testing.T) {
	code, stdout, stderr := runRpmgr("version")
	if code != cli.ExitOK || !strings.HasPrefix(stdout, "rpmgr dev (commit ") || stderr != "" {
		t.Errorf("rpmgr version: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// TestVersionFromLinkerFlags builds the binary the way release builds set the version.
func TestVersionFromLinkerFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	// go test puts its own go command first in PATH.
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go tool not found: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "rpmgr")
	const pkg = "github.com/felix-homelab/rpmgr/internal/version"
	build := exec.Command(goTool, "build", "-trimpath", "-o", bin,
		"-ldflags", "-X "+pkg+".Version=1.4.2 -X "+pkg+".Commit=3f2a9c1", ".")
	build.Env = append(build.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatalf("rpmgr version: %v", err)
	}
	want := "rpmgr 1.4.2 (commit 3f2a9c1, " + runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH + ")\n"
	if string(out) != want {
		t.Errorf("rpmgr version = %q, want %q", out, want)
	}
	var exitErr *exec.ExitError
	if err := exec.Command(bin).Run(); !errors.As(err, &exitErr) || exitErr.ExitCode() != cli.ExitUsage {
		t.Errorf("rpmgr without a command: %v, want exit code %d", err, cli.ExitUsage)
	}
}
