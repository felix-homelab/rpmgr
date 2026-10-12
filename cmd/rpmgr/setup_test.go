// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/setup"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// setupFakes replaces the host of `rpmgr setup` with a temporary root: systemctl, systemd-creds,
// the enrollment and the readiness check are recorded, not run.
type setupFakes struct {
	root     string
	commands []string
	enrolled []agent.EnrollOptions
	enroll   error // what the enrollment returns
}

func fakeSetup(t *testing.T) *setupFakes {
	t.Helper()
	f := &setupFakes{root: t.TempDir()}
	bin := filepath.Join(f.root, "rpmgr")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // G306: a fake binary
		t.Fatal(err)
	}
	old, oldConfirm := setupHost, setupConfirm
	t.Cleanup(func() { setupHost, setupConfirm = old, oldConfirm })
	setupConfirm = func(io.Writer, *setup.Plan) error { return errors.New("setup: not confirmed; nothing was changed") }
	setupHost = setup.Host{
		Paths: setup.Paths{Etc: filepath.Join(f.root, "etc"), Lib: filepath.Join(f.root, "lib"), Units: filepath.Join(f.root, "units"), Bin: bin},
		Run: func(_ context.Context, name string, args ...string) error {
			f.commands = append(f.commands, name+" "+strings.Join(args, " "))
			return nil
		},
		UserExists: func() bool { return true }, GiveTo: func(string) error { return nil }, IsRoot: func() bool { return true },
		SystemdVersion: func() int { return 255 }, PortFree: func(string) bool { return true },
		Ready: func(context.Context, string) error { return nil },
		Encrypt: func(_ context.Context, _, path string, b []byte) error {
			return os.WriteFile(path, b, 0o600) // stands in for systemd-creds encrypt
		},
		Enroll: func(_ context.Context, o agent.EnrollOptions) (agent.Identity, error) {
			f.enrolled = append(f.enrolled, o)
			if f.enroll != nil {
				return agent.Identity{}, f.enroll
			}
			return agent.Identity{AgentID: "con_01TEST", Kind: "connector"}, os.MkdirAll(o.IdentityDir, 0o700)
		},
		Getenv: func(string) string { return "" },
	}
	return f
}

// TestSetup_Connector (docs/16-cli.md): `rpmgr setup` takes every value as a flag and the token
// from $RPMGR_ENROLL_TOKEN, never the command line; it runs the plan with --yes, asks otherwise,
// and changes nothing when the operator declines.
func TestSetup_Connector(t *testing.T) {
	f := fakeSetup(t)
	tok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"RPMGR_ENROLL_TOKEN": tok}
	args := []string{"setup", "--role", "connector", "--controller", "https://panel.example.com",
		"--ca-pin", "sha256:" + strings.Repeat("A", 43) + "=", "--allow-target", "10.0.0.5:8080"}

	if code, _, errOut := runWith(env, "", "setup"); code != cli.ExitUsage || !strings.Contains(errOut, "--role") {
		t.Errorf("without a role: %d %q", code, errOut)
	}
	if code, _, errOut := runWith(env, "", args...); code != cli.ExitError || !strings.Contains(errOut, "not confirmed") || len(f.enrolled) != 0 {
		t.Fatalf("declined: %d %q, enrolled %d", code, errOut, len(f.enrolled))
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a declined plan created %s: %v", filepath.Join(f.root, "etc"), err)
	}

	code, out, errOut := runWith(env, "", append(args, "--yes")...)
	if code != cli.ExitOK || len(f.enrolled) != 1 || f.enrolled[0].Token != tok || strings.Contains(out+errOut, tok) ||
		!strings.Contains(out, "enrolled as connector con_01TEST") || !strings.Contains(out, "rpmgr policy allow-target") {
		t.Fatalf("setup: %d %q %q, enrolled %+v", code, out, errOut, f.enrolled)
	}
	if !strings.Contains(strings.Join(f.commands, "\n"), "enable --now rpmgr-connector") {
		t.Errorf("commands %q", f.commands)
	}
	if code, _, errOut := runWith(env, "", append(args, "--yes")...); code != cli.ExitError || !strings.Contains(errOut, "--force") {
		t.Errorf("a second setup: %d %q", code, errOut)
	}
}

// TestSetup_AllInOne: an all-in-one is initialised end to end with its KEK in a systemd
// credential and Let's Encrypt staging, and setup shows the trust domain, the CA pin and the
// first-user link, with the next step.
func TestSetup_AllInOne(t *testing.T) {
	f := fakeSetup(t)
	code, out, errOut := runWith(nil, "", "setup", "--role", "all-in-one", "--public-url", "https://panel.example.com",
		"--acme-directory", "staging", "--acme-email", "ops@example.com", "--listen-admin", "127.0.0.1:17381", "--yes")
	if code != cli.ExitOK {
		t.Fatalf("setup: %d %q %q", code, out, errOut)
	}
	for _, want := range []string{"→ set the instance's ACME directory", "runs as rpmgr-all-in-one", "trust domain: ", "CA pin:       sha256:",
		"https://panel.example.com/setup#", "rpmgr setup --role connector --controller https://panel.example.com --ca-pin sha256:"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	unit, err := os.ReadFile(filepath.Join(f.root, "units", "rpmgr-all-in-one.service"))
	if err != nil || !strings.Contains(string(unit), "LoadCredentialEncrypted=rpmgr-kek") {
		t.Errorf("unit %q %v", unit, err)
	}
	if !strings.Contains(strings.Join(f.commands, "\n"), "enable --now rpmgr-all-in-one") {
		t.Errorf("commands %q", f.commands)
	}
}

// TestSetup_Refuses: wrong flags are usage errors before anything happens, and a failure names
// what setup had created, never the token.
func TestSetup_Refuses(t *testing.T) {
	f := fakeSetup(t)
	pin := "sha256:" + strings.Repeat("A", 43) + "="
	if code, _, errOut := runWith(nil, "", "setup", "--role", "controller", "--public-url", "https://panel.example.com",
		"--token-file", "/nonexistent"); code != cli.ExitUsage || !strings.Contains(errOut, "--token-file") {
		t.Errorf("a token file for a controller: %d %q", code, errOut)
	}
	if code, _, errOut := runWith(nil, "", "setup", "--role", "router", "--yes"); code == cli.ExitOK || !strings.Contains(errOut, "no role") {
		t.Errorf("an unknown role: %d %q", code, errOut)
	}
	if code, _, errOut := runWith(nil, "", "setup", "--role", "controller", "extra"); code != cli.ExitUsage {
		t.Errorf("an argument: %d %q", code, errOut)
	}

	f.enroll = errors.New("token used up")
	tok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runWith(map[string]string{"RPMGR_ENROLL_TOKEN": tok}, "", "setup", "--role", "gateway",
		"--controller", "https://panel.example.com", "--ca-pin", pin, "--yes")
	if code != cli.ExitError || !strings.Contains(errOut, "token used up") || !strings.Contains(errOut, "It had created: "+filepath.Join(f.root, "etc")) ||
		strings.Contains(errOut, tok) {
		t.Errorf("a failed enrollment: %d %q", code, errOut)
	}
}
