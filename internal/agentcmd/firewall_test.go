// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
)

func runFirewall(t *testing.T, root bool, args ...string) (int, string, string) {
	t.Helper()
	old := isRoot
	t.Cleanup(func() { isRoot = old })
	isRoot = func() bool { return root }
	var out, errOut bytes.Buffer
	tree := &cli.Command{Name: "rpmgr", Sub: []*cli.Command{Firewall()}}
	code := cli.Main(context.Background(), tree, append([]string{"firewall", "apply"}, args...), &cli.Env{
		Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }})
	return code, out.String(), errOut.String()
}

// TestFirewallApplyRefusesNonRootAndArguments: the helper runs only as root and takes no
// arguments; as root with no bounds file it is switched off, which needs no ufw to say so.
func TestFirewallApplyRefusesNonRootAndArguments(t *testing.T) {
	dir := t.TempDir()
	flags := []string{"--desired", filepath.Join(dir, "d.json"), "--bounds", filepath.Join(dir, "b.json"), "--status", filepath.Join(dir, "s.json")}
	if code, _, errOut := runFirewall(t, false, flags...); code == 0 || !strings.Contains(errOut, "as root") {
		t.Errorf("as a user: %d %q", code, errOut)
	}
	if code, _, _ := runFirewall(t, true, append(flags, "extra")...); code != cli.ExitUsage {
		t.Errorf("with an argument: %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "s.json")); err == nil {
		t.Error("a refused run wrote a status")
	}
}

func runFirewallInstall(t *testing.T, root bool, args ...string) (int, string, string) {
	t.Helper()
	old := isRoot
	t.Cleanup(func() { isRoot = old })
	isRoot = func() bool { return root }
	var out, errOut bytes.Buffer
	tree := &cli.Command{Name: "rpmgr", Sub: []*cli.Command{Firewall()}}
	code := cli.Main(context.Background(), tree, append([]string{"firewall", "install"}, args...), &cli.Env{
		Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }})
	return code, out.String(), errOut.String()
}

// TestFirewallInstall (D152): `rpmgr firewall install` is what the install script runs: as root
// only, with no argument, for a gateway or an all-in-one whose boot file names ufw; it writes the
// bounds from the boot file, the directory and the units.
func TestFirewallInstall(t *testing.T) {
	f := fakeSetup(t)
	setupHost.HasUfw = func() bool { return false }
	etc, lib, units := filepath.Join(f.root, "etc"), filepath.Join(f.root, "lib"), filepath.Join(f.root, "units")
	flags := []string{"--etc", etc, "--lib", lib, "--units", units, "--bin", filepath.Join(f.root, "rpmgr")}
	if code, _, errOut := runFirewallInstall(t, false, flags...); code == 0 || !strings.Contains(errOut, "as root") {
		t.Errorf("as a user: %d %q", code, errOut)
	}
	if code, _, _ := runFirewallInstall(t, true, append(flags, "extra")...); code != cli.ExitUsage {
		t.Errorf("with an argument: %d", code)
	}
	if code, _, errOut := runFirewallInstall(t, true, flags...); code == 0 || errOut == "" {
		t.Errorf("without a boot file: %d %q", code, errOut)
	}
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "gateway.yaml"), []byte("version: 1\ncontroller: {endpoints: [https://panel.example.com]}\n"+
		"firewall: {backend: ufw}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runFirewallInstall(t, true, append([]string{"--role", "connector"}, flags...)...); code == 0 || !strings.Contains(errOut, "no firewall to hand") {
		t.Errorf("a connector: %d %q", code, errOut)
	}
	code, out, errOut := runFirewallInstall(t, true, flags...)
	if code != 0 || !strings.Contains(out, "firewall.json") || !strings.Contains(errOut, "ufw is not installed") {
		t.Fatalf("install: %d %q %q", code, out, errOut)
	}
	for _, p := range []string{filepath.Join(etc, "firewall.json"), filepath.Join(lib, "firewall"), filepath.Join(units, "rpmgr-firewall.path"),
		filepath.Join(units, "rpmgr-firewall.service")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%v", err)
		}
	}
	if len(f.commands) != 0 { // the script enables the units, as it does the updater's
		t.Errorf("commands %q", f.commands)
	}
	if err := os.Remove(filepath.Join(units, "rpmgr-firewall.path")); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runFirewallInstall(t, true, append([]string{"--no-units"}, flags...)...); code != 0 {
		t.Errorf("--no-units: %d", code)
	}
	if _, err := os.Stat(filepath.Join(units, "rpmgr-firewall.path")); err == nil {
		t.Error("--no-units wrote a unit")
	}
}
