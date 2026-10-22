// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
)

func run(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := cli.Main(context.Background(), commands(), args, &cli.Env{
		Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" },
	})
	return code, out.String(), errOut.String()
}

// TestRoleCommandsAbsent: the controller, the gateway and the all-in-one are not in the
// connector-only build; calling one says so and exits 2, as 16 has it for a command of another
// build. Setup and the systemd unit offer the connector only, besides the updater's units.
func TestRoleCommandsAbsent(t *testing.T) {
	for _, role := range []string{"controller", "gateway", "all-in-one"} {
		code, _, errOut := run(role)
		if code != cli.ExitUsage || !strings.Contains(errOut, "not available in this build") {
			t.Errorf("rpmgr %s: %d %q", role, code, errOut)
		}
		code, _, errOut = run("setup", "--yes", "--role", role, "--public-url", "https://panel.example.com")
		if code != cli.ExitUsage || !strings.Contains(errOut, "not available in this build") {
			t.Errorf("rpmgr setup --role %s: %d %q", role, code, errOut)
		}
		if code, _, _ := run("systemd-unit", role); code != cli.ExitUsage {
			t.Errorf("rpmgr systemd-unit %s: %d", role, code)
		}
	}
	if code, _, errOut := run("setup", "--yes"); code != cli.ExitUsage || !strings.Contains(errOut, "--role: connector") {
		t.Errorf("setup --yes without a role names the roles of this build: %d %q", code, errOut)
	}
	if code, out, _ := run("version", "--verbose"); code != 0 || !strings.Contains(out, "\nvariant: connector\n") {
		t.Errorf("rpmgr version --verbose names the variant: %d %q", code, out)
	}
	if code, out, _ := run("systemd-unit", "connector"); code != 0 || !strings.Contains(out, "ExecStart=/usr/local/bin/rpmgr connector") {
		t.Errorf("rpmgr systemd-unit connector: %d %q", code, out)
	}
	// The root updater replaces this build too (docs/02-architecture.md, "Roles").
	if code, out, _ := run("systemd-unit", "--bin", "/usr/local/bin/rpmgr", "update"); code != 0 ||
		!strings.Contains(out, "ExecStart=/usr/local/bin/rpmgr updater apply") {
		t.Errorf("rpmgr systemd-unit update: %d %q", code, out)
	}
	for _, c := range []string{"apply", "install"} {
		if code, _, errOut := run("updater", c, "--help"); code != 0 {
			t.Errorf("rpmgr updater %s --help: %d %q", c, code, errOut)
		}
	}
	// The resource commands of the public API, the controller's administration and the importer
	// are not in the tree at all.
	for _, c := range []string{"login", "get", "backup", "release", "import", "ca"} {
		if code, _, _ := run(c); code != cli.ExitUsage {
			t.Errorf("rpmgr %s: %d, want an unknown command", c, code)
		}
	}
}

// serverPackage matches what the connector-only build must not link: the controller, the
// gateway, the importer, the store and everything that keeps state in it (D119).
var serverPackage = regexp.MustCompile(`^github\.com/felix-homelab/rpmgr/internal/(` +
	`accounts|acme|allinone|api|apicli|apisvc|audit|authz|controller|dns|domains|egress|enroll|gateway|importer|itest|lease|` +
	`mail|manifest|pki/castore|revlog|routes|settings|setup/serversetup|snapshot|store|testseed|webui|websession)(/|$)`)

// TestNoServerCode: the build links none of the server packages, and no database driver or ACME
// client.
func TestNoServerCode(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain on PATH: %v", err)
	}
	out, err := exec.Command(gobin, "list", "-deps", ".").Output() //nolint:gosec // G204: the toolchain on a fixed package
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	deps := strings.Fields(string(out))
	for _, p := range deps {
		if serverPackage.MatchString(p) || strings.HasPrefix(p, "modernc.org/sqlite") || strings.HasPrefix(p, "github.com/jackc/pgx") ||
			strings.HasPrefix(p, "entgo.io/") || strings.HasPrefix(p, "github.com/caddyserver/certmagic") ||
			strings.HasPrefix(p, "connectrpc.com/") {
			t.Errorf("links %s", p)
		}
	}
	for _, want := range []string{"github.com/felix-homelab/rpmgr/internal/connector", "github.com/felix-homelab/rpmgr/internal/setup"} {
		if !strings.Contains(" "+string(out)+" ", "\n"+want+"\n") && !strings.Contains(string(out), want+"\n") {
			t.Errorf("does not link %s: the test reads the wrong package", want)
		}
	}
}
