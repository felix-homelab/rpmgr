// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
)

// runRpmgr runs a command tree of this package's commands, as cmd/rpmgr registers them.
func runRpmgr(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	tree := &cli.Command{Name: "rpmgr", Sub: []*cli.Command{Connector(), Enroll(), Leave(), Status(), Diag(), Policy(), Version("full")}}
	code := cli.Main(context.Background(), tree, args, &cli.Env{
		Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" },
	})
	return code, out.String(), errOut.String()
}

// serverPackage matches the packages of the controller, the gateway, the importer and the store,
// which the connector-only build must not link (docs/02-architecture.md, "Roles"; D119).
var serverPackage = regexp.MustCompile(`^github\.com/felix-homelab/rpmgr/internal/(` +
	`accounts|acme|allinone|api|apisvc|audit|authz|controller|domains|enroll|gateway|importer|itest|lease|mail|` +
	`manifest|pki/castore|revlog|routes|settings|setup/serversetup|snapshot|store|testseed|websession|webui)(/|$)`)

// linkedNow are the server packages this package still links, each with why; the slice that
// removes the reason removes its entry. The test fails when an entry is no longer linked, so the
// list only shrinks. It is empty since the agent-side parts of internal/pki and of the snapshots
// left the database (internal/pki/castore, internal/snapsig).
var linkedNow = map[string]string{}

// TestNoServerPackages: the commands of a connector or gateway host link nothing of the
// controller, the gateway or the importer, so that the connector-only build can register them.
func TestNoServerPackages(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain on PATH: %v", err)
	}
	out, err := exec.Command(gobin, "list", "-deps", ".").Output() //nolint:gosec // G204: the toolchain on a fixed package
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	linked := map[string]bool{}
	for _, p := range strings.Fields(string(out)) {
		m := serverPackage.FindStringSubmatch(p)
		if m == nil {
			continue
		}
		if _, ok := linkedNow[m[1]]; !ok {
			t.Errorf("links %s, a server package", p)
		}
		linked[m[1]] = true
	}
	for name := range linkedNow {
		if !linked[name] {
			t.Errorf("no longer links %s: remove it from linkedNow", name)
		}
	}
	if !slices.Contains(strings.Fields(string(out)), "github.com/felix-homelab/rpmgr/internal/connector") {
		t.Error("go list did not list the connector role: the test reads the wrong package")
	}
}

// TestSystemdUnit_Roles: systemd-unit prints the unit of one of its roles and refuses another;
// the connector-only build gives it the connector only.
func TestSystemdUnit_Roles(t *testing.T) {
	run := func(c *cli.Command, args ...string) (int, string) {
		var out, errOut bytes.Buffer
		tree := &cli.Command{Name: "rpmgr", Sub: []*cli.Command{c}}
		code := cli.Main(context.Background(), tree, args, &cli.Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }})
		return code, out.String() + errOut.String()
	}
	if code, out := run(SystemdUnit("connector"), "systemd-unit", "connector"); code != 0 || !strings.Contains(out, "rpmgr connector") {
		t.Errorf("the connector's unit: %d %q", code, out)
	}
	for _, role := range []string{"gateway", "controller", "all-in-one", "relay"} {
		if code, out := run(SystemdUnit("connector"), "systemd-unit", role); code != cli.ExitUsage || !strings.Contains(out, "no role") {
			t.Errorf("%s from a connector-only systemd-unit: %d %q", role, code, out)
		}
	}
	if code, out := run(SystemdUnit(), "systemd-unit", "gateway"); code != 0 || !strings.Contains(out, "rpmgr gateway") {
		t.Errorf("every role by default: %d %q", code, out)
	}
}
