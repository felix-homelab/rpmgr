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
