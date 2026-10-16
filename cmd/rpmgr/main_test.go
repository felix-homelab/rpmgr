// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/itest"
	"github.com/felix-homelab/rpmgr/internal/release"
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

// TestEveryCommandIsAvailable: with Phase 1's commands built, no command of the tree answers "not
// available in this build" any more (docs/16-cli.md).
func TestEveryCommandIsAvailable(t *testing.T) {
	notAvailable := reflect.ValueOf(cli.NotAvailable).Pointer()
	walk(commands(), nil, func(c *cli.Command, path []string) {
		if c.Run != nil && reflect.ValueOf(c.Run).Pointer() == notAvailable {
			t.Errorf("rpmgr %s is not available", strings.Join(path, " "))
		}
	})
}

// TestSystemdUnit: the unit of an agent role needs no boot file; a controller's or all-in-one's
// takes the KEK credential and the revocation-log sink from its boot file, and needs one.
func TestSystemdUnit(t *testing.T) {
	code, stdout, stderr := runRpmgr("systemd-unit", "--bin", "/usr/bin/rpmgr", "connector")
	if code != cli.ExitOK || !strings.Contains(stdout, "ExecStart=/usr/bin/rpmgr connector --config /etc/rpmgr/connector.yaml\n") {
		t.Errorf("connector: exit %d, %q, %q", code, stdout, stderr)
	}
	boot := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(boot, []byte("version: 1\npublic_url: https://panel.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = runRpmgr("systemd-unit", "--config", boot, "controller")
	if code != cli.ExitOK || !strings.Contains(stdout, "LoadCredentialEncrypted=rpmgr-kek:/etc/rpmgr/credstore/rpmgr-kek\n") ||
		strings.Contains(stdout, "ReadWritePaths=") {
		t.Errorf("controller with a credential KEK and no sink: exit %d, %q", code, stdout)
	}
	code, _, stderr = runRpmgr("systemd-unit", "--config", filepath.Join(t.TempDir(), "none.yaml"), "controller")
	if code != cli.ExitError || !strings.Contains(stderr, "init") {
		t.Errorf("controller without a boot file: exit %d, %q", code, stderr)
	}
	// The revocation-log sink of the boot file is writable for the controller and the all-in-one.
	for _, role := range []string{"controller", "all-in-one"} {
		boot := filepath.Join(t.TempDir(), role+".yaml")
		if err := os.WriteFile(boot, []byte("version: 1\npublic_url: https://panel.example.com\nkek: {source: file, path: /etc/rpmgr/kek}\n"+
			"revocation_log: {sink: /mnt/rpmgr-revocations/}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr = runRpmgr("systemd-unit", "--config", boot, role)
		if code != cli.ExitOK || !strings.Contains(stdout, "\nReadWritePaths=-/mnt/rpmgr-revocations\n") || strings.Contains(stdout, "LoadCredential") {
			t.Errorf("%s with a sink and a KEK file: exit %d, %q, %q", role, code, stdout, stderr)
		}
	}
	// A sink systemd would read differently gives no unit at all, rather than one that cannot write it.
	if err := os.WriteFile(boot, []byte("version: 1\npublic_url: https://panel.example.com\nrevocation_log: {sink: /mnt/my share}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runRpmgr("systemd-unit", "--config", boot, "controller")
	if code != cli.ExitError || stdout != "" || !strings.Contains(stderr, `"/mnt/my share"`) {
		t.Errorf("controller with a sink holding a space: exit %d, %q, %q", code, stdout, stderr)
	}
}

// TestReleaseImport: `rpmgr release import` reads the controller's boot file; a development
// build imports nothing; the import itself is tested in internal/controller. --config may follow
// the directory, and after "--" a directory may begin with "-".
func TestReleaseImport(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.yaml")
	for name, args := range map[string][]string{
		"flags first":                {"--config", missing, t.TempDir()},
		"flags last":                 {t.TempDir(), "--config", missing},
		"a directory that is a flag": {"--config", missing, "--", "-release"},
	} {
		code, _, stderr := runRpmgr(append([]string{"release", "import"}, args...)...)
		if code != cli.ExitError || !strings.Contains(stderr, "none.yaml") {
			t.Errorf("%s, a missing boot file: exit %d, %q", name, code, stderr)
		}
	}
	code, _, stderr := runRpmgr("release", "import", "--config", missing, "-release")
	if code != cli.ExitUsage || !strings.Contains(stderr, "flag provided but not defined: -release") {
		t.Errorf("a directory that is a flag, without --: exit %d, %q", code, stderr)
	}
}

// TestFlagsAfterArguments (docs/16-cli.md): flags may follow the positional arguments, so --help
// after a kind or a name prints the command's help.
func TestFlagsAfterArguments(t *testing.T) {
	for _, args := range [][]string{
		{"get", "install-command", "--help"},
		{"get", "route", "web", "-h"},
		{"update", "route", "wiki", "--policy", "office", "--help"},
		{"delete", "route", "--help"},
		{"systemd-unit", "connector", "--help"},
	} {
		code, stdout, stderr := runRpmgr(args...)
		if want := "Usage: rpmgr " + args[0] + " "; code != cli.ExitOK || !strings.HasPrefix(stdout, want) || stderr != "" {
			t.Errorf("rpmgr %q: exit %d, stdout %q, stderr %q; want the help", args, code, stdout, stderr)
		}
	}
	code, stdout, stderr := runRpmgr("systemd-unit", "connector", "--bin", "/usr/bin/rpmgr")
	if code != cli.ExitOK || !strings.Contains(stdout, "ExecStart=/usr/bin/rpmgr connector ") {
		t.Errorf("a flag after the role: exit %d, %q, %q", code, stdout, stderr)
	}
}

// TestInitHelp: the help of both init commands gives the default KEK source as init chooses it:
// the systemd credential from the first systemd version with encrypted credentials, else a file.
func TestInitHelp(t *testing.T) {
	first := 0
	for controller.KEKSourceFor(first) != config.KEKSystemdCredential {
		first++
	}
	want := fmt.Sprintf("(default systemd-credential from systemd %d, else file)", first)
	for _, role := range []string{"controller", "all-in-one"} {
		code, stdout, _ := runRpmgr(role, "init", "--help")
		if code != cli.ExitOK || !strings.Contains(stdout, want) || strings.Contains(stdout, "systemd-credential (default)") {
			t.Errorf("rpmgr %s init --help: exit %d, %q; want %q", role, code, stdout, want)
		}
	}
}

// TestRestore: `rpmgr restore` reads the controller's boot file; the restore itself is tested in
// internal/controller.
func TestRestore(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.yaml")
	code, _, stderr := runRpmgr("restore", "--in", "x.backup", "--revocation-log", "a", "--revocation-log", "b", "--config", missing)
	if code != cli.ExitError || !strings.Contains(stderr, "none.yaml") {
		t.Errorf("a missing boot file: exit %d, %q", code, stderr)
	}
	if code, _, stderr := runRpmgr("restore", "confirm", "--org", "acme", "--config", missing); code != cli.ExitError || !strings.Contains(stderr, "none.yaml") {
		t.Errorf("restore confirm with a missing boot file: exit %d, %q", code, stderr)
	}
}

// TestController: the role commands read their boot file from --config, else $RPMGR_CONFIG, and
// stop with the boot file's problem; running is tested in their packages and internal/itest.
func TestController(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.yaml")
	for _, role := range []string{"controller", "gateway", "connector", "all-in-one"} {
		code, _, stderr := runRpmgr(role, "--config", missing)
		if code != cli.ExitError || !strings.Contains(stderr, missing) {
			t.Fatalf("%s with a missing boot file: exit %d, stderr %q", role, code, stderr)
		}
	}
	agent := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(agent, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"gateway", "connector"} {
		code, _, stderr := runRpmgr(role, "--config", agent)
		if code != cli.ExitError || !strings.Contains(stderr, "controller.endpoints") {
			t.Fatalf("%s without controller endpoints: exit %d, stderr %q", role, code, stderr)
		}
	}
	var code int
	var stderr string
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var errOut bytes.Buffer
	code = cli.Main(context.Background(), commands(), []string{"controller"}, &cli.Env{Stdout: &bytes.Buffer{}, Stderr: &errOut,
		Getenv: func(k string) string { return map[string]string{"RPMGR_CONFIG": bad}[k] }})
	stderr = errOut.String()
	if code != cli.ExitError || !strings.Contains(stderr, "public_url") {
		t.Fatalf("a boot file without public_url: exit %d, stderr %q", code, stderr)
	}
}

// TestAgentCommands runs status, diag and leave against a connector enrolled with a test
// controller; they are tested in internal/itest.
func TestAgentCommands(t *testing.T) {
	c := itest.StartController(t, itest.Options{})
	dir := t.TempDir()
	l := c.EnrollConnector(t, filepath.Join(dir, "identity"))
	cfg := filepath.Join(dir, "connector.yaml")
	boot := fmt.Sprintf("version: 1\ncontroller: {endpoints: [%q]}\nidentity_dir: %s\nstate_dir: %s\nlisten: {admin: 127.0.0.1:1}\n",
		c.URL, l.Dir, dir)
	if err := os.WriteFile(cfg, []byte(boot), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"status"}, cli.ExitOK, "connector (boot file " + cfg + ")"},
		{[]string{"status"}, cli.ExitOK, "none received yet"},
		{[]string{"status"}, cli.ExitOK, "not running"},
		{[]string{"diag", "clock"}, cli.ExitOK, "ahead of this host's"},
		{[]string{"diag", "transport"}, cli.ExitError, "no configuration from the controller yet"},
		{[]string{"leave"}, cli.ExitOK, "The controller revoked " + l.SPIFFE()},
		{[]string{"status"}, cli.ExitError, "rpmgr enroll"},
		{[]string{"leave"}, cli.ExitError, "agent.json"},
	} {
		code, stdout, stderr := runRpmgr(append(tc.args, "--config", cfg)...)
		if code != tc.code || !strings.Contains(stdout+stderr, tc.want) {
			t.Errorf("rpmgr %s: exit %d, no %q in %q %q", strings.Join(tc.args, " "), code, tc.want, stdout, stderr)
		}
	}
	if code, _, stderr := runRpmgr("status", "--config", filepath.Join(dir, "none.yaml")); code != cli.ExitError || !strings.Contains(stderr, "none.yaml") {
		t.Errorf("a missing boot file: exit %d, %q", code, stderr)
	}
}

// TestLocalAdmin runs the local administration commands against an initialised controller; they
// are tested in internal/controller.
func TestLocalAdmin(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "controller.yaml")
	boot := "version: 1\npublic_url: https://panel.example.com\n" +
		"database: {dsn: " + filepath.Join(dir, "controller.db") + "}\n" +
		"kek: {source: file, path: " + filepath.Join(dir, "kek") + "}\n"
	if err := os.WriteFile(cfg, []byte(boot), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runRpmgr("controller", "init", "--config", cfg); code != cli.ExitOK {
		t.Fatalf("init: %q", stderr)
	}
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"ca", "status"}, []string{"Trust domain: rpmgr-", "Root pin:     sha256:", "root ", "intermediate ", "config-signing ", "active"}},
		{[]string{"ca", "rotate-intermediate"}, []string{"The new issuing intermediate", "retired"}},
		{[]string{"kek", "status"}, []string{"The boot file's KEK: version ", "(the boot file's)"}},
		{[]string{"migrate"}, []string{"The database is up to date."}},
	} {
		code, stdout, stderr := runRpmgr(append(tc.args, "--config", cfg)...)
		for _, w := range tc.want {
			if code != cli.ExitOK || !strings.Contains(stdout, w) {
				t.Errorf("rpmgr %s: exit %d, no %q in %q (stderr %q)", strings.Join(tc.args, " "), code, w, stdout, stderr)
			}
		}
	}
	missing := filepath.Join(t.TempDir(), "none.yaml")
	for _, args := range [][]string{{"ca", "status"}, {"kek", "status"}, {"migrate"}, {"kek", "rotate", "--previous-file", "x"}} {
		if code, _, stderr := runRpmgr(append(args, "--config", missing)...); code != cli.ExitError || !strings.Contains(stderr, "none.yaml") {
			t.Errorf("rpmgr %s without a boot file: exit %d, %q", strings.Join(args, " "), code, stderr)
		}
	}
}

// TestControllerBootDefault (docs/16-cli.md): without --config and $RPMGR_CONFIG, the commands of
// the controller host read /etc/rpmgr/controller.yaml, else, on an all-in-one host,
// /etc/rpmgr/all-in-one.yaml. The test's boot files are not valid, so each command names the one
// it read.
func TestControllerBootDefault(t *testing.T) {
	commands := [][]string{{"backup", "--out", filepath.Join(t.TempDir(), "b")}, {"restore", "--in", filepath.Join(t.TempDir(), "b")},
		{"restore", "confirm"}, {"user", "reset-password"}, {"migrate"}, {"ca", "status"}, {"ca", "rotate-intermediate"},
		{"kek", "status"}, {"kek", "rotate", "--previous-file", filepath.Join(t.TempDir(), "k")}}
	t.Cleanup(func() { bootDir = "/etc/rpmgr" })
	for _, tc := range []struct {
		present []string
		want    string
	}{
		{[]string{"all-in-one.yaml"}, "all-in-one.yaml"},
		{[]string{"controller.yaml", "all-in-one.yaml"}, "controller.yaml"},
		{nil, "controller.yaml"},
	} {
		bootDir = t.TempDir()
		for _, f := range tc.present {
			if err := os.WriteFile(filepath.Join(bootDir, f), []byte("version: 99\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want := filepath.Join(bootDir, tc.want)
		for _, args := range commands {
			if code, _, stderr := runRpmgr(args...); code != cli.ExitError || !strings.Contains(stderr, want) {
				t.Errorf("rpmgr %s with %v: exit %d, %q; want %s read", strings.Join(args, " "), tc.present, code, stderr, want)
			}
		}
	}
	if got := controllerBoot("", func(k string) string { return map[string]string{"RPMGR_CONFIG": "/srv/aio.yaml"}[k] }); got != "/srv/aio.yaml" {
		t.Errorf("with $RPMGR_CONFIG: %s", got)
	}
	if got := controllerBoot("/srv/c.yaml", func(string) string { return "/srv/aio.yaml" }); got != "/srv/c.yaml" {
		t.Errorf("with --config: %s", got)
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
	if code != cli.ExitOK || !strings.Contains(stdout, "trust domain: rpmgr-") || !strings.Contains(stdout, "CA pin:       sha256:") ||
		!strings.Contains(stdout, "https://panel.example.com/setup#rpmgr_prs_") {
		t.Fatalf("first init: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	// Before the first user exists, reset-password makes another first-user link; an e-mail
	// address of nobody is refused.
	code, stdout, stderr = runRpmgr("user", "reset-password", "--config", cfg)
	if code != cli.ExitOK || !strings.Contains(stdout, "https://panel.example.com/setup#rpmgr_prs_") || !strings.Contains(stdout, "first user") {
		t.Errorf("reset-password before the first user: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, _, stderr = runRpmgr("user", "reset-password", "--config", cfg, "--email", "nobody@example.com")
	if code != cli.ExitError || !strings.Contains(stderr, "no user nobody@example.com") {
		t.Errorf("reset-password for nobody: exit %d, stderr %q", code, stderr)
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

// TestEnrollCommand: the token never comes from the command line, the controller and the pin are
// required, and a malformed token or pin fails before any connection.
func TestEnrollCommand(t *testing.T) {
	for _, name := range []string{"token", "t", "enrollment-token"} {
		if code, _, _ := runRpmgr("enroll", "--"+name, "x"); code != cli.ExitUsage {
			t.Errorf("rpmgr enroll --%s: exit %d; a token on the command line must be refused", name, code)
		}
	}
	if code, _, stderr := runRpmgr("enroll", "--controller", "https://p.example"); code != cli.ExitUsage || !strings.Contains(stderr, "--ca-pin") {
		t.Errorf("without --ca-pin: exit %d, %q", code, stderr)
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("rpmgr_enr_not-a-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runRpmgr("enroll", "--controller", "https://127.0.0.1:1", "--ca-pin", "sha256:"+strings.Repeat("A", 43)+"=",
		"--token-file", tokenFile, "--identity-dir", filepath.Join(t.TempDir(), "id"))
	if code != cli.ExitError || !strings.Contains(stderr, "malformed or mistyped") {
		t.Errorf("a malformed token: exit %d, %q", code, stderr)
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
		{"release", "import"},        // no directory
		{"systemd-unit"},             // no role
		{"systemd-unit", "relay"},    // no such role
		{"kek", "rotate"},            // no previous KEK
		{"migrate", "extra"},         // a local command takes no arguments
		{"status", "extra"},          // an agent command takes no arguments
		{"restore"},                  // no archive
		{"backup"},                   // no archive
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

// TestVersionVerbose: --verbose adds the release root keys, none in a release build until the
// interim keys exist (D48), the two test roots in an rpmgrtest build (D60).
func TestVersionVerbose(t *testing.T) {
	code, stdout, stderr := runRpmgr("version", "--verbose")
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if code != cli.ExitOK || stderr != "" || !strings.HasPrefix(lines[0], "rpmgr dev (commit ") {
		t.Fatalf("rpmgr version --verbose: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	roots := release.Roots()
	if !release.TestBuild {
		if len(lines) != 4 || lines[1] != "release root keys:" ||
			lines[2] != "  7485D509E3D91A07  sha256:"+roots[0].Fingerprint() || lines[3] != "  E4C68FF1029A58D5  sha256:"+roots[1].Fingerprint() {
			t.Errorf("roots of a release build: %q", lines[1:])
		}
		return
	}
	if len(lines) != 4 || lines[1] != "test release root keys (rpmgrtest build):" ||
		lines[2] != "  "+roots[0].IDString()+"  sha256:"+roots[0].Fingerprint() || lines[3] != "  "+roots[1].IDString()+"  sha256:"+roots[1].Fingerprint() {
		t.Errorf("roots of an rpmgrtest build: %q", lines[1:])
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
