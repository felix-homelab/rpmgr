// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/setup"
	"github.com/felix-homelab/rpmgr/internal/setup/serversetup"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// setupFakes replaces the host of `rpmgr setup` with a temporary root: systemctl, systemd-creds,
// the enrollment and the readiness check are recorded, not run. The forms read plain prompts from
// stdin.
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
	old, oldStdin, oldTerminal := setupHost, setupStdin, setupTerminal
	t.Cleanup(func() { setupHost, setupStdin, setupTerminal = old, oldStdin, oldTerminal })
	setupStdin, setupTerminal = strings.NewReader(""), func() bool { return false }
	setupHost = setup.Host{
		Paths:  setup.Paths{Etc: filepath.Join(f.root, "etc"), Lib: filepath.Join(f.root, "lib"), Units: filepath.Join(f.root, "units"), Bin: bin},
		Server: serversetup.Server{},
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
// from $RPMGR_ENROLL_TOKEN, never the command line; it runs the plan with --yes, asks otherwise in
// forms pre-filled with the flags, and changes nothing when the operator does not confirm.
func TestSetup_Connector(t *testing.T) {
	f := fakeSetup(t)
	tok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"RPMGR_ENROLL_TOKEN": tok}
	args := []string{"setup", "--role", "connector", "--controller", "https://panel.example.com",
		"--ca-pin", "sha256:" + strings.Repeat("A", 43) + "=", "--allow-target", "10.0.0.5:8080"}

	if code, _, errOut := runWith(env, "", "setup", "--yes"); code != cli.ExitUsage || !strings.Contains(errOut, "--role") {
		t.Errorf("--yes without a role: %d %q", code, errOut)
	}
	code, out, errOut := runWith(env, "", args...) // every answer the pre-filled one, up to "Run it?"
	if code != cli.ExitError || !strings.Contains(errOut, "not confirmed") || len(f.enrolled) != 0 ||
		!strings.Contains(out, "10.0.0.5:8080") || !strings.Contains(out, "enroll with https://panel.example.com") {
		t.Fatalf("declined: %d %q %q, enrolled %d", code, out, errOut, len(f.enrolled))
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a declined plan created %s: %v", filepath.Join(f.root, "etc"), err)
	}

	code, out, errOut = runWith(env, "", append(args, "--yes")...)
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
		"--token-file", "/nonexistent", "--yes"); code != cli.ExitUsage || !strings.Contains(errOut, "--token-file") {
		t.Errorf("a token file for a controller: %d %q", code, errOut)
	}
	if code, _, errOut := runWith(nil, "", "setup", "--role", "router", "--yes"); code == cli.ExitOK || !strings.Contains(errOut, "no role") {
		t.Errorf("an unknown role: %d %q", code, errOut)
	}
	if code, _, errOut := runWith(nil, "", "setup", "--role", "controller", "extra"); code != cli.ExitUsage {
		t.Errorf("an argument: %d %q", code, errOut)
	}
	setupHost.IsRoot = func() bool { return false }
	setupStdin = strings.NewReader("1\n")
	if code, out, errOut := runWith(nil, "", "setup"); code != cli.ExitError || !strings.Contains(errOut, "as root") || out != "" {
		t.Errorf("not root: %d %q %q", code, out, errOut)
	}
	setupHost.IsRoot = func() bool { return true }

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

// testProxy is a proxy URL with a made-up password.
const testProxy = "http://ops:s3cret@proxy.lan:3128" //nolint:gosec // G101: a made-up test password

// TestSetup_ProxyFile (#557): a proxy URL with credentials never comes from the command line:
// --proxy refuses it without repeating it, --proxy-file reads it, warns of a file other users may
// read, and setup writes it into the connector's environment file only.
func TestSetup_ProxyFile(t *testing.T) {
	f := fakeSetup(t)
	tok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"RPMGR_ENROLL_TOKEN": tok}
	args := []string{"setup", "--role", "connector", "--controller", "https://panel.example.com",
		"--ca-pin", "sha256:" + strings.Repeat("A", 43) + "=", "--yes"}
	file := filepath.Join(t.TempDir(), "proxy")
	if err := os.WriteFile(file, []byte(testProxy+"\n"), 0o644); err != nil { //nolint:gosec // G306: a file other users may read, on purpose
		t.Fatal(err)
	}

	for name, extra := range map[string][]string{
		"credentials in --proxy": {"--proxy", testProxy},
		"a user name in --proxy": {"--proxy", "http://s3cret@proxy.lan:3128"},
		"both flags":             {"--proxy", "http://proxy.lan:3128", "--proxy-file", file},
	} {
		code, out, errOut := runWith(env, "", append(args, extra...)...)
		if code != cli.ExitUsage || strings.Contains(out+errOut, "s3cret") || !strings.Contains(errOut, "--proxy-file") || len(f.enrolled) != 0 {
			t.Errorf("%s: %d %q %q, enrolled %d", name, code, out, errOut, len(f.enrolled))
		}
	}
	if code, out, errOut := runWith(env, "", append(args, "--proxy-file", filepath.Join(t.TempDir(), "none"))...); code != cli.ExitError ||
		!strings.Contains(errOut, "--proxy-file") || len(f.enrolled) != 0 {
		t.Errorf("a missing file: %d %q %q", code, out, errOut)
	}

	code, out, errOut := runWith(env, "", append(args, "--proxy-file", file)...)
	if code != cli.ExitOK || strings.Contains(out+errOut, "s3cret") || !strings.Contains(errOut, "warning: the proxy file") ||
		len(f.enrolled) != 1 || f.enrolled[0].Dial == nil {
		t.Fatalf("--proxy-file: %d %q %q, enrolled %d", code, out, errOut, len(f.enrolled))
	}
	envFile := filepath.Join(f.root, "etc", "connector-proxy.env")
	b, err := os.ReadFile(envFile) //nolint:gosec // G304: the test's own file
	if err != nil || string(b) != "HTTPS_PROXY="+testProxy+"\n" {
		t.Fatalf("%s: %q %v", envFile, b, err)
	}
	if fi, err := os.Stat(envFile); err != nil {
		t.Error(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("%s: mode %v", envFile, fi.Mode())
	}
}

// TestSetup_Form: without flags, the plain prompts ask role by role, ask again after a wrong
// answer, show the plan and run it once confirmed.
func TestSetup_Form(t *testing.T) {
	f := fakeSetup(t)
	setupStdin = strings.NewReader(strings.Join([]string{
		"",                               // role: all-in-one, the default
		"http://panel.example.com",       // refused: not https
		"https://panel.example.com",      // public URL
		"2",                              // KEK: file
		"3",                              // certificate: self-signed
		"",                               // KEK file: the default
		"2",                              // ACME CA: staging
		"ops@example.com",                // ACME e-mail
		"127.0.0.1:8080 10.0.0.0/24",     // the connector's allowed targets
		"10.0.0.9",                       // and denied ones
		"", "", "off", "127.0.0.1:17381", // listen.tcp, udp, http, admin
		"",  // install the unit: yes
		"y", // run it
	}, "\n") + "\n")
	code, out, errOut := runWith(nil, "", "setup")
	if code != cli.ExitOK {
		t.Fatalf("setup: %d %q %q", code, out, errOut)
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("plain prompts with styles:\n%q", out)
	}
	for _, want := range []string{"all-in-one: controller, gateway and connector in one process", "want https://", "back the KEK up apart from the database",
		"Steps:", "→ make a self-signed certificate for panel.example.com", "→ set the instance's ACME directory", "CA pin:       sha256:",
		"enroll its gateway and connector", "→ allow 2 and deny 1 target(s) in the connector-local policy", "allowed targets: 127.0.0.1:8080, 10.0.0.0/24",
		"connector:    con_", "rpmgr policy allow-target"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	policyFile := filepath.Join(f.root, "etc", "policy.yaml")
	boot, err := os.ReadFile(filepath.Join(f.root, "etc", "all-in-one.yaml"))
	if err != nil || !strings.Contains(string(boot), "source: file") || !strings.Contains(string(boot), `http: ""`) ||
		!strings.Contains(string(boot), "admin: 127.0.0.1:17381") || !strings.Contains(string(boot), "policy_file: "+policyFile) {
		t.Errorf("boot file %q %v", boot, err)
	}
	p, err := policy.Load(policyFile)
	if err != nil || p.Check("127.0.0.1:8080") != nil || p.Check("10.0.0.5:22") != nil || p.Check("10.0.0.9:22") == nil {
		t.Errorf("the connector's policy: %v", err)
	}
}

// TestSetup_FormGateway: a gateway asked in plain prompts takes its token from the environment
// and never shows it.
func TestSetup_FormGateway(t *testing.T) {
	f := fakeSetup(t)
	tok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	setupStdin = strings.NewReader(strings.Join([]string{
		"3", "https://panel.example.com", "sha256:" + strings.Repeat("A", 43) + "=", // role, controller, pin
		"", "", "", "", // listen.tcp, udp, http, admin
		"n", // no unit
		"y",
	}, "\n") + "\n")
	code, out, errOut := runWith(map[string]string{"RPMGR_ENROLL_TOKEN": tok}, "", "setup")
	if code != cli.ExitOK || len(f.enrolled) != 1 || f.enrolled[0].Token != tok || strings.Contains(out+errOut, tok) ||
		!strings.Contains(out, "rpmgr gateway is set up: enrolled") || len(f.commands) != 0 {
		t.Fatalf("setup: %d %q %q, enrolled %+v, commands %q", code, out, errOut, f.enrolled, f.commands)
	}
}

// TestSetup_FormPrivateName: without systemd 250 the KEK is a file, said rather than asked; a name
// no public CA certifies is offered no ACME certificate; and a plan not confirmed changes nothing.
func TestSetup_FormPrivateName(t *testing.T) {
	f := fakeSetup(t)
	setupHost.SystemdVersion = func() int { return 0 }
	setupStdin = strings.NewReader(strings.Join([]string{
		"2", "https://rpmgr.home.arpa", // controller, public URL
		"2",        // certificate: self-signed, the second of files and self-signed
		"", "", "", // KEK file, ACME CA, e-mail
		"", "", "", // listen.https, http, admin
		"n", // no unit: there is no systemd
		"n", // do not run it
	}, "\n") + "\n")
	code, out, errOut := runWith(nil, "", "setup")
	if code != cli.ExitError || !strings.Contains(errOut, "not confirmed") {
		t.Fatalf("setup: %d %q %q", code, out, errOut)
	}
	if !strings.Contains(out, "The KEK is a file") || strings.Contains(out, "Where the KEK is kept") || strings.Contains(out, "acme: from the ACME CA") ||
		!strings.Contains(out, "certificate:     self-signed") || !strings.Contains(out, "none (--no-unit)") {
		t.Errorf("form:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an unconfirmed plan created %s: %v", filepath.Join(f.root, "etc"), err)
	}
}

// TestLineReader: the plain prompts get one line per read, however long, and the last line
// without a newline too.
func TestLineReader(t *testing.T) {
	long := strings.Repeat("x", 9000)
	r := &lineReader{r: bufio.NewReader(strings.NewReader("a\n" + long + "\nlast"))}
	var got []string
	for {
		s := bufio.NewScanner(r) // a new scanner per prompt, as huh's plain prompts read
		s.Buffer(make([]byte, 0, 64), 1<<20)
		if !s.Scan() {
			break
		}
		got = append(got, s.Text())
	}
	if len(got) != 3 || got[0] != "a" || got[1] != long || got[2] != "last" {
		t.Errorf("lines %d: %.20q", len(got), got)
	}
	if err := keep("https://panel.example.com", setup.CheckPublicURL)(""); err != nil {
		t.Errorf("an empty answer keeps a pre-filled value: %v", err)
	}
	if err := keep("", setup.CheckPublicURL)(""); err == nil {
		t.Error("an empty answer without a value accepted")
	}
}

// runWith runs `rpmgr setup` of the full build in a command tree of this package's commands, with
// env as the environment.
func runWith(env map[string]string, _ string, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	tree := &cli.Command{Name: "rpmgr", Sub: []*cli.Command{Setup(serversetup.Server{}), Enroll(), Policy()}}
	code := cli.Main(context.Background(), tree, args, &cli.Env{Stdout: &out, Stderr: &errOut, Getenv: func(k string) string { return env[k] }})
	return code, out.String(), errOut.String()
}
