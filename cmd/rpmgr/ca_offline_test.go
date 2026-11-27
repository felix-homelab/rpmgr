// SPDX-License-Identifier: Apache-2.0

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

// TestCAOfflineRootRoundTrip is the ceremony through the command line: take the root offline, see
// the warning, ask for a signature, sign on the "offline host" and import. The commands that need
// the online root refuse meanwhile; every refusal changes nothing.
func TestCAOfflineRootRoundTrip(t *testing.T) {
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
	rootFile := filepath.Join(dir, "root.age")
	passFile := filepath.Join(dir, "pass")
	if err := os.WriteFile(passFile, []byte("Tr4ffic-Light-Mango-91x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fail := func(args ...string) string {
		t.Helper()
		code, stdout, stderr := runRpmgr(append(args, "--config", cfg)...)
		if code != cli.ExitError {
			t.Fatalf("rpmgr %s: exit %d, want an error; %q %q", strings.Join(args, " "), code, stdout, stderr)
		}
		return stderr
	}
	run := func(args ...string) string {
		t.Helper()
		code, stdout, stderr := runRpmgr(append(args, "--config", cfg)...)
		if code != cli.ExitOK {
			t.Fatalf("rpmgr %s: exit %d: %q %q", strings.Join(args, " "), code, stdout, stderr)
		}
		return stdout
	}
	if out := run("ca", "status"); !strings.Contains(out, "Root key:     online") {
		t.Errorf("status before: %q", out)
	}

	// Usage errors and refusals before anything is written. A passphrase is never an argument.
	for _, args := range [][]string{
		{"ca", "offline-root"}, // no --out
		{"ca", "offline-root", "--out", rootFile, "--passphrase", "Tr4ffic-Light-Mango-91x"},
		{"ca", "offline-root", "--out", rootFile, "--passphrase-file", passFile, "--prompt"},
		{"ca", "offline-root", "--out", rootFile, "Tr4ffic-Light-Mango-91x"},
		{"ca", "sign-intermediate", "--root-file", rootFile},
		{"ca", "import-intermediate"},
	} {
		if code, _, stderr := runRpmgr(append(args, "--config", cfg)...); code != cli.ExitUsage || strings.Contains(stderr, "Mango") {
			t.Errorf("rpmgr %s: exit %d, %q", strings.Join(args, " "), code, stderr)
		}
	}
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("Tr4ffic-Light-Mango-91x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil { //nolint:gosec // G302: a passphrase file other users can read, which must be refused
		t.Fatal(err)
	}
	weak := filepath.Join(dir, "weak")
	if err := os.WriteFile(weak, []byte("passwordpassword\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if e := fail("ca", "offline-root", "--out", rootFile, "--passphrase-file", loose); !strings.Contains(e, "mode") {
		t.Errorf("a passphrase file other users can read: %q", e)
	}
	if e := fail("ca", "offline-root", "--out", rootFile, "--passphrase-file", weak); !strings.Contains(e, "too weak") {
		t.Errorf("a weak passphrase: %q", e)
	}
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if e := fail("ca", "offline-root", "--out", existing, "--passphrase-file", passFile); !strings.Contains(e, "exists") {
		t.Errorf("an existing output file: %q", e)
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep me" {
		t.Error("an existing output file was changed")
	}
	if out := run("ca", "status"); !strings.Contains(out, "Root key:     online") {
		t.Errorf("a refused ceremony took the root offline: %q", out)
	}
	if e := fail("ca", "rotate-intermediate", "--csr-out", filepath.Join(dir, "no.csr")); !strings.Contains(e, "online") {
		t.Errorf("--csr-out with an online root: %q", e)
	}

	// The passphrase from the terminal, asked twice; two that differ are refused.
	origPrompt := passphrasePrompt
	t.Cleanup(func() { passphrasePrompt = origPrompt })
	passphrasePrompt = func(twice bool) (string, error) {
		if !twice {
			t.Error("offline-root must ask twice")
		}
		return "", errors.New("the two passphrases differ")
	}
	if e := fail("ca", "offline-root", "--out", rootFile, "--prompt"); !strings.Contains(e, "differ") {
		t.Errorf("--prompt with answers that differ: %q", e)
	}

	// The ceremony from a prompt.
	passphrasePrompt = func(bool) (string, error) { return "Tr4ffic-Light-Mango-91x", nil }
	out := run("ca", "offline-root", "--out", rootFile, "--prompt")
	if !strings.Contains(out, "Root pin:     sha256:") || strings.Contains(out, "Passphrase:") || !strings.Contains(out, "Rotate the KEK") {
		t.Errorf("offline-root: %q", out)
	}
	if st, err := os.Stat(rootFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("the root file: %v %v", st, err)
	}
	status := run("ca", "status")
	if !strings.Contains(status, "Root key:     offline") || !strings.Contains(status, "WARNING: the root's sealed key may still be recoverable") {
		t.Errorf("status after: %q", status)
	}

	// The online-root commands refuse.
	if e := fail("ca", "rotate-intermediate"); !strings.Contains(e, "root is offline") || !strings.Contains(e, "--csr-out") {
		t.Errorf("rotate-intermediate with an offline root: %q", e)
	}
	if e := fail("ca", "offline-root", "--out", filepath.Join(dir, "second"), "--passphrase-file", passFile); !strings.Contains(e, "offline") {
		t.Errorf("a second ceremony: %q", e)
	}

	// A request, signed on the offline host.
	csr, cert := filepath.Join(dir, "next.csr"), filepath.Join(dir, "next.crt")
	asked := run("ca", "rotate-intermediate", "--csr-out", csr)
	hash := regexp.MustCompile(`Key SHA-256: ([0-9a-f]{64})`).FindStringSubmatch(asked)
	if hash == nil {
		t.Fatalf("no key hash in %q", asked)
	}
	if out := run("ca", "status"); !strings.Contains(out, "needs the offline root's signature (key SHA-256 "+hash[1]+")") {
		t.Errorf("status with a request that waits: %q", out)
	}
	if e := fail("ca", "rotate-intermediate", "--csr-out", csr); !strings.Contains(e, "exists") {
		t.Errorf("an existing request file: %q", e)
	}
	sign := func(extra ...string) (int, string, string) {
		return runRpmgr(append([]string{"ca", "sign-intermediate", "--root-file", rootFile, "--csr", csr, "--out", cert}, extra...)...)
	}
	// --yes signs without asking, so it must name the key; a request with another key is refused.
	if code, _, stderr := sign("--passphrase-file", passFile, "--yes"); code != cli.ExitUsage || !strings.Contains(stderr, "--key-sha256") {
		t.Errorf("--yes without --key-sha256: exit %d, %q", code, stderr)
	}
	if code, _, stderr := sign("--passphrase-file", passFile, "--yes", "--key-sha256", strings.Repeat("0", 64)); code != cli.ExitError || !strings.Contains(stderr, "nothing was signed") {
		t.Errorf("--yes with another key's hash: exit %d, %q", code, stderr)
	}
	if _, err := os.Lstat(cert); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused request left a certificate: %v", err)
	}
	wrong := filepath.Join(dir, "wrong")
	if err := os.WriteFile(wrong, []byte("Not-The-Passphrase-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := sign("--passphrase-file", wrong, "--yes", "--key-sha256", hash[1]); code != cli.ExitError || !strings.Contains(stderr, "does not open") || strings.Contains(stderr, "Not-The") {
		t.Errorf("a wrong passphrase: exit %d, %q", code, stderr)
	}
	origConfirm := confirmPrompt
	t.Cleanup(func() { confirmPrompt = origConfirm })
	confirmPrompt = func(string) (bool, error) { return false, nil }
	if code, stdout, stderr := sign("--passphrase-file", passFile); code != cli.ExitError || !strings.Contains(stderr, "not confirmed") ||
		!strings.Contains(stdout, hash[1]) || !strings.Contains(stdout, "path length 0") {
		t.Errorf("a declined confirmation: exit %d, %q %q", code, stdout, stderr)
	}
	if _, err := os.Lstat(cert); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a declined signature wrote a certificate: %v", err)
	}
	confirmPrompt = func(string) (bool, error) { return true, nil }
	passphrasePrompt = func(twice bool) (string, error) {
		if twice {
			t.Error("sign-intermediate asks once")
		}
		return "Tr4ffic-Light-Mango-91x", nil
	}
	if code, stdout, stderr := sign(); code != cli.ExitOK || !strings.Contains(stdout, hash[1]) {
		t.Fatalf("sign: exit %d, %q %q", code, stdout, stderr)
	}
	if code, _, stderr := sign("--yes", "--key-sha256", hash[1]); code != cli.ExitError || !strings.Contains(stderr, "exists") {
		t.Errorf("an existing certificate: exit %d, %q", code, stderr)
	}

	// The import: the request is no certificate; the certificate is.
	if e := fail("ca", "import-intermediate", "--in", csr); e == "" {
		t.Error("a request imported as a certificate")
	}
	if e := fail("ca", "import-intermediate", "--in", filepath.Join(dir, "none")); !strings.Contains(e, "none") {
		t.Errorf("a missing file: %q", e)
	}
	if out := run("ca", "import-intermediate", "--in", cert); !strings.Contains(out, hash[1]) {
		t.Errorf("import: %q", out)
	}
	if e := fail("ca", "import-intermediate", "--in", cert); !strings.Contains(e, "no intermediate waits") {
		t.Errorf("a second import: %q", e)
	}
	if out := run("ca", "status"); !strings.Contains(out, "next") || strings.Contains(out, "needs the offline root's signature") {
		t.Errorf("status after the import shows no next intermediate, or still asks for a signature: %q", out)
	}
}

// TestAskSecret: a passphrase is read with echo off, through readPassword, once or twice, and the
// prompt goes to the terminal, not to the output.
func TestAskSecret(t *testing.T) {
	tty, err := os.CreateTemp(t.TempDir(), "tty")
	if err != nil {
		t.Fatal(err)
	}
	origTTY, origRead := openTTY, readPassword
	t.Cleanup(func() { openTTY, readPassword = origTTY, origRead })
	openTTY = func() (*os.File, error) { return tty, nil }
	var asked []int
	answers := []string{"Tr4ffic-Light-Mango-91x", "Tr4ffic-Light-Mango-91x"}
	readPassword = func(fd int) ([]byte, error) {
		asked = append(asked, fd)
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
	if p, err := passphrasePrompt(true); err != nil || p != "Tr4ffic-Light-Mango-91x" || len(asked) != 2 {
		t.Fatalf("passphrase %q %v after %d reads without echo", p, err, len(asked))
	}
	b, _ := os.ReadFile(tty.Name())
	if !strings.Contains(string(b), "Passphrase again: ") || strings.Contains(string(b), "Mango") {
		t.Errorf("the terminal got %q", b)
	}
	// Two answers that differ are refused.
	tty2, _ := os.CreateTemp(t.TempDir(), "tty")
	openTTY = func() (*os.File, error) { return tty2, nil }
	answers = []string{"Tr4ffic-Light-Mango-91x", "another"}
	if _, err := passphrasePrompt(true); err == nil || !strings.Contains(err.Error(), "differ") {
		t.Errorf("answers that differ: %v", err)
	}
	// No terminal: a clear refusal.
	openTTY = func() (*os.File, error) { return nil, errors.New("no tty") }
	if _, err := passphrasePrompt(false); err == nil || !strings.Contains(err.Error(), "--passphrase-file") {
		t.Errorf("no terminal: %v", err)
	}
}

// TestCAOfflineRootRotationPath: the whole offline path of a root rotation through the CLI, as the output
// of `ca new-root --csr-out` tells it: both requests are signed with sign-intermediate (the new root's with
// --kind cross-root) and imported; a kind that does not exist, or the wrong kind for a request, is refused.
func TestCAOfflineRootRotationPath(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "controller.yaml")
	boot := "version: 1\npublic_url: https://panel.example.com\n" +
		"database: {dsn: " + filepath.Join(dir, "controller.db") + "}\n" +
		"kek: {source: file, path: " + filepath.Join(dir, "kek") + "}\n"
	if err := os.WriteFile(cfg, []byte(boot), 0o644); err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(dir, "pass")
	if err := os.WriteFile(passFile, []byte("Tr4ffic-Light-Mango-91x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(dir, "root.age")
	run := func(args ...string) string {
		t.Helper()
		code, stdout, stderr := runRpmgr(append(args, "--config", cfg)...)
		if code != cli.ExitOK {
			t.Fatalf("rpmgr %s: exit %d: %q %q", strings.Join(args, " "), code, stdout, stderr)
		}
		return stdout
	}
	run("controller", "init")
	run("ca", "offline-root", "--out", rootFile, "--passphrase-file", passFile)

	csr := filepath.Join(dir, "r2.csr")
	out := run("ca", "new-root", "--csr-out", csr)
	hashes := regexp.MustCompile(`key SHA-256 ([0-9a-f]{64})`).FindAllStringSubmatch(out, -1)
	if len(hashes) != 2 || !strings.Contains(out, "--kind cross-root") {
		t.Fatalf("new-root --csr-out: %q", out)
	}
	sign := func(csrFile, out, hash string, extra ...string) (int, string, string) {
		return runRpmgr(append([]string{"ca", "sign-intermediate", "--root-file", rootFile, "--csr", csrFile, "--out", out,
			"--passphrase-file", passFile, "--yes", "--key-sha256", hash}, extra...)...)
	}
	x, y := filepath.Join(dir, "x.crt"), filepath.Join(dir, "y.crt")
	if code, _, stderr := sign(csr, filepath.Join(dir, "bad.crt"), hashes[0][1], "--kind", "bogus"); code != cli.ExitUsage || !strings.Contains(stderr, "--kind") {
		t.Errorf("an unknown --kind: exit %d, %q", code, stderr)
	}
	// Without --kind cross-root the request of the new root is signed as an intermediate, which the import refuses.
	plain := filepath.Join(dir, "plain.crt")
	if code, _, stderr := sign(csr, plain, hashes[0][1]); code != cli.ExitOK {
		t.Fatalf("signing as an intermediate: exit %d, %q", code, stderr)
	}
	if code, _, _ := runRpmgr("ca", "import-intermediate", "--in", plain, "--config", cfg); code == cli.ExitOK {
		t.Error("an ordinary intermediate for the new root's key was imported")
	}
	if code, _, stderr := sign(csr, x, hashes[0][1], "--kind", "cross-root"); code != cli.ExitOK {
		t.Fatalf("signing the cross-certificate: exit %d, %q", code, stderr)
	}
	if code, _, stderr := sign(csr+controller.IntermediateSuffix, y, hashes[1][1]); code != cli.ExitOK {
		t.Fatalf("signing the intermediate: exit %d, %q", code, stderr)
	}
	if st := run("ca", "status"); !strings.Contains(st, "cross-certificate of the new root is missing") {
		t.Errorf("status before the imports: %q", st)
	}
	run("ca", "import-intermediate", "--in", x)
	run("ca", "import-intermediate", "--in", y)
	if st := run("ca", "status"); !strings.Contains(st, "Both are imported") {
		t.Errorf("status after the imports: %q", st)
	}
}

// TestCANewRootAbort: a rotation that waits for the old root is given up with --abort, which the status
// points to; it excludes --csr-out and is refused when nothing waits.
func TestCANewRootAbort(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "controller.yaml")
	boot := "version: 1\npublic_url: https://panel.example.com\n" +
		"database: {dsn: " + filepath.Join(dir, "controller.db") + "}\n" +
		"kek: {source: file, path: " + filepath.Join(dir, "kek") + "}\n"
	if err := os.WriteFile(cfg, []byte(boot), 0o644); err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(dir, "pass")
	if err := os.WriteFile(passFile, []byte("Tr4ffic-Light-Mango-91x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) { return runRpmgr(append(args, "--config", cfg)...) }
	if code, _, stderr := run("controller", "init"); code != cli.ExitOK {
		t.Fatal(stderr)
	}
	if code, _, stderr := run("ca", "offline-root", "--out", filepath.Join(dir, "root.age"), "--passphrase-file", passFile); code != cli.ExitOK {
		t.Fatal(stderr)
	}
	if code, _, stderr := run("ca", "new-root", "--abort"); code != cli.ExitError || !strings.Contains(stderr, "no new root waits") {
		t.Errorf("--abort with no rotation: exit %d, %q", code, stderr)
	}
	if code, _, stderr := run("ca", "new-root", "--csr-out", filepath.Join(dir, "r2.csr")); code != cli.ExitOK {
		t.Fatal(stderr)
	}
	if code, stdout, _ := run("ca", "status"); code != cli.ExitOK || !strings.Contains(stdout, "new-root --abort") {
		t.Errorf("status of a rotation that waits: %q", stdout)
	}
	if code, _, stderr := run("ca", "new-root", "--abort", "--csr-out", filepath.Join(dir, "x.csr")); code != cli.ExitUsage {
		t.Errorf("--abort with --csr-out: exit %d, %q", code, stderr)
	}
	if code, stdout, stderr := run("ca", "new-root", "--abort"); code != cli.ExitOK || !strings.Contains(stdout, "removed") {
		t.Fatalf("--abort: exit %d, %q %q", code, stdout, stderr)
	}
	if code, stdout, _ := run("ca", "status"); code != cli.ExitOK || strings.Contains(stdout, "Root rotation") {
		t.Errorf("status after the abort: %q", stdout)
	}
	if code, _, stderr := run("ca", "new-root", "--csr-out", filepath.Join(dir, "r2b.csr")); code != cli.ExitOK {
		t.Errorf("a new rotation after the abort: %q", stderr)
	}
}
