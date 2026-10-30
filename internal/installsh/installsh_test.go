// SPDX-License-Identifier: Apache-2.0

package installsh_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/installsh"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
)

var (
	root    = releasetest.Key("install root")
	signing = releasetest.Key("install signing")
	arch    = kernelArch()
)

// kernelArch is the architecture of the release the script installs on this host, from uname -m as
// the script reads it: an armv7 test binary on an arm64 kernel gets the arm64 release.
func kernelArch() string {
	out, err := exec.Command("uname", "-m").Output()
	if err != nil {
		return ""
	}
	return map[string]string{"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "arm", "riscv64": "riscv64"}[strings.TrimSpace(string(out))]
}

func pubkey(t *testing.T, s releasetest.Signer) release.PublicKey {
	t.Helper()
	k, err := release.ParsePublicKey(s.Public())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// files returns a test release of 1.4.2 for this machine's architecture, signed through root.
func files(t *testing.T, edit func(st map[string]any, m *release.Manifest)) map[string][]byte {
	t.Helper()
	now := time.Now().UTC()
	st := map[string]any{"statement": 1, "signer": signing.Public(),
		"not_before": now.Add(-24 * time.Hour).Format(time.RFC3339), "not_after": now.Add(300 * 24 * time.Hour).Format(time.RFC3339)}
	body := []byte("#!/bin/sh\necho rpmgr test binary\n")
	sum := sha256.Sum256(body)
	conn := []byte("#!/bin/sh\necho rpmgr connector-only test binary\n")
	connSum := sha256.Sum256(conn)
	m := release.Manifest{Seq: 87, Version: "1.4.2", Floor: "1.4.0", Channel: release.Stable, IssuedAt: now,
		Artifacts: []release.Artifact{{OS: "linux", Arch: arch, Variant: "full", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))},
			{OS: "linux", Arch: arch, Variant: "connector", SHA256: hex.EncodeToString(connSum[:]), Size: int64(len(conn))}}}
	if edit != nil {
		edit(st, &m)
	}
	stb, _ := json.Marshal(st)
	mb, _ := json.Marshal(m)
	return map[string][]byte{"signing-key.json": stb, "signing-key.json.minisig": root.Sign(stb), "manifest.json": mb,
		"manifest.json.minisig": signing.Sign(mb), "rpmgr-1.4.2-linux-" + arch: body, "rpmgr-1.4.2-linux-" + arch + "-connector": conn}
}

type server struct {
	mu    sync.Mutex
	files map[string][]byte
	*httptest.Server
	ca string
}

func newServer(t *testing.T) *server {
	s := &server{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		b, ok := s.files[strings.TrimPrefix(r.URL.Path, "/dl/1.4.2/")]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(s.Close)
	s.ca = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(s.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

// run runs the install script of 1.4.2 for root with args; extra PATH directories come first.
func run(t *testing.T, s *server, path string, args ...string) (string, error) {
	t.Helper()
	return runOn(t, newHostDirs(t), s, path, args...)
}

// hostDirs are where a script under test finds the host's binary and install record
// (RPMGR_INSTALL_BIN, RPMGR_INSTALL_STATE), so that no test reads the machine's own.
type hostDirs struct{ bin, state string }

// newHostDirs is a host without rpmgr.
func newHostDirs(t *testing.T) hostDirs {
	d := t.TempDir()
	return hostDirs{bin: filepath.Join(d, "bin", "rpmgr"), state: filepath.Join(d, "rpmgr-update")}
}

// withRecord gives h an install record of variant.
func (h hostDirs) withRecord(t *testing.T, variant string) hostDirs {
	t.Helper()
	if err := os.MkdirAll(h.state, 0o700); err != nil {
		t.Fatal(err)
	}
	rec := `{"method":"script","path":"/usr/local/bin/rpmgr","variant":"` + variant + `","role":"connector"}` + "\n"
	if err := os.WriteFile(filepath.Join(h.state, "install.json"), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

// withBinary gives h an rpmgr that prints out as `rpmgr version --verbose`, or exits 1 for "".
func (h hostDirs) withBinary(t *testing.T, out string) hostDirs {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(h.bin), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\nexit 1\n"
	if out != "" {
		body = "#!/bin/sh\ncat <<'EOF'\n" + out + "\nEOF\n"
	}
	if err := os.WriteFile(h.bin, []byte(body), 0o700); err != nil { //nolint:gosec // G306: a fake binary
		t.Fatal(err)
	}
	return h
}

// runOn runs the controller's script on host h.
func runOn(t *testing.T, h hostDirs, s *server, path string, args ...string) (string, error) {
	t.Helper()
	b, err := installsh.Render("1.4.2", []release.PublicKey{pubkey(t, root)})
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(script, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Env = []string{"PATH=" + path + os.Getenv("PATH"), "CURL_CA_BUNDLE=" + s.ca, "HOME=" + t.TempDir(),
		"RPMGR_INSTALL_BIN=" + h.bin, "RPMGR_INSTALL_STATE=" + h.state}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func needTools(t *testing.T) {
	t.Helper()
	if arch == "" {
		t.Skip("no rpmgr build for this kernel's architecture")
	}
	for _, tool := range []string{"sh", "curl", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	if out, _ := exec.Command("openssl", "version").Output(); !strings.HasPrefix(string(out), "OpenSSL 3") {
		t.Skipf("OpenSSL 3 is not installed: %s", out)
	}
}

// TestVerify: the script verifies a good release with OpenSSL, and refuses every broken link of
// the chain root -> statement -> manifest -> SHA-256 (docs/04-security.md, "Install scripts").
func TestVerify(t *testing.T) {
	needTools(t)
	s := newServer(t)
	ctl := []string{"--controller", s.URL, "--verify-only"}
	s.files = files(t, nil)
	if out, err := run(t, s, "", ctl...); err != nil || !strings.Contains(out, "verified rpmgr 1.4.2 (manifest 87)") ||
		!strings.Contains(out, "downloading rpmgr 1.4.2 (full) for linux/"+arch) {
		t.Fatalf("a good release: %v\n%s", err, out)
	}
	// The connector-only build (D119) is its own artifact, verified against its own manifest entry.
	if out, err := run(t, s, "", append(ctl, "--variant", "connector")...); err != nil || !strings.Contains(out, "verified rpmgr 1.4.2 (manifest 87)") ||
		!strings.Contains(out, "downloading rpmgr 1.4.2 (connector) for linux/"+arch) {
		t.Fatalf("the connector-only build: %v\n%s", err, out)
	}
	swapped := files(t, nil)
	full, conn := "rpmgr-1.4.2-linux-"+arch, "rpmgr-1.4.2-linux-"+arch+"-connector"
	swapped[full], swapped[conn] = swapped[conn], swapped[full]
	s.mu.Lock()
	s.files = swapped
	s.mu.Unlock()
	for _, variant := range []string{"full", "connector"} {
		if out, err := run(t, s, "", append(ctl, "--variant", variant)...); err == nil || !strings.Contains(out, "does not match") {
			t.Errorf("the %s build served as the other: %v\n%s", variant, err, out)
		}
	}
	s.mu.Lock()
	s.files = files(t, func(_ map[string]any, m *release.Manifest) { m.Artifacts = m.Artifacts[:1] })
	s.mu.Unlock()
	if out, err := run(t, s, "", append(ctl, "--variant", "connector")...); err == nil || !strings.Contains(out, "no connector build for linux/") {
		t.Errorf("a release without the connector-only build: %v\n%s", err, out)
	}
	other := releasetest.Key("another root")
	flip := func(b []byte, old, new string) []byte {
		return bytes.Replace(bytes.Clone(b), []byte(old), []byte(new), 1)
	}
	artifact := "rpmgr-1.4.2-linux-" + arch
	for name, tc := range map[string]struct {
		change func(f map[string][]byte)
		edit   func(st map[string]any, m *release.Manifest)
		want   string
	}{
		"a changed binary":   {change: func(f map[string][]byte) { f[artifact] = flip(f[artifact], "test", "TEST") }, want: "SHA-256 does not match"},
		"a longer binary":    {change: func(f map[string][]byte) { f[artifact] = append(f[artifact], '\n') }, want: "size does not match"},
		"a changed manifest": {change: func(f map[string][]byte) { f["manifest.json"] = flip(f["manifest.json"], `"seq":87`, `"seq":88`) }, want: "does not verify"},
		"a changed trusted comment": {change: func(f map[string][]byte) {
			f["manifest.json.minisig"] = flip(f["manifest.json.minisig"], "file:test", "file:evil")
		}, want: "trusted comment"},
		"a statement of another key": {change: func(f map[string][]byte) { f["signing-key.json.minisig"] = other.Sign(f["signing-key.json"]) }, want: "unknown key"},
		"a manifest of the root":     {change: func(f map[string][]byte) { f["manifest.json.minisig"] = root.Sign(f["manifest.json"]) }, want: "unknown key"},
		"a legacy signature": {change: func(f map[string][]byte) {
			lines := strings.Split(string(f["manifest.json.minisig"]), "\n")
			sig, _ := base64.StdEncoding.DecodeString(lines[1])
			sig[1] = 'd'
			lines[1] = base64.StdEncoding.EncodeToString(sig)
			f["manifest.json.minisig"] = []byte(strings.Join(lines, "\n"))
		}, want: "not a prehashed"},
		"a missing file": {change: func(f map[string][]byte) { delete(f, "manifest.json.minisig") }, want: "cannot download manifest.json.minisig"},
		"an expired statement": {edit: func(st map[string]any, _ *release.Manifest) {
			st["not_before"], st["not_after"] = "2025-01-01T00:00:00Z", time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
		}, want: "not valid now"},
		"a 13-month statement": {edit: func(st map[string]any, _ *release.Manifest) {
			st["not_after"] = time.Now().UTC().Add(380 * 24 * time.Hour).Format(time.RFC3339)
		}, want: "more than 12 months"},
		"another version":   {edit: func(_ map[string]any, m *release.Manifest) { m.Version = "1.4.3" }, want: "not of version 1.4.2"},
		"no build for here": {edit: func(_ map[string]any, m *release.Manifest) { m.Artifacts[0].Arch = "mips" }, want: "no full build for linux/"},
	} {
		f := files(t, tc.edit)
		if tc.change != nil {
			tc.change(f)
		}
		s.mu.Lock()
		s.files = f
		s.mu.Unlock()
		out, err := run(t, s, "", ctl...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}

// TestRefusals: what the script refuses before it downloads anything.
func TestRefusals(t *testing.T) {
	needTools(t)
	s := newServer(t)
	s.files = files(t, nil)
	old := t.TempDir()
	if err := os.WriteFile(filepath.Join(old, "openssl"), []byte("#!/bin/sh\necho 'OpenSSL 1.1.1w  11 Sep 2023'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "openssl"), []byte("#!/bin/sh\nexit 127\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path string
		args []string
		want string
	}{
		"plain HTTP":                 {"", []string{"--controller", "http://panel.example.com", "--verify-only"}, "must be an https:// URL"},
		"no controller":              {"", []string{"--verify-only"}, "must be an https:// URL"},
		"no pin to install":          {"", []string{"--controller", s.URL}, "--ca-pin is required"},
		"an unknown argument":        {"", []string{"--controller", s.URL, "--yes"}, "unknown argument --yes"},
		"an unknown role":            {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--role", "controller"}, "--role must be"},
		"targets for a gateway":      {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--role", "gateway", "--allow-target", "10.0.0.5:22"}, "no local policy"},
		"a target with a newline":    {"", []string{"--controller", s.URL, "--allow-target", "10.0.0.5:22\nx"}, "with a newline"},
		"denials for a gateway":      {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--role", "gateway", "--deny-target", "10.0.0.5"}, "no local policy"},
		"a denial with a newline":    {"", []string{"--controller", s.URL, "--deny-target", "10.0.0.5\nx"}, "with a newline"},
		"a denial without target":    {"", []string{"--controller", s.URL, "--deny-target"}, "--deny-target needs a target"},
		"an unreadable token file":   {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--token-file", "/nonexistent/token"}, "cannot read --token-file"},
		"an unknown variant":         {"", []string{"--controller", s.URL, "--verify-only", "--variant", "lite"}, "--variant must be full or connector"},
		"a connector-only gateway":   {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--role", "gateway", "--variant", "connector"}, "runs no gateway"},
		"another firewall":           {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--role", "gateway", "--firewall", "nftables"}, "--firewall must be ufw"},
		"a firewall for a connector": {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--firewall", "ufw"}, "--firewall is a gateway's"},
		"a range without a firewall": {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--role", "gateway", "--firewall-max-range", "20000-29999"}, "needs --firewall ufw"},
		"a range with a letter":      {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--role", "gateway", "--firewall", "ufw", "--firewall-max-range", "2000a-29999"}, "must be <from>-<to>"},
		"a range with one end":       {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--role", "gateway", "--firewall", "ufw", "--firewall-max-range", "20000"}, "must be <from>-<to>"},
		"a range that starts at 0":   {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--role", "gateway", "--firewall", "ufw", "--firewall-max-range", "0-100"}, "must be <from>-<to>"},
		"a range without a value":    {"", []string{"--controller", s.URL, "--firewall-max-range"}, "--firewall-max-range needs"},
		"a firewall without a value": {"", []string{"--controller", s.URL, "--firewall"}, "--firewall needs ufw"},
		"OpenSSL 1.1":                {old + ":", []string{"--controller", s.URL, "--verify-only"}, "OpenSSL 3.0 or later is needed"},
		"OpenSSL that fails":         {broken + ":", []string{"--controller", s.URL, "--verify-only"}, "openssl does not run"},
	} {
		out, err := run(t, s, tc.path, tc.args...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}

// TestNotRoot: installing needs root, and the script then says to run its file with sudo, never to
// pipe it into a shell (docs/04-security.md, "Install scripts"); verifying needs no root.
func TestNotRoot(t *testing.T) {
	b, err := installsh.Render("1.4.2", []release.PublicKey{pubkey(t, root)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `die "run as root: sudo sh install.sh ..."`) || strings.Contains(string(b), "sh -s") {
		t.Error("the script does not tell a user without root to run its file with sudo")
	}
	needTools(t)
	if os.Getuid() == 0 {
		t.Skip("the test runs as root")
	}
	s := newServer(t)
	s.files = files(t, nil)
	if out, err := run(t, s, "", "--controller", s.URL, "--ca-pin", "sha256:x"); err == nil || !strings.Contains(out, "run as root: sudo sh install.sh ...") {
		t.Errorf("an install without root: %v\n%s", err, out)
	}
}

// TestHandler: a release build with root keys serves its script; a development build, or one
// without root keys, serves a script that says why and fails; only GET and HEAD.
func TestHandler(t *testing.T) {
	get := func(h http.Handler, method string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, "/install.sh", nil))
		return w
	}
	w := get(installsh.Handler("1.4.2", []release.PublicKey{pubkey(t, root)}), http.MethodGet)
	// A connector's denied targets go into its policy before the allowed ones, so that an allow never
	// stands without the denials that narrow it.
	if deny, allow := strings.Index(w.Body.String(), `"$BIN" policy deny-target`), strings.Index(w.Body.String(), `"$BIN" policy allow-target`); deny < 0 ||
		allow < deny {
		t.Errorf("the script writes the denials at %d, the allows at %d", deny, allow)
	}
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "VERSION='1.4.2'") ||
		!strings.Contains(w.Body.String(), "BEGIN PUBLIC KEY") || w.Header().Get("Content-Type") != "text/x-shellscript; charset=utf-8" {
		t.Errorf("a release: %d %v", w.Code, w.Header())
	}
	for name, h := range map[string]http.Handler{"a development build": installsh.Handler("dev", []release.PublicKey{pubkey(t, root)}),
		"no root keys": installsh.Handler("1.4.2", nil)} {
		w := get(h, http.MethodGet)
		out, err := exec.Command("sh", "-c", w.Body.String()).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "serves no install script") {
			t.Errorf("%s: %v %q", name, err, out)
		}
	}
	if w := get(installsh.Handler("1.4.2", nil), http.MethodPost); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
}

// TestSyntax: the rendered script is valid POSIX shell for sh -n, with two roots embedded.
func TestSyntax(t *testing.T) {
	b, err := installsh.Render("1.4.2", []release.PublicKey{pubkey(t, root), pubkey(t, releasetest.Key("second root"))})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), "BEGIN PUBLIC KEY") != 2 {
		t.Errorf("roots in the script: %d", strings.Count(string(b), "BEGIN PUBLIC KEY"))
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = bytes.NewReader(b)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh -n: %v\n%s", err, out)
	}
}

// TestFirewallSteps (D152): with --firewall ufw the script adds the firewall section to a boot file
// that has none, lets the binary write the helper's bounds, directory and units from it, and
// enables them after the updater's, before the role's unit; without the flag it does none of it.
func TestFirewallSteps(t *testing.T) {
	b, err := installsh.Render("1.4.2", []release.PublicKey{pubkey(t, root)})
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	order := []string{`firewall install --role "$role"`, "systemctl enable --now rpmgr-update.path",
		"systemctl enable rpmgr-firewall.service", "systemctl enable --now rpmgr-firewall.path", `systemctl enable --now "rpmgr-$role"`}
	at := 0
	for _, want := range order {
		i := strings.Index(script[at:], want)
		if i < 0 {
			t.Fatalf("no %q after offset %d in the script", want, at)
		}
		at += i + len(want)
	}
	// The two units are enabled in one block, behind the flag.
	enable := strings.Index(script, "systemctl enable rpmgr-firewall.service")
	if enable < 0 || !strings.HasSuffix(strings.TrimSpace(script[:enable]), `if [ -n "$firewall" ]; then`) || strings.Count(script, "rpmgr-firewall") != 2 {
		t.Error("the firewall units are not enabled only behind the flag")
	}
	if !strings.Contains(script, `grep -q '^firewall:' "$boot"`) {
		t.Error("an existing firewall section of the boot file is not kept")
	}
}
