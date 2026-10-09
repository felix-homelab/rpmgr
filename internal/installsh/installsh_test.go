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
	"runtime"
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
	arch    = map[string]string{"amd64": "amd64", "arm64": "arm64", "arm": "arm", "riscv64": "riscv64"}[runtime.GOARCH]
)

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
	m := release.Manifest{Seq: 87, Version: "1.4.2", Floor: "1.4.0", Channel: release.Stable, IssuedAt: now,
		Artifacts: []release.Artifact{{OS: "linux", Arch: arch, Variant: "full", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))}}}
	if edit != nil {
		edit(st, &m)
	}
	stb, _ := json.Marshal(st)
	mb, _ := json.Marshal(m)
	return map[string][]byte{"signing-key.json": stb, "signing-key.json.minisig": root.Sign(stb), "manifest.json": mb,
		"manifest.json.minisig": signing.Sign(mb), "rpmgr-1.4.2-linux-" + arch: body}
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
	b, err := installsh.Render("1.4.2", []release.PublicKey{pubkey(t, root)})
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(script, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Env = []string{"PATH=" + path + os.Getenv("PATH"), "CURL_CA_BUNDLE=" + s.ca, "HOME=" + t.TempDir()}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func needTools(t *testing.T) {
	t.Helper()
	if arch == "" {
		t.Skip("no rpmgr build for " + runtime.GOARCH)
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
	if out, err := run(t, s, "", ctl...); err != nil || !strings.Contains(out, "verified rpmgr 1.4.2 (manifest 87)") {
		t.Fatalf("a good release: %v\n%s", err, out)
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
		"plain HTTP":               {"", []string{"--controller", "http://panel.example.com", "--verify-only"}, "must be an https:// URL"},
		"no controller":            {"", []string{"--verify-only"}, "must be an https:// URL"},
		"no pin to install":        {"", []string{"--controller", s.URL}, "--ca-pin is required"},
		"an unknown argument":      {"", []string{"--controller", s.URL, "--yes"}, "unknown argument --yes"},
		"an unknown role":          {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--role", "controller"}, "--role must be"},
		"targets for a gateway":    {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--role", "gateway", "--allow-target", "10.0.0.5:22"}, "no local policy"},
		"a target with a newline":  {"", []string{"--controller", s.URL, "--allow-target", "10.0.0.5:22\nx"}, "with a newline"},
		"an unreadable token file": {"", []string{"--controller", s.URL, "--ca-pin", "sha256:x", "--token-file", "/nonexistent/token"}, "cannot read --token-file"},
		"OpenSSL 1.1":              {old + ":", []string{"--controller", s.URL, "--verify-only"}, "OpenSSL 3.0 or later is needed"},
		"OpenSSL that fails":       {broken + ":", []string{"--controller", s.URL, "--verify-only"}, "openssl does not run"},
	} {
		out, err := run(t, s, tc.path, tc.args...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
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
