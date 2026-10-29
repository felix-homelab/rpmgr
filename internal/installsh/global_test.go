// SPDX-License-Identifier: Apache-2.0

package installsh_test

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/installsh"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/units"
)

// github fakes the GitHub of rpmgr's releases: the download URLs of release v1.4.2, and the API's
// latest release and release list.
type github struct {
	mu    sync.Mutex
	files map[string][]byte
	*httptest.Server
	ca string
}

func newGitHub(t *testing.T) *github {
	g := &github{}
	g.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/felix-homelab/rpmgr/releases/latest":
			_, _ = w.Write([]byte(`{"url": "x", "tag_name": "v1.4.2", "name": "rpmgr 1.4.2"}`))
			return
		case "/repos/felix-homelab/rpmgr/releases":
			_, _ = w.Write([]byte("[\n  {\"tag_name\": \"v1.5.0-rc.1\", \"prerelease\": true},\n  {\"tag_name\": \"v1.4.2\"}\n]"))
			return
		}
		g.mu.Lock()
		b, ok := g.files[strings.TrimPrefix(r.URL.Path, "/felix-homelab/rpmgr/releases/download/v1.4.2/")]
		g.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(g.Close)
	g.ca = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(g.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return g
}

// runGlobal runs the global install script, pinned to version ("" for the repository's copy),
// against g with args; extra PATH directories come first.
func runGlobal(t *testing.T, g *github, version, path string, args ...string) (string, error) {
	t.Helper()
	return runGlobalOn(t, newHostDirs(t), g, version, path, args...)
}

// runGlobalOn runs the global script on host h: its binary and install record.
func runGlobalOn(t *testing.T, h hostDirs, g *github, version, path string, args ...string) (string, error) {
	t.Helper()
	b, err := installsh.RenderGlobal(version, []release.PublicKey{pubkey(t, root)})
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(script, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Env = []string{"PATH=" + path + os.Getenv("PATH"), "CURL_CA_BUNDLE=" + g.ca, "HOME=" + t.TempDir(),
		"RPMGR_INSTALL_GITHUB=" + g.URL, "RPMGR_INSTALL_API=" + g.URL, "RPMGR_INSTALL_BIN=" + h.bin, "RPMGR_INSTALL_STATE=" + h.state}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// stubs returns a PATH directory with a script per name, each printing its text.
func stubs(t *testing.T, scripts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return dir + ":"
}

// TestGlobal_Verify (docs/04-security.md, "Install scripts"): the global script finds the latest
// release, or takes a pinned or given version, downloads it from GitHub and verifies it as the
// controller's script does; it refuses every broken link of the chain, and what it cannot run on.
func TestGlobal_Verify(t *testing.T) {
	needTools(t)
	g := newGitHub(t)
	g.files = files(t, nil)
	for name, tc := range map[string]struct{ version string }{"the latest": {""}, "a pinned version": {"1.4.2"}} {
		out, err := runGlobal(t, g, tc.version, "", "--verify-only")
		if err != nil || !strings.Contains(out, "downloading rpmgr 1.4.2 (full) for linux/"+arch) || !strings.Contains(out, "verified rpmgr 1.4.2 (manifest 87)") {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
	}
	if out, err := runGlobal(t, g, "1.4.2", "", "--verify-only", "--variant", "connector"); err != nil ||
		!strings.Contains(out, "downloading rpmgr 1.4.2 (connector) for linux/"+arch) || !strings.Contains(out, "verified rpmgr 1.4.2") {
		t.Errorf("--variant connector: %v\n%s", err, out)
	}
	if out, err := runGlobal(t, g, "", "", "--verify-only", "--version", "v1.4.2"); err != nil || !strings.Contains(out, "verified rpmgr 1.4.2") {
		t.Errorf("--version v1.4.2: %v\n%s", err, out)
	}
	// With --prerelease the newest release counts, a pre-release too; this fake has no files for it.
	if out, err := runGlobal(t, g, "", "", "--verify-only", "--prerelease"); err == nil || !strings.Contains(out, "of rpmgr 1.5.0-rc.1") {
		t.Errorf("--prerelease: %v\n%s", err, out)
	}
	dir := filepath.Join(t.TempDir(), "keep")
	if out, err := runGlobal(t, g, "1.4.2", "", "--verify-only", "--dir", dir); err != nil {
		t.Errorf("--dir: %v\n%s", err, out)
	} else if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
		t.Errorf("--dir keeps the files: %v", err)
	}

	artifact := "rpmgr-1.4.2-linux-" + arch
	for name, tc := range map[string]struct {
		change func(f map[string][]byte)
		edit   func(st map[string]any, m *release.Manifest)
		want   string
	}{
		"a changed binary": {change: func(f map[string][]byte) { f[artifact] = bytes.Replace(f[artifact], []byte("test"), []byte("TEST"), 1) }, want: "SHA-256 does not match"},
		"a changed manifest": {change: func(f map[string][]byte) {
			f["manifest.json"] = bytes.Replace(f["manifest.json"], []byte(`"seq":87`), []byte(`"seq":88`), 1)
		}, want: "does not verify"},
		"a manifest of the root": {change: func(f map[string][]byte) { f["manifest.json.minisig"] = root.Sign(f["manifest.json"]) }, want: "unknown key"},
		"no build for here":      {edit: func(_ map[string]any, m *release.Manifest) { m.Artifacts[0].Arch = "mips" }, want: "no full build for linux/"},
		"a missing file":         {change: func(f map[string][]byte) { delete(f, "signing-key.json") }, want: "cannot download signing-key.json"},
	} {
		f := files(t, tc.edit)
		if tc.change != nil {
			tc.change(f)
		}
		g.mu.Lock()
		g.files = f
		g.mu.Unlock()
		out, err := runGlobal(t, g, "1.4.2", "", "--verify-only")
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}

// TestGlobal_Refusals: what the global script refuses before it downloads anything.
func TestGlobal_Refusals(t *testing.T) {
	needTools(t)
	g := newGitHub(t)
	g.files = files(t, nil)
	for name, tc := range map[string]struct {
		path string
		args []string
		env  string
		want string
	}{
		"another OS":             {path: stubs(t, map[string]string{"uname": `[ "$1" = -s ] && echo Darwin || echo x86_64`}), want: "rpmgr installs on Linux only; this is Darwin"},
		"another architecture":   {path: stubs(t, map[string]string{"uname": `[ "$1" = -s ] && echo Linux || echo s390x`}), want: "no rpmgr build for linux/s390x"},
		"OpenSSL 1.1":            {path: stubs(t, map[string]string{"openssl": "echo 'OpenSSL 1.1.1w  11 Sep 2023'"}), want: "OpenSSL 3.0 or later is needed"},
		"a bad version":          {args: []string{"--version", "latest"}, want: "is not a release version"},
		"a version with a slash": {args: []string{"--version", "1.4.2/../x"}, want: "is not a release version"},
		"an unknown argument":    {args: []string{"--yes"}, want: "unknown argument --yes"},
		"an unknown variant":     {args: []string{"--variant", "lite"}, want: "--variant must be full or connector"},
	} {
		out, err := runGlobal(t, g, "", tc.path, append([]string{"--verify-only"}, tc.args...)...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
	// A plain-HTTP source is refused.
	b, err := installsh.RenderGlobal("1.4.2", []release.PublicKey{pubkey(t, root)})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", string(b), "install.sh", "--verify-only")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "RPMGR_INSTALL_GITHUB=http://github.example"}
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "must be an https:// URL") {
		t.Errorf("plain HTTP: %v\n%s", err, out)
	}
	// Installing needs root; verifying does not.
	if os.Getuid() != 0 {
		if out, err := runGlobal(t, g, "1.4.2", "", "--no-setup"); err == nil || !strings.Contains(out, "run as root") {
			t.Errorf("not root: %v\n%s", err, out)
		}
	}
	if out, err := runGlobal(t, g, "", "", "--help"); err != nil || !strings.Contains(out, "Usage: sh install.sh") {
		t.Errorf("--help: %v\n%s", err, out)
	}
}

// TestGlobal_Syntax: the global script is valid POSIX shell, pinned or not, and a development
// version is refused.
func TestGlobal_Syntax(t *testing.T) {
	for _, v := range []string{"", "1.4.2", "0.1.0-rc.1"} {
		b, err := installsh.RenderGlobal(v, []release.PublicKey{pubkey(t, root)})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "PINNED='"+v+"'") || strings.Count(string(b), "BEGIN PUBLIC KEY") != 1 {
			t.Errorf("%q: not pinned, or not one root", v)
		}
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = bytes.NewReader(b)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%q: sh -n: %v\n%s", v, err, out)
		}
	}
	if _, err := installsh.RenderGlobal("dev", []release.PublicKey{pubkey(t, root)}); err == nil {
		t.Error("a development version was accepted")
	}
	if _, err := installsh.RenderGlobal("", nil); err == nil {
		t.Error("a script without root keys was written")
	}
}

// TestGlobal_InSync: deploy/install.sh is the global script of this build's release root keys
// (internal/release/roots.go), as go generate ./internal/installsh writes it.
func TestGlobal_InSync(t *testing.T) {
	if release.TestBuild {
		t.Skip("an rpmgrtest build has test root keys")
	}
	want, err := installsh.RenderGlobal("", release.Roots())
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join("..", "..", "deploy", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("deploy/install.sh is out of date: run go generate ./internal/installsh")
	}
	for _, k := range release.Roots() {
		if !strings.Contains(string(got), "root-"+strings.ToLower(hexID(k))+".pem") {
			t.Errorf("deploy/install.sh lacks the root %s", k.IDString())
		}
	}
}

func hexID(k release.PublicKey) string {
	const digits = "0123456789abcdef"
	b := make([]byte, 0, 16)
	for _, c := range k.ID {
		b = append(b, digits[c>>4], digits[c&15])
	}
	return string(b)
}

// TestVariant_KeptOnTheHost (D119): both scripts keep the build a host runs, from its install
// record, else from what its binary reports, full for a binary from before the variants; another
// --variant is refused, and an upgrade that cannot tell which build the host runs asks for one.
func TestVariant_KeptOnTheHost(t *testing.T) {
	needTools(t)
	g := newGitHub(t)
	g.files = files(t, nil)
	s := newServer(t)
	s.files = files(t, nil)
	ctl := []string{"--controller", s.URL, "--verify-only"}
	connBin := "rpmgr 1.4.1 (commit abc, go1.27.2, linux/amd64)\nvariant: connector"
	oldBin := "rpmgr 0.1.0 (commit abc, go1.27.2, linux/amd64)\nrelease root keys:"
	for name, tc := range map[string]struct {
		host   func(hostDirs) hostDirs
		global bool
		args   []string
		want   string // "(full)", "(connector)" or a refusal
	}{
		"controller script, record connector":            {host: func(h hostDirs) hostDirs { return h.withRecord(t, "connector") }, want: "(connector)"},
		"controller script, record connector, --variant": {host: func(h hostDirs) hostDirs { return h.withRecord(t, "connector") }, args: []string{"--variant", "full"}, want: "runs the connector build"},
		"controller script, binary reports connector":    {host: func(h hostDirs) hostDirs { return h.withBinary(t, connBin) }, want: "(connector)"},
		"controller script, a 0.1.0 binary":              {host: func(h hostDirs) hostDirs { return h.withBinary(t, oldBin) }, want: "(full)"},
		"controller script, a 0.1.0 binary, --variant":   {host: func(h hostDirs) hostDirs { return h.withBinary(t, oldBin) }, args: []string{"--variant", "connector"}, want: "runs the full build"},
		"controller script, an unknown recorded variant": {host: func(h hostDirs) hostDirs { return h.withRecord(t, "lite") }, want: "unknown variant lite"},
		"global upgrade, record connector":               {global: true, host: func(h hostDirs) hostDirs { return h.withBinary(t, "").withRecord(t, "connector") }, args: []string{"--upgrade", "--verify-only"}, want: "(connector)"},
		"global upgrade, record connector, --variant":    {global: true, host: func(h hostDirs) hostDirs { return h.withBinary(t, "").withRecord(t, "connector") }, args: []string{"--upgrade", "--variant", "full"}, want: "runs the connector build"},
		"global upgrade, binary reports connector":       {global: true, host: func(h hostDirs) hostDirs { return h.withBinary(t, connBin) }, args: []string{"--upgrade", "--verify-only"}, want: "(connector)"},
		"global upgrade, binary that does not run":       {global: true, host: func(h hostDirs) hostDirs { return h.withBinary(t, "") }, args: []string{"--upgrade"}, want: "cannot tell which build"},
		"global upgrade, no tell, --variant":             {global: true, host: func(h hostDirs) hostDirs { return h.withBinary(t, "") }, args: []string{"--upgrade", "--variant", "connector", "--verify-only"}, want: "(connector)"},
		"global run again, binary reports connector":     {global: true, host: func(h hostDirs) hostDirs { return h.withBinary(t, connBin) }, args: []string{"--verify-only"}, want: "(connector)"},
		"global new host":                                {global: true, host: func(h hostDirs) hostDirs { return h }, args: []string{"--verify-only"}, want: "(full)"},
	} {
		h := tc.host(newHostDirs(t))
		var out string
		var err error
		if tc.global {
			out, err = runGlobalOn(t, h, g, "1.4.2", "", tc.args...)
		} else {
			out, err = runOn(t, h, s, "", append(append([]string{}, ctl...), tc.args...)...)
		}
		if strings.HasPrefix(tc.want, "(") {
			if err != nil || !strings.Contains(out, "downloading rpmgr 1.4.2 "+tc.want) {
				t.Errorf("%s: %v\n%s", name, err, out)
			}
		} else if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}

// TestScripts_HasHandoff: the scripts decide with has_handoff, in shell, which releases get the
// hand-off drop-in, and agree with units.HasHandoff, which the updater uses, on every version.
func TestScripts_HasHandoff(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	script, err := installsh.RenderGlobal("", []release.PublicKey{pubkey(t, root)})
	if err != nil {
		t.Fatal(err)
	}
	_, fn, ok := strings.Cut(string(script), "has_handoff() {")
	fn, _, ok2 := strings.Cut(fn, "\n}\n")
	if !ok || !ok2 {
		t.Fatal("no has_handoff in the global script")
	}
	for _, v := range []string{"0.1.0", "0.2.9", "0.2.0-rc.1", "0.3.0-rc.1", "0.3.0", "0.3.1", "0.10.0", "1.0.0", "12.0.0", "dev", "", "x.3.0"} {
		out, err := exec.Command("sh", "-c", "has_handoff() {"+fn+"\n}\nhas_handoff \"$1\" && echo yes || echo no", "sh", v).Output() //nolint:gosec // G204: a test's own script
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if got, want := strings.TrimSpace(string(out)) == "yes", units.HasHandoff(v); got != want {
			t.Errorf("has_handoff %q = %v; units.HasHandoff = %v", v, got, want)
		}
	}
}
