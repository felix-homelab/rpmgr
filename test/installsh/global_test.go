// SPDX-License-Identifier: Apache-2.0

//go:build installsh

package installsh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/installsh"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
)

// globalStub is the "binary" of the global script's test release: it records its arguments, prints
// a version, and has a setup command only once /tmp/has-setup exists, as a release with it would.
const globalStub = `#!/bin/sh
echo "argv: $*" >>/tmp/rpmgr-calls
case "$1 ${2-}" in
  "version --verbose") echo "rpmgr 1.4.2 (stub)"; echo "release root keys:" ;;
  "setup --help") [ -f /tmp/has-setup ] && exit 0; echo "rpmgr: unknown command setup" >&2; exit 2 ;;
esac
`

// TestGlobalInstall runs the global install script, deploy/install.sh as go generate writes it but
// with test root keys, in containers of the supported distributions against a fake of GitHub
// (docs/10-operations.md, "Install paths"): it installs the binary, the user and the directories,
// does so again without touching the configuration, and refuses a changed binary or manifest, a
// host it has no build for, and a host without OpenSSL 3.
func TestGlobalInstall(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is needed")
	}
	root, signing := releasetest.Key("global root"), releasetest.Key("global signing")
	rootKey, _ := release.ParsePublicKey(root.Public())
	now := time.Now().UTC()
	st, _ := json.Marshal(release.Statement{Statement: 1, SigningKey: signing.Public(), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)})
	// rel is release v of the stub, with its binary changed afterwards by broken, if set.
	rel := func(v string, broken func(f map[string][]byte)) map[string][]byte {
		sum := sha256.Sum256([]byte(globalStub))
		man, _ := json.Marshal(release.Manifest{Seq: 5, Version: v, Floor: v, Channel: release.Stable, IssuedAt: now,
			Artifacts: []release.Artifact{{OS: "linux", Arch: "amd64", Variant: "full", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(globalStub))}}})
		f := map[string][]byte{"signing-key.json": st, "signing-key.json.minisig": root.Sign(st), "manifest.json": man,
			"manifest.json.minisig": signing.Sign(man), "rpmgr-" + v + "-linux-amd64": []byte(globalStub)}
		if broken != nil {
			broken(f)
		}
		return f
	}
	releases := map[string]map[string][]byte{
		"1.4.2": rel("1.4.2", nil),
		"1.4.3": rel("1.4.3", func(f map[string][]byte) { // a changed binary
			f["rpmgr-1.4.3-linux-amd64"] = bytes.Replace(f["rpmgr-1.4.3-linux-amd64"], []byte("stub"), []byte("evil"), 1)
		}),
		"1.4.4": rel("1.4.4", func(f map[string][]byte) { // a changed manifest
			f["manifest.json"] = bytes.Replace(f["manifest.json"], []byte(`"seq":5`), []byte(`"seq":6`), 1)
		}),
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/felix-homelab/rpmgr/releases/latest" {
			_, _ = w.Write([]byte(`{"tag_name": "v1.4.2"}`))
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/felix-homelab/rpmgr/releases/download/v")
		v, name, _ := strings.Cut(rest, "/")
		if b, found := releases[v][name]; ok && found {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)

	script, err := installsh.RenderGlobal("", []release.PublicKey{rootKey})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("install.sh", string(script), 0o644)
	write("ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})), 0o644)
	write("s390x/uname", "#!/bin/sh\n[ \"$1\" = -s ] && echo Linux || echo s390x\n", 0o755)
	sum := sha256.Sum256([]byte(globalStub))

	// The test CA joins the system's trust store, which curl and wget both read.
	const trustDebian = "cp /t/ca.pem /usr/local/share/ca-certificates/rpmgr-test.crt && update-ca-certificates >/dev/null 2>&1"
	const trustRocky = "cp /t/ca.pem /etc/pki/ca-trust/source/anchors/rpmgr-test.pem && update-ca-trust"
	const apt = "apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "
	env := "export RPMGR_INSTALL_GITHUB=" + srv.URL + " RPMGR_INSTALL_API=" + srv.URL
	for _, d := range []struct {
		name, image, prepare string
		refusals             bool   // also check what the script refuses
		fail                 string // the whole run must fail with this
	}{
		{name: "debian-12", image: image("debian-12"), prepare: apt + "curl openssl ca-certificates >/dev/null && " + trustDebian, refusals: true},
		{name: "debian-12-wget", image: image("debian-12"), prepare: apt + "wget openssl ca-certificates >/dev/null && " + trustDebian},
		{name: "ubuntu-24.04", image: image("ubuntu-24.04"), prepare: apt + "curl openssl ca-certificates >/dev/null && " + trustDebian},
		{name: "rocky-9", image: image("rocky-9"), prepare: trustRocky},
		// ca-certificates pulls in openssl, so the binary is moved out of the way afterwards.
		{name: "debian-12-no-openssl", image: image("debian-12"), prepare: apt + "curl ca-certificates >/dev/null && " + trustDebian +
			" && mv /usr/bin/openssl /usr/bin/openssl.gone", fail: "openssl is needed"},
		{name: "ubuntu-20.04", image: image("ubuntu-20.04"), prepare: apt + "curl openssl ca-certificates >/dev/null && " + trustDebian, fail: "OpenSSL 3.0 or later is needed"},
	} {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
			defer cancel()
			refusals := ""
			if d.refusals {
				refusals = `
				sh /t/install.sh --version 1.4.3 --no-setup; echo "exit changed binary: $?"
				sh /t/install.sh --version 1.4.4 --no-setup; echo "exit changed manifest: $?"
				PATH=/t/s390x:$PATH sh /t/install.sh --no-setup; echo "exit s390x: $?"
				[ -e /usr/local/bin/rpmgr ] && echo "INSTALLED AFTER A REFUSAL"`
			}
			out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "host", "-v", dir+":/t:ro", d.image, "sh", "-c",
				d.prepare+" && "+env+refusals+`
				sh /t/install.sh --no-setup; echo "exit first: $?"
				echo "keep: me" >/etc/rpmgr/all-in-one.yaml
				sh /t/install.sh; echo "exit again: $?"
				touch /tmp/has-setup
				sh /t/install.sh; echo "exit with setup: $?"
				echo "== user"; id rpmgr
				echo "== owner"; stat -c '%n %U %a' /etc/rpmgr /var/lib/rpmgr /usr/local/bin/rpmgr
				echo "== config"; cat /etc/rpmgr/all-in-one.yaml
				echo "== calls"; cat /tmp/rpmgr-calls
				echo "== binary"; sha256sum /usr/local/bin/rpmgr | cut -d' ' -f1`).CombinedOutput()
			text := string(out)
			if d.fail != "" {
				if !strings.Contains(text, d.fail) || !strings.Contains(text, "exit first: 1") {
					t.Fatalf("not refused with %q:\n%s", d.fail, text)
				}
				return
			}
			if err != nil {
				t.Fatalf("docker: %v\n%s", err, text)
			}
			want := []string{
				"downloading rpmgr 1.4.2 for linux/amd64", "verified rpmgr 1.4.2 (manifest 5)", "installed rpmgr 1.4.2 to /usr/local/bin/rpmgr",
				"exit first: 0", "exit again: 0", "exit with setup: 0",
				"next: set up this host's role with: sudo rpmgr setup",
				"rpmgr 1.4.2 has no setup command",
				"/etc/rpmgr root 755", "/var/lib/rpmgr rpmgr 750", "/usr/local/bin/rpmgr root 755",
				"== config\nkeep: me\n", "argv: version --verbose", "argv: setup --help",
				"== binary\n" + hex.EncodeToString(sum[:]),
			}
			if d.refusals {
				want = append(want, "SHA-256 does not match", "exit changed binary: 1", "does not verify", "exit changed manifest: 1",
					"no rpmgr build for linux/s390x", "exit s390x: 1")
			}
			for _, w := range want {
				if !strings.Contains(text, w) {
					t.Errorf("no %q in:\n%s", w, text)
				}
			}
			for _, never := range []string{"INSTALLED AFTER A REFUSAL", "Run rpmgr setup now?"} {
				if strings.Contains(text, never) {
					t.Errorf("%q in:\n%s", never, text)
				}
			}
		})
	}
}
