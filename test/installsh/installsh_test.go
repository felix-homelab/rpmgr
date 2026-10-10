// SPDX-License-Identifier: Apache-2.0

//go:build installsh

// Package installsh runs the controller's /install.sh in containers of the supported
// distributions (docs/10-operations.md, "Supported platforms"; VB-15): it installs a connector
// from a test release whose binary is a stub that records how it is called, under a stub
// systemctl, and checks what the script wrote. Run with check-install.sh; needs Docker.
package installsh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
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

// stub is the "binary" of the test release: it records its arguments and whether the token is in
// its environment, and plays the parts of rpmgr the script uses.
const stub = `#!/bin/sh
echo "argv: $*" >>/tmp/rpmgr-calls
env | grep -q not-a-real-token && echo "token in env" >>/tmp/rpmgr-calls
case $1 in
  enroll) mkdir -p /var/lib/rpmgr/identity && echo chain >/var/lib/rpmgr/identity/chain.pem ;;
  systemd-unit) echo "[Service]"; echo "ExecStart=$3 $4" ;;
  policy) echo "  - target $5" >>/tmp/rpmgr-policy ;;
esac
`

const systemctl = `#!/bin/sh
echo "systemctl $*" >>/tmp/systemctl-calls
`

// Distributions with their package commands; Ubuntu 20.04 has OpenSSL 1.1, which the script must
// refuse.
var distros = []struct {
	name, image, prepare string
	oldOpenSSL           bool
}{
	{"debian-12", "debian@sha256:2c037a04925515fdd6ea85ea14a682d0e79931f5e9f5d07b6dbfc6ba12f9e858", apt, false},
	{"debian-13", "debian@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5", apt, false},
	{"ubuntu-22.04", "ubuntu@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401", apt, false},
	{"ubuntu-24.04", "ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55", apt, false},
	// The image has OpenSSL 3 and curl; no package install, whose mirrors once hung for 15 min.
	{"rocky-9", "rockylinux/rockylinux@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f", "true", false},
	{"ubuntu-20.04", "ubuntu@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214", apt, true},
}

const apt = "apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl openssl ca-certificates >/dev/null"

func TestInstall(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is needed")
	}
	root, signing := releasetest.Key("installsh root"), releasetest.Key("installsh signing")
	rootKey, _ := release.ParsePublicKey(root.Public())
	now := time.Now().UTC()
	st, _ := json.Marshal(release.Statement{Statement: 1, SigningKey: signing.Public(), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)})
	sum := sha256.Sum256([]byte(stub))
	man, _ := json.Marshal(release.Manifest{Seq: 87, Version: "1.4.2", Floor: "1.4.0", Channel: release.Stable, IssuedAt: now,
		Artifacts: []release.Artifact{{OS: "linux", Arch: "amd64", Variant: "full", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(stub))}}})
	files := map[string][]byte{"signing-key.json": st, "signing-key.json.minisig": root.Sign(st), "manifest.json": man,
		"manifest.json.minisig": signing.Sign(man), "rpmgr-1.4.2-linux-amd64": []byte(stub)}
	script, err := installsh.Render("1.4.2", []release.PublicKey{rootKey})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := files[strings.TrimPrefix(r.URL.Path, "/dl/1.4.2/")]; ok {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close) // after the parallel subtests, which run once this function returns

	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("install.sh", string(script), 0o644)
	write("ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})), 0o644)
	write("systemctl", systemctl, 0o755)
	write("token", "not-a-real-token-value\n", 0o600)

	// The connector's admin port is taken, as by another program; the script must pick the next.
	busy, err := net.Listen("tcp", "127.0.0.1:7383")
	if err != nil {
		t.Fatalf("port 7383 for the test: %v", err)
	}
	t.Cleanup(func() { _ = busy.Close() })

	for _, d := range distros {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
			defer cancel()
			out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "host", "-v", dir+":/t:ro",
				"-e", "CURL_CA_BUNDLE=/t/ca.pem", d.image, "sh", "-c", d.prepare+` &&
				echo "== openssl: $(openssl version)" &&
				cp /t/systemctl /usr/local/sbin/systemctl && cp /t/token /root/token && chmod 0600 /root/token &&
				sh /t/install.sh --controller `+srv.URL+` --ca-pin sha256:pin --allow-target 10.0.0.5:5432 --allow-target /run/app.sock \
				  --token-file /root/token; echo "exit: $?"
				for f in /etc/rpmgr/connector.yaml /etc/rpmgr/policy.yaml /var/lib/rpmgr-update/install.json \
				  /var/lib/rpmgr-update/state.json /etc/sysctl.d/60-rpmgr.conf /etc/systemd/system/rpmgr-connector.service \
				  /tmp/rpmgr-calls /tmp/rpmgr-policy /tmp/systemctl-calls; do echo "== $f"; cat "$f" 2>&1; done
				echo "== owner"; stat -c '%U %a' /var/lib/rpmgr/identity /var/lib/rpmgr /var/lib/rpmgr-update /usr/local/bin/rpmgr
				echo "== binary"; openssl dgst -sha256 -r /usr/local/bin/rpmgr | cut -d' ' -f1`).CombinedOutput()
			text := string(out)
			if i := strings.Index(text, "== openssl: "); i >= 0 {
				t.Logf("%s: %s", d.name, strings.SplitN(text[i:], "\n", 2)[0])
			}
			if d.oldOpenSSL {
				if !strings.Contains(text, "OpenSSL 3.0 or later is needed") || !strings.Contains(text, "exit: 1") {
					t.Fatalf("OpenSSL 1.1 was not refused:\n%s", text)
				}
				return
			}
			if err != nil || !strings.Contains(text, "exit: 0") {
				t.Fatalf("install: %v\n%s", err, text)
			}
			for _, want := range []string{
				"verified rpmgr 1.4.2 (manifest 87)",
				"endpoints: ['" + srv.URL + "']", "admin: '127.0.0.1:7384'", // the next free port
				"auto_update: auto", "update_channel: stable", // the update keys, always explicit
				`{"method":"script","path":"/usr/local/bin/rpmgr","variant":"full","role":"connector"}`,
				`{"seq":87,"floor":"1.4.2"}`,
				"argv: policy allow-target --no-reload -- 10.0.0.5:5432", "argv: policy allow-target --no-reload -- /run/app.sock",
				"argv: enroll --controller " + srv.URL + " --ca-pin sha256:pin --token-file /root/token",
				"argv: systemd-unit --bin /usr/local/bin/rpmgr connector",
				"systemctl daemon-reload", "systemctl enable --now rpmgr-connector",
				"== owner\nrpmgr ", "\nrpmgr 750\nroot 700\nroot 755\n", "== binary\n" + hex.EncodeToString(sum[:]),
			} {
				if !strings.Contains(text, want) {
					t.Errorf("no %q in:\n%s", want, text)
				}
			}
			for _, never := range []string{"not-a-real-token-value", "token in env"} {
				if strings.Contains(text, never) {
					t.Errorf("the token reached argv or the environment:\n%s", text)
				}
			}
		})
	}
}
