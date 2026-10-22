// SPDX-License-Identifier: Apache-2.0

//go:build ota

// Package ota runs the root updater on a real systemd host in a container, with the binary's
// directory and /var on different filesystems (docs/12-testing-and-quality.md, "Continuous
// integration"; slice 2.11). Run with check-ota.sh; needs Docker.
package ota

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/release/releasetest"
)

const (
	image  = "rpmgr-ota-test"
	oldVer = "0.2.0"
	newVer = "0.3.0"
)

var (
	imageOnce sync.Once
	imageErr  error
)

// TestOTA (docs/12; VB-07) runs the root updater on real systemd: the install crosses filesystems
// because /var is a tmpfs, the service user cannot write the binary or the updater's state, a
// replayed old manifest is refused, and a symlink planted in the staging directory is refused.
func TestOTA(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is needed")
	}
	t.Run("cross-filesystem install and permissions", testInstall)
	t.Run("replayed manifest refused", testReplay)
	t.Run("hostile staging refused", testHostile)
}

func testInstall(t *testing.T) {
	h := newHost(t)
	out := h.setup()
	out += h.apply("0.3.0")
	for _, want := range []string{
		"apply: 0",
		"version: rpmgr " + newVer,
		"var: tmpfs",
		"binary dir: not tmpfs",
		`"result":"updated"`,
		"binary: protected",
		"state: protected",
		"status: protected",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
}

func testReplay(t *testing.T) {
	h := newHost(t)
	h.setup()
	if out := h.apply("0.3.0"); !strings.Contains(out, "apply: 0") {
		t.Fatalf("the new release did not install:\n%s", out)
	}
	out := h.apply(oldVer)
	for _, want := range []string{"apply: 1", `"result":"refused"`, "version: rpmgr " + newVer} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
}

func testHostile(t *testing.T) {
	h := newHost(t)
	h.setup()
	// The service user replaces the staged artifact with a symbolic link, as a compromised agent
	// could; the updater refuses the staging rather than reading through it.
	h.exec("su rpmgr -s /bin/sh -c 'rm /var/lib/rpmgr/update/rpmgr-" + newVer + "-linux-amd64 && ln -s /etc/passwd /var/lib/rpmgr/update/rpmgr-" + newVer + "-linux-amd64'")
	out := h.apply("")
	for _, want := range []string{"apply: 1", `"result":"refused"`, "version: rpmgr " + oldVer} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
}

// host is one systemd container with the old binary installed.
type host struct {
	t      *testing.T
	id     string
	assets string
	bins   string
}

func newHost(t *testing.T) *host {
	t.Helper()
	mustBuildImage(t)
	bins := t.TempDir()
	build(t, filepath.Join(bins, "rpmgr-"+oldVer), "./cmd/rpmgr", oldVer)
	build(t, filepath.Join(bins, "role-ready"), "./test/ota/ready", "")
	assets := t.TempDir()
	writeAssets(t, filepath.Join(assets, oldVer), oldVer, 1, filepath.Join(bins, "rpmgr-"+oldVer))
	writeAssets(t, filepath.Join(assets, newVer), newVer, 2, filepath.Join(bins, "rpmgr-"+newVer))
	out := run(t, "run", "-d", "--rm", "--privileged", "--cgroupns=host",
		"--tmpfs", "/var:rw,size=256m", "--tmpfs", "/run:rw,size=64m",
		"-v", assets+":/t:ro", "-v", bins+":/b:ro", image, "/sbin/init")
	id := strings.TrimSpace(out)
	if id == "" {
		t.Fatal("docker run returned no container")
	}
	t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "-f", id).CombinedOutput() })
	h := &host{t: t, id: id, assets: assets, bins: bins}
	h.waitSystemd()
	return h
}

func (h *host) exec(script string) string {
	h.t.Helper()
	return run(h.t, "exec", h.id, "sh", "-c", script)
}

// setup installs the old binary and the updater's record and units, and starts the role service.
func (h *host) setup() string {
	h.t.Helper()
	return h.exec(`
set -e
useradd --system --home-dir /var/lib/rpmgr --shell /usr/sbin/nologin rpmgr
mkdir -p /etc/rpmgr /var/lib/rpmgr/update /var/lib/rpmgr-update /usr/local/bin
install -m 0755 /b/rpmgr-` + oldVer + ` /usr/local/bin/rpmgr
install -m 0755 /b/role-ready /usr/local/bin/role-ready
chown -R rpmgr:rpmgr /var/lib/rpmgr
printf 'listen:\n  admin: "127.0.0.1:7384"\n' > /etc/rpmgr/connector.yaml
/usr/local/bin/rpmgr updater install --state /var/lib/rpmgr-update --path /usr/local/bin/rpmgr --role connector --seq 1 --floor ` + oldVer + ` --units /etc/systemd/system
printf '%s\n' '[Unit]' 'Description=rpmgr connector (test)' 'After=network.target' '[Service]' 'ExecStart=/usr/local/bin/role-ready -addr 127.0.0.1:7384' 'Restart=always' '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/rpmgr-connector.service
systemctl daemon-reload
systemctl enable --now rpmgr-connector.service
for i in $(seq 1 50); do curl -fsS http://127.0.0.1:7384/readyz >/dev/null 2>&1 && break; sleep 0.1; done
echo setup: done
`)
}

// apply stages a release's files as the service user and runs the updater. An empty version
// stages nothing: the test has staged its own, hostile files.
func (h *host) apply(version string) string {
	h.t.Helper()
	if version != "" {
		h.exec("su rpmgr -s /bin/sh -c 'cp /t/" + version + "/* /var/lib/rpmgr/update/'")
	}
	return h.exec(`
set +e
/usr/local/bin/rpmgr updater apply --staged /var/lib/rpmgr/update --state /var/lib/rpmgr-update; echo "apply: $?"
echo "version: $(/usr/local/bin/rpmgr version)"
echo "var: $(findmnt -no FSTYPE /var)"
[ "$(findmnt -no FSTYPE /var)" = tmpfs ] || echo "var: not tmpfs"
[ "$(findmnt -no FSTYPE /usr/local/bin)" = tmpfs ] && echo "binary dir: tmpfs" || echo "binary dir: not tmpfs"
echo "status: $(cat /run/rpmgr-update/status.json 2>/dev/null)"
su rpmgr -s /bin/sh -c 'echo x >>/usr/local/bin/rpmgr' 2>/dev/null && echo "binary: writable" || echo "binary: protected"
su rpmgr -s /bin/sh -c 'echo x >>/var/lib/rpmgr-update/state.json' 2>/dev/null && echo "state: writable" || echo "state: protected"
su rpmgr -s /bin/sh -c 'echo x >>/run/rpmgr-update/status.json' 2>/dev/null && echo "status: writable" || echo "status: protected"
`)
}

func (h *host) waitSystemd() {
	h.t.Helper()
	for i := 0; i < 60; i++ {
		out := strings.TrimSpace(h.exec("systemctl is-system-running 2>/dev/null || true"))
		if out == "running" || out == "degraded" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	h.t.Fatal("systemd did not start")
}

func mustBuildImage(t *testing.T) {
	t.Helper()
	imageOnce.Do(func() {
		cmd := exec.Command("docker", "build", "-t", image, ".")
		if out, err := cmd.CombinedOutput(); err != nil {
			imageErr = fmt.Errorf("building the test image: %w\n%s", err, out)
		}
	})
	if imageErr != nil {
		t.Fatal(imageErr)
	}
}

// build builds a linux/amd64 binary of the repository at version; "" for a development build.
func build(t *testing.T, out, pkg, version string) {
	t.Helper()
	args := []string{"build", "-trimpath", "-buildvcs=false"}
	if strings.HasSuffix(pkg, "cmd/rpmgr") {
		args = append(args, "-tags", "rpmgrtest", "-ldflags",
			"-X github.com/felix-homelab/rpmgr/internal/version.Version="+version)
	}
	args = append(args, "-o", out, pkg)
	cmd := exec.Command("go", args...)
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", pkg, err, b)
	}
}

// writeAssets writes the signed files of a release of version, with the binary at artifact as its
// full linux/amd64 artifact, and returns its name.
func writeAssets(t *testing.T, dir, version string, seq uint64, artifact string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	a := release.Artifact{OS: "linux", Arch: "amd64", Variant: "full", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
	name := release.ArtifactName(version, a)
	m := release.Manifest{Seq: seq, Version: version, Floor: oldVer, Channel: release.Stable,
		IssuedAt: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), Artifacts: []release.Artifact{a}}
	man, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	signing := releasetest.Key("ota signing")
	root := releasetest.Key("root 1")
	st := []byte(`{"statement":1,"signer":"` + signing.Public() + `","not_before":"2026-10-01T00:00:00Z","not_after":"2027-10-01T00:00:00Z"}`)
	mustWrite(t, filepath.Join(dir, release.StatementFile), st)
	mustWrite(t, filepath.Join(dir, release.StatementSigFile), root.Sign(st))
	mustWrite(t, filepath.Join(dir, release.ManifestFile), man)
	mustWrite(t, filepath.Join(dir, release.ManifestSigFile), signing.Sign(man))
	mustWrite(t, filepath.Join(dir, name), body)
	return name
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
