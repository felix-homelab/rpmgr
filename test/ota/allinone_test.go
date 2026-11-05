// SPDX-License-Identifier: Apache-2.0

//go:build ota

package ota

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	aioOldVer = "0.3.0"
	aioNewVer = "0.4.0-beta.1"
	aioAdmin  = "127.0.0.1:7392"
)

// sampler writes, every 5 s, what the root updater's readiness gate sees of the all-in-one's unit
// (systemctl show), what the admin listener answers and the processes of the unit's cgroup. It
// runs as its own transient unit so that it is not in the all-in-one's cgroup.
const sampler = `#!/bin/sh
mkdir -p /var/log
out=/var/log/ota-samples.txt
exec >>$out 2>&1
end=$(( $(date +%s) + $1 ))
while [ "$(date +%s)" -lt "$end" ]; do
  rzt=$(curl -s -m 30 -o /dev/null -w '%{http_code} %{time_total}' http://` + aioAdmin + `/readyz)
  rz=${rzt% *}; rt=${rzt#* }
  st=$(systemctl show -p ActiveState,SubState,NRestarts,MainPID,Type,StatusText rpmgr-all-in-one | tr '\n' ' ')
  act=$(systemctl show -p ActiveState --value rpmgr-all-in-one)
  # The updater's gates: ActiveState is active, no restart (NRestarts unchanged), /readyz is 200.
  if [ "$act" = active ] && [ "$rz" = 200 ]; then v=pass; else v="WAIT(unit=$act readyz=$rz)"; fi
  echo "== $(date +%T) gate=$v readyz=$rz time=$rt"
  echo "$st"
  cg=$(systemctl show -p ControlGroup --value rpmgr-all-in-one)
  for p in $(cat /sys/fs/cgroup$cg/cgroup.procs 2>/dev/null); do
    echo "  $p $(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null)"
  done
  sleep 5
done
`

// watcher logs every change of /readyz's answer, polled every 0.2 s, to see what the updater's
// two-second polls can miss.
const watcher = `#!/bin/sh
exec >>/var/log/ota-readyz.txt 2>&1
end=$(( $(date +%s) + $1 )); last=
while [ "$(date +%s)" -lt "$end" ]; do
  ct=$(curl -s -m 30 -o /dev/null -w '%{http_code} %{time_total}' http://` + aioAdmin + `/readyz)
  c=${ct% *}; t=${ct#* }
  [ "$c" = "$last" ] || { echo "$(date +%T.%N | cut -c1-12) readyz=$c time=$t active=$(systemctl show -p ActiveState --value rpmgr-all-in-one)"; last=$c; }
  sleep 0.2
done
`

// maxTime is the largest "time=<seconds>" in the sampler's lines (curl's time_total of /readyz).
func maxTime(samples string) float64 {
	var m float64
	for _, f := range regexp.MustCompile(`time=([0-9.]+)`).FindAllStringSubmatch(samples, -1) {
		if v, err := strconv.ParseFloat(f[1], 64); err == nil {
			m = max(m, v)
		}
	}
	return m
}

// testAllInOneUpdate (issue 1138) runs the previous release's root updater on a real all-in-one
// under systemd with the socket hand-off drop-in (Type=notify, NotifyAccess=all), routes and open
// connections, and the release of this tree staged. The updater's readiness gate asks systemd and
// the admin listener for up to five minutes; it must see the new process active, not restarted
// and ready, and must not roll back. Every five seconds of the window are logged.
func testAllInOneUpdate(t *testing.T) {
	h := newAIOHost(t)
	h.exec(`systemd-run --unit=svc /b/e2eclient serve -listen 127.0.0.1:7007 -udp 127.0.0.1:7008 >/dev/null`)
	h.setupAIO()
	for i := 1; i <= 3; i++ {
		h.exec(`systemd-run --unit=hold` + string(rune('0'+i)) + ` /b/e2eclient hold -addr 127.0.0.1:21001 -duration 420s -every 1s >/dev/null`)
	}
	h.exec(`systemd-run --unit=probe /b/e2eclient probe -tcp 127.0.0.1:21001 -udpaddr 127.0.0.1:21002 -duration 420s >/dev/null`)
	h.exec(`systemd-run --unit=sampler /bin/sh /b/sampler 400 >/dev/null; systemd-run --unit=watcher /bin/sh /b/watcher 400 >/dev/null`)
	time.Sleep(6 * time.Second)

	// As the path unit runs it: the sandbox of rpmgr-update.service, not a root shell.
	h.stage(aioNewVer)
	out := h.exec(`systemctl start rpmgr-update.service; echo "start: $?"; journalctl -u rpmgr-update.service --no-pager -o cat | cut -c1-300; cat /run/rpmgr-update/status.json; echo; echo "version: $(/usr/local/bin/rpmgr version)"`)
	samples := h.exec("sleep 10; cat /var/log/ota-samples.txt; echo; cat /var/log/ota-readyz.txt; echo; journalctl -u rpmgr-all-in-one --no-pager -o cat | cut -c1-260 | grep -v 'data session' | tail -n 60; echo; systemctl show -p ActiveState,SubState,NRestarts,MainPID,Type rpmgr-all-in-one; systemctl status rpmgr-all-in-one --no-pager -l | head -n 20")
	t.Logf("apply:\n%s\nsamples:\n%s", out, samples)
	t.Logf("max /readyz latency in the samples: %.3f s over %d samples", maxTime(samples), strings.Count(samples, "gate="))
	for _, want := range []string{"start: 0", "version: rpmgr " + aioNewVer, `"state":"updated"`} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "rolled back") || strings.Contains(out, "rollback") {
		t.Errorf("the updater rolled back:\n%s", out)
	}
	if got := h.exec("curl -s -o /dev/null -w '%{http_code}' http://" + aioAdmin + "/readyz"); got != "200" {
		t.Errorf("/readyz answers %s after the update", got)
	}
}

// newAIOHost starts a systemd container holding the previous release's build (OTA_FROM, by
// default the tag v0.3.0) and the staged assets of this tree's build.
func newAIOHost(t *testing.T) *host {
	t.Helper()
	mustBuildImage(t)
	from := os.Getenv("OTA_FROM")
	if from == "" {
		from = "v" + aioOldVer
	}
	src := t.TempDir()
	if out, err := exec.Command("sh", "-c", `git -C ../.. archive "$1" | tar -x -C "$2"`, "sh", from, src).CombinedOutput(); err != nil { //nolint:gosec // G204: the test's own revision
		// Never a silent pass: the case needs the previous release's source.
		t.Fatalf("the previous release %s is not in this checkout (fetch the tag, as the ops job does, or set OTA_FROM to a revision): %v\n%s", from, err, out)
	}
	bins := t.TempDir()
	buildIn(t, src, filepath.Join(bins, "rpmgr-"+aioOldVer), "./cmd/rpmgr", aioOldVer)
	build(t, filepath.Join(bins, "rpmgr-"+aioNewVer), "./cmd/rpmgr", aioNewVer)
	build(t, filepath.Join(bins, "e2eclient"), "./test/e2e/e2eclient", "")
	crt, key := selfSigned(t)
	mustWrite(t, filepath.Join(bins, "web.crt"), crt)
	mustWrite(t, filepath.Join(bins, "web.key"), key)
	mustWrite(t, filepath.Join(bins, "sampler"), []byte(sampler))
	mustWrite(t, filepath.Join(bins, "watcher"), []byte(watcher))
	assets := t.TempDir()
	writeAssets(t, filepath.Join(assets, aioNewVer), aioNewVer, 2, filepath.Join(bins, "rpmgr-"+aioNewVer))
	out := run(t, "run", "-d", "--rm", "--privileged", "--cgroupns=host",
		"--tmpfs", "/var:rw,size=512m", "--tmpfs", "/run:rw,size=64m",
		"-v", assets+":/t:ro", "-v", bins+":/b:ro", image, "/sbin/init")
	id := strings.TrimSpace(out)
	t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "-f", id).CombinedOutput() })
	h := &host{t: t, id: id, assets: assets, bins: bins}
	h.waitSystemd()
	return h
}

// buildIn builds the rpmgr command of the tree in dir, at version.
func buildIn(t *testing.T, dir, out, pkg, version string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-tags", "rpmgrtest", "-ldflags",
		"-X github.com/felix-homelab/rpmgr/internal/version.Version="+version, "-o", out, pkg) //nolint:gosec // G204: the test's own arguments
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s in %s: %v\n%s", pkg, dir, err, b)
	}
}

// setupAIO installs the previous release as an all-in-one with its unit and hand-off drop-in, the
// updater's record, two routes and the policy, and starts it.
func (h *host) setupAIO() {
	h.t.Helper()
	h.exec(`
set -e
useradd --system --home-dir /var/lib/rpmgr --shell /usr/sbin/nologin rpmgr
mkdir -p /etc/rpmgr /var/lib/rpmgr/update /var/lib/rpmgr-update /usr/local/bin
chown -R rpmgr:rpmgr /var/lib/rpmgr
install -m 0755 /b/rpmgr-` + aioOldVer + ` /usr/local/bin/rpmgr
install -m 0600 -o rpmgr -g rpmgr /b/web.crt /b/web.key /var/lib/rpmgr/
head -c 32 /dev/urandom | base64 > /var/lib/rpmgr/kek
chown rpmgr:rpmgr /var/lib/rpmgr/kek; chmod 600 /var/lib/rpmgr/kek
cat > /etc/rpmgr/all-in-one.yaml <<EOF
version: 1
public_url: https://localhost:9543
listen: {tcp: ":9543", udp: ":9543", http: "", admin: "` + aioAdmin + `"}
database: {dsn: /var/lib/rpmgr/controller.db}
kek: {source: file, path: /var/lib/rpmgr/kek}
tls: {cert_file: /var/lib/rpmgr/web.crt, key_file: /var/lib/rpmgr/web.key}
state_dir: /var/lib/rpmgr
policy_file: /etc/rpmgr/policy.yaml
EOF
cat > /var/lib/rpmgr/seed.yaml <<EOF
version: 1
public_url: https://localhost:9543
listen: {https: ":9543", http: "", admin: "` + aioAdmin + `"}
database: {dsn: /var/lib/rpmgr/controller.db}
kek: {source: file, path: /var/lib/rpmgr/kek}
EOF
chown rpmgr:rpmgr /var/lib/rpmgr/seed.yaml
printf 'version: 1\nallow_targets:\n  - cidr: 127.0.0.1/32\n    ports: [7007, 7008]\nupdate_channel: prerelease\n' > /etc/rpmgr/policy.yaml
su rpmgr -s /bin/sh -c 'rpmgr all-in-one init --config /etc/rpmgr/all-in-one.yaml' >/dev/null
for v in "route --name tcp-auto --port 21001 --target 127.0.0.1:7007" "udp-route --name udp-auto --port 21002 --target 127.0.0.1:7008"; do
  su rpmgr -s /bin/sh -c "RPMGR_TESTSEED_ORG=default rpmgr testseed $v --group default --connector local --config /var/lib/rpmgr/seed.yaml" >/dev/null
done
rm /var/lib/rpmgr/seed.yaml
# The unit and the hand-off drop-in as the previous release's install script writes them; the
# encrypted credential of the KEK is replaced by the key file above.
rpmgr systemd-unit --bin /usr/local/bin/rpmgr all-in-one | grep -v LoadCredentialEncrypted > /etc/systemd/system/rpmgr-all-in-one.service
mkdir -p /etc/systemd/system/rpmgr-all-in-one.service.d
rpmgr systemd-unit --drop-in all-in-one > /etc/systemd/system/rpmgr-all-in-one.service.d/handoff.conf
rpmgr updater install --state /var/lib/rpmgr-update --path /usr/local/bin/rpmgr --role all-in-one --seq 1 --floor ` + aioOldVer + ` --units /etc/systemd/system
systemctl daemon-reload
systemctl start rpmgr-all-in-one.service
for i in $(seq 1 100); do curl -fsS http://` + aioAdmin + `/readyz >/dev/null 2>&1 && break; sleep 0.2; done
curl -fsS http://` + aioAdmin + `/readyz
`)
}

// selfSigned returns a certificate for localhost and its key, PEM encoded.
func selfSigned(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
}
