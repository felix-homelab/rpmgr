// SPDX-License-Identifier: Apache-2.0

//go:build images

// Package images tests the OCI image ghcr.io/felix-homelab/rpmgr (docs/10-operations.md,
// "Install") as the Dockerfile builds it from release artifacts: on every released platform
// it runs the binary as the nonroot user without a shell, and every role starts and looks for its
// boot file; on this host's platform an all-in-one, which runs the controller and a gateway, is
// initialised and run as the nonroot user and serves on ports 80 and 443 published by Docker. Run
// with check-images.sh; needs Docker with buildx, and QEMU user-mode emulation for the platforms
// other than this host's, without which they are only built unless REQUIRE_EMULATION=1.
package images

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// nonroot is the user of the distroless nonroot images.
const nonroot = "65532"

// platform is the OCI platform of a release architecture, as RELEASE_ARCHES names it.
func platform(arch string) string {
	if arch == "arm" {
		return "linux/arm/v7"
	}
	return "linux/" + arch
}

func docker(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func must(t *testing.T, args ...string) string {
	t.Helper()
	out, err := docker(t, args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// artifacts returns the directory of release artifacts and their version: RPMGR_IMAGE_ARTIFACTS
// and RPMGR_IMAGE_VERSION, or binaries built here without the web UI.
func artifacts(t *testing.T, arches []string) (string, string) {
	t.Helper()
	if dir := os.Getenv("RPMGR_IMAGE_ARTIFACTS"); dir != "" {
		return dir, os.Getenv("RPMGR_IMAGE_VERSION")
	}
	dir, version := t.TempDir(), "0.0.0-images"
	for _, arch := range arches {
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-X github.com/felix-homelab/rpmgr/internal/version.Version="+version,
			"-o", filepath.Join(dir, "rpmgr-"+version+"-linux-"+arch), "../../cmd/rpmgr")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch, "GOARM=7")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build for %s: %v\n%s", arch, err, out)
		}
	}
	return dir, version
}

func TestImage(t *testing.T) {
	arches := strings.Fields(os.Getenv("RPMGR_RELEASE_ARCHES"))
	if len(arches) == 0 {
		t.Fatal("RPMGR_RELEASE_ARCHES is not set; run .github/scripts/check-images.sh")
	}
	dir, version := artifacts(t, arches)
	dockerfile, err := filepath.Abs("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	for _, arch := range arches {
		image := "rpmgr-images-test:" + arch + "-" + hex.EncodeToString(suffix)
		must(t, "buildx", "build", "--quiet", "--platform", platform(arch), "--build-arg", "VERSION="+version, "-f", dockerfile,
			"--load", "-t", image, dir)
		t.Cleanup(func() { _, _ = docker(t, "image", "rm", image) })
		t.Run(arch, func(t *testing.T) {
			if cfg := must(t, "image", "inspect", "-f", "{{.Config.User}} {{json .Config.Entrypoint}} {{.Config.WorkingDir}}", image); cfg !=
				nonroot+` ["/usr/bin/rpmgr"] /var/lib/rpmgr` {
				t.Errorf("image config %q", cfg)
			}
			out, err := docker(t, "run", "--rm", "--platform", platform(arch), image, "version")
			if err != nil && strings.Contains(out, "exec format error") && os.Getenv("REQUIRE_EMULATION") != "1" {
				t.Skipf("no emulation of %s on this host", platform(arch))
			}
			if err != nil || !strings.HasPrefix(out, "rpmgr "+version+" (") || !strings.HasSuffix(out, ", linux/"+arch+")") {
				t.Fatalf("rpmgr version on %s: %v\n%s", platform(arch), err, out)
			}
			for _, role := range []string{"controller", "gateway", "connector", "all-in-one"} {
				out, err := docker(t, "run", "--rm", "--platform", platform(arch), image, role)
				if err == nil || !strings.Contains(out, "rpmgr "+role+": open /etc/rpmgr/"+role+".yaml: no such file") {
					t.Errorf("%s without a boot file: %v\n%s", role, err, out)
				}
			}
			if out, err := docker(t, "run", "--rm", "--platform", platform(arch), "--entrypoint", "/bin/sh", image, "-c", "true"); err == nil {
				t.Errorf("the image has a shell: %s", out)
			}
		})
		if arch == runtime.GOARCH {
			t.Run("all-in-one", func(t *testing.T) { allInOne(t, image) })
		}
	}
}

// allInOne initialises and runs an all-in-one as the nonroot user, with its state in a volume
// and its boot file and UI certificate mounted read-only, and reaches its ports 443 and 80 as
// Docker publishes them.
func allInOne(t *testing.T, image string) {
	conf := t.TempDir()
	if err := os.Chmod(conf, 0o755); err != nil { //nolint:gosec // G302: the container's user reads the boot file
		t.Fatal(err)
	}
	pool := uiCertificate(t, filepath.Join(conf, "ui.crt"), filepath.Join(conf, "ui.key"))
	boot := `version: 1
public_url: https://localhost
kek: {source: file, path: /var/lib/rpmgr/kek}
tls: {cert_file: /etc/rpmgr/ui.crt, key_file: /etc/rpmgr/ui.key}
`
	if err := os.WriteFile(filepath.Join(conf, "all-in-one.yaml"), []byte(boot), 0o644); err != nil { //nolint:gosec // G306: read by the container's user
		t.Fatal(err)
	}
	volume := must(t, "volume", "create")
	t.Cleanup(func() { _, _ = docker(t, "volume", "rm", volume) })
	mounts := []string{"-v", volume + ":/var/lib/rpmgr", "-v", conf + ":/etc/rpmgr:ro"}
	if out, err := docker(t, append(append([]string{"run", "--rm"}, mounts...), image, "all-in-one", "init")...); err != nil ||
		!strings.Contains(out, "https://localhost/setup#") {
		t.Fatalf("all-in-one init: %v\n%s", err, out)
	}
	id := must(t, append(append([]string{"run", "-d", "-p", "127.0.0.1::80/tcp", "-p", "127.0.0.1::443/tcp", "-p", "127.0.0.1::443/udp"},
		mounts...), image, "all-in-one")...)
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := docker(t, "logs", id)
			t.Logf("all-in-one log:\n%s", logs)
		}
		_, _ = docker(t, "stop", id)
		_, _ = docker(t, "rm", id)
	})
	https := must(t, "port", id, "443/tcp")
	http80 := must(t, "port", id, "80/tcp")

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, firstLine(https))
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var resp *http.Response
	var err error
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		if resp, err = client.Get("https://localhost/"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no answer on port 443: %v", err)
		}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("the UI on port 443: %s", resp.Status)
	}

	req, _ := http.NewRequest(http.MethodGet, "http://"+firstLine(http80)+"/", nil)
	req.Host = "localhost"
	plain := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = plain.Do(req)
	if err != nil {
		t.Fatalf("port 80: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 3 || !strings.HasPrefix(resp.Header.Get("Location"), "https://localhost") {
		t.Errorf("port 80 answers %s, Location %q; want a redirect to HTTPS", resp.Status, resp.Header.Get("Location"))
	}
	if user := must(t, "inspect", "-f", "{{.Config.User}}", id); user != nonroot {
		t.Errorf("the all-in-one runs as %q", user)
	}
}

// firstLine is the first address `docker port` prints, IPv4 here as the port is published on
// 127.0.0.1.
func firstLine(s string) string { return strings.SplitN(s, "\n", 2)[0] }

// uiCertificate writes a certificate for localhost and its key, readable by the container's user,
// and returns the pool of the test CA that issued it.
func uiCertificate(t *testing.T, certFile, keyFile string) *x509.CertPool {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "images test CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for path, block := range map[string]*pem.Block{certFile: {Type: "CERTIFICATE", Bytes: der}, keyFile: {Type: "EC PRIVATE KEY", Bytes: keyDER}} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil { //nolint:gosec // G306: a test key, read by the container's user
			t.Fatal(err)
		}
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool
}
