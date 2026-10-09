// SPDX-License-Identifier: Apache-2.0

//go:build webe2e

// Package webe2e runs the web UI's browser tests (web/e2e) with Playwright against an all-in-one
// in this process, which serves the UI built into internal/webui (docs/12-testing-and-quality.md,
// "Test layers"). check-web-e2e.sh runs it with the Playwright image of .github/scripts/lib.sh.
package webe2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// uiCertificate writes a certificate for localhost and its key, from a CA of its own, and returns
// the base64 SHA-256 of its public key, which the browser trusts.
func uiCertificate(t *testing.T, certFile, keyFile string) string {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "webe2e CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
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
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func TestBrowser(t *testing.T) {
	image := os.Getenv("PLAYWRIGHT_IMAGE")
	if image == "" {
		t.Fatal("PLAYWRIGHT_IMAGE is not set; run .github/scripts/check-web-e2e.sh")
	}
	web, err := filepath.Abs("../../web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("../../internal/webui/ui/app/index.html"); err != nil {
		t.Fatalf("the UI is not built into internal/webui (npm run build in web/): %v", err)
	}

	dir := t.TempDir()
	port := freePort(t)
	public := "https://localhost:" + strconv.Itoa(port)
	certFile, keyFile := filepath.Join(dir, "ui.crt"), filepath.Join(dir, "ui.key")
	spki := uiCertificate(t, certFile, keyFile)
	state := filepath.Join(dir, "lib")
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	boot := filepath.Join(dir, "all-in-one.yaml")
	if err := os.WriteFile(boot, fmt.Appendf(nil, `version: 1
public_url: %s
listen: {tcp: ":%d", udp: ":%d", http: "127.0.0.1:%d", admin: "127.0.0.1:%d"}
database: {dsn: %s}
kek: {source: file, path: %s}
tls: {cert_file: %s, key_file: %s}
state_dir: %s
`, public, port, port, freePort(t), freePort(t), filepath.Join(state, "controller.db"), filepath.Join(dir, "kek"), certFile, keyFile, state), 0o600); err != nil {
		t.Fatal(err)
	}
	none := func(string) string { return "" }
	r, err := allinone.Init(context.Background(), controller.InitOptions{ConfigPath: boot, Getenv: none})
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.AllInOne
	if err := config.Load(boot, &cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	listening, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- allinone.Run(ctx, allinone.RunOptions{Config: cfg, Version: "0.1.0", Getenv: none, DrainPeriod: 200 * time.Millisecond,
			Listening: func() { close(listening) }})
	}()
	select {
	case <-listening:
	case err := <-done:
		cancel()
		t.Fatalf("Run: %v", err)
	}
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run ended with %v", err)
		}
	}()

	cmd := exec.Command("docker", "run", "--rm", "--network", "host", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-e", "HOME=/tmp", "-e", "CI=1", "-e", "RPMGR_URL="+public, "-e", "RPMGR_SETUP="+r.FirstUserLink, "-e", "RPMGR_SPKI="+spki,
		"-v", web+":/web", "-w", "/web", image, "npx", "--no-install", "playwright", "test")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("the browser tests failed: %v", err)
	}
}
