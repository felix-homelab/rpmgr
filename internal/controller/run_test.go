// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// freeAddr returns a loopback address whose port was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// webCA is a CA for the public URL's certificate files, which the test's clients trust.
type webCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pool *x509.CertPool
}

func newWebCA(t *testing.T) *webCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test web CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &webCA{key: key, cert: c, pool: pool}
}

// issue writes a certificate for 127.0.0.1 with common name cn and its key to the two files.
func (ca *webCA) issue(t *testing.T, certFile, keyFile, cn string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// running is a controller started by Run.
type running struct {
	h                     host
	cfg                   config.Controller
	https, http, admin    string
	certFile, keyFile     string
	ca                    *webCA
	ended                 chan struct{} // closed when Run returns, with its error in err
	err                   error
	cancel                context.CancelFunc
	client                *http.Client
	pin, trustDomain, url string
}

// startRun initialises a controller in a temporary directory and runs it.
func startRun(t *testing.T) *running {
	t.Helper()
	controller.SetRunTimers(t, 500*time.Millisecond, 50*time.Millisecond)
	h := newHost(t)
	r := &running{h: h, https: freeAddr(t), http: freeAddr(t), admin: freeAddr(t), ca: newWebCA(t),
		certFile: filepath.Join(h.dir, "ui.crt"), keyFile: filepath.Join(h.dir, "ui.key")}
	r.url = "https://" + r.https
	r.ca.issue(t, r.certFile, r.keyFile, "first")
	if err := os.MkdirAll(filepath.Dir(h.db), 0o750); err != nil {
		t.Fatal(err)
	}
	boot := "version: 1\npublic_url: " + r.url + "\ndatabase: {dsn: " + h.db + "}\n" + h.fileKEK() +
		"listen: {https: \"" + r.https + "\", http: \"" + r.http + "\", admin: \"" + r.admin + "\"}\n" +
		"tls: {cert_file: " + r.certFile + ", key_file: " + r.keyFile + "}\n"
	if err := os.WriteFile(h.cfg, []byte(boot), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := controller.Init(context.Background(), h.opts())
	if err != nil {
		t.Fatal(err)
	}
	r.pin, r.trustDomain = res.RootPin, res.TrustDomain
	if err := config.Load(h.cfg, &r.cfg); err != nil {
		t.Fatal(err)
	}
	r.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: r.ca.pool, MinVersion: tls.VersionTLS13}}}
	r.start(t)
	return r
}

func (r *running) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan struct{})
	r.cancel, r.ended = cancel, ended
	listening := make(chan struct{})
	go func() {
		r.err = controller.Run(ctx, controller.RunOptions{Config: r.cfg, Version: "0.1.0", Getenv: func(string) string { return "" },
			Listening: func() { close(listening) }})
		close(ended)
	}()
	t.Cleanup(func() { cancel(); <-ended })
	select {
	case <-listening:
	case <-ended:
		t.Fatalf("Run: %v", r.err)
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not start")
	}
}

func (r *running) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case <-r.ended:
		if r.err != nil {
			t.Fatalf("Run ended with %v", r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// TestRun: a running controller serves the trust bundle over the public URL's certificate, enrolls
// an agent at its agent endpoint, redirects port 80, is ready on its admin listener and stops
// cleanly; a restart keeps its node identity.
func TestRun(t *testing.T) {
	r := startRun(t)
	resp, err := r.client.Get(r.url + "/.well-known/rpmgr/trust-bundle")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Fatalf("trust bundle: %s %q", resp.Status, body)
	}

	// Enrollment through the agent endpoint on the same port; the token is written alongside the
	// running controller, as admin commands may.
	db, err := store.OpenSQLite(context.Background(), r.h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sys := storetest.SystemCtx(t)
	org := storetest.Org(t, db, "org-a")
	tok, _ := token.New(token.Enrollment)
	db.Client().EnrollmentToken.Create().SetOrgID(org).SetTokenHash(token.Hash(tok)).SetRole("connector").
		SetExpiresAt(time.Now().Add(time.Hour)).SetCreatedBy("usr_test").ExecX(sys)
	_ = db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id, err := agent.Enroll(ctx, agent.EnrollOptions{Controller: r.url, Pin: r.pin, Token: tok, IdentityDir: filepath.Join(t.TempDir(), "id"),
		HTTPClient: r.client, Host: &agentv1.HostFacts{Hostname: "test"}, Version: "0.1.0"})
	if err != nil {
		t.Fatalf("enrollment: %v", err)
	}
	if id.TrustDomain != r.trustDomain || len(id.Endpoints) != 1 || id.Endpoints[0] != r.url {
		t.Fatalf("enrolled %+v", id)
	}

	noFollow := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = noFollow.Get("http://" + r.http + "/some/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != r.url+"/some/path?q=1" {
		t.Fatalf("port 80: %s %s", resp.Status, resp.Header.Get("Location"))
	}
	resp, err = http.Get("http://" + r.admin + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz: %s", resp.Status)
	}

	node, err := os.ReadFile(filepath.Join(filepath.Dir(r.h.db), "controller-node.id"))
	if err != nil {
		t.Fatal(err)
	}
	r.stop(t)
	if resp, err := r.client.Get(r.url + "/.well-known/rpmgr/trust-bundle"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("still serving after Run returned")
	}
	r.start(t)
	again, _ := os.ReadFile(filepath.Join(filepath.Dir(r.h.db), "controller-node.id"))
	if string(again) != string(node) {
		t.Fatalf("node identity %q after a restart, want %q", again, node)
	}
}

// TestRun_CertificateReload: new certificate files are served without a restart; a pair that does
// not load keeps the previous certificate.
func TestRun_CertificateReload(t *testing.T) {
	r := startRun(t)
	served := func() string {
		t.Helper()
		c, err := tls.Dial("tcp", r.https, &tls.Config{RootCAs: r.ca.pool, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		return c.ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	if cn := served(); cn != "first" {
		t.Fatalf("served %q", cn)
	}
	r.ca.issue(t, r.certFile, r.keyFile, "second")
	deadline := time.Now().Add(5 * time.Second)
	for served() != "second" {
		if time.Now().After(deadline) {
			t.Fatal("the new certificate was not loaded")
		}
		time.Sleep(60 * time.Millisecond)
	}
	if err := os.WriteFile(r.keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if cn := served(); cn != "second" {
		t.Fatalf("after a broken key the controller serves %q", cn)
	}
}

// TestRun_Refusals: a second controller on the same database, a missing KEK and a database without
// an installation stop Run before it listens.
func TestRun_Refusals(t *testing.T) {
	r := startRun(t)
	run := func(cfg config.Controller) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cfg.Listen.HTTPS, cfg.Listen.Admin = freeAddr(t), freeAddr(t)
		none := ""
		cfg.Listen.HTTP = &none
		return controller.Run(ctx, controller.RunOptions{Config: cfg, Getenv: func(string) string { return "" },
			Listening: func() { t.Error("Run started") }})
	}
	if err := run(r.cfg); err == nil || !strings.Contains(err.Error(), "another controller") {
		t.Fatalf("a second controller on the database: %v", err)
	}
	cfg := r.cfg
	cfg.KEK.Path = filepath.Join(t.TempDir(), "missing")
	if err := run(cfg); err == nil {
		t.Fatal("ran without a KEK")
	}
	cfg = r.cfg
	cfg.Database.DSN = filepath.Join(t.TempDir(), "empty.db")
	if err := run(cfg); !errors.Is(err, controller.ErrNotInitialised) {
		t.Fatalf("an empty database: %v", err)
	}
}

// TestRun_InProcess: given a listener and a registry, as all-in-one gives them, Run serves on that
// listener instead of listen.https, registers its metrics there, hands over its readiness check and
// serves no admin listener of its own.
func TestRun_InProcess(t *testing.T) {
	r := startRun(t)
	r.stop(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reg := telemetry.NewRegistry()
	checks := make(chan func(context.Context) error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	listening := make(chan struct{})
	go func() {
		done <- controller.Run(ctx, controller.RunOptions{Config: r.cfg, Getenv: func(string) string { return "" }, Listener: ln,
			Registry: reg, Readiness: func(c func(context.Context) error) { checks <- c }, Listening: func() { close(listening) }})
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-listening:
	case err := <-done:
		t.Fatalf("Run: %v", err)
	}
	resp, err := r.client.Get("https://" + ln.Addr().String() + "/.well-known/rpmgr/trust-bundle")
	if err != nil {
		t.Fatalf("the given listener: %v", err)
	}
	_ = resp.Body.Close()
	if c, err := net.Dial("tcp", r.https); err == nil {
		_ = c.Close()
		t.Fatal("listen.https is bound as well")
	}
	if resp, err := http.Get("http://" + r.admin + "/healthz"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("an admin listener of its own")
	}
	if err := (<-checks)(context.Background()); err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if mfs, err := reg.Gather(); err != nil || len(mfs) == 0 {
		t.Fatalf("metrics: %v", err)
	}
}
