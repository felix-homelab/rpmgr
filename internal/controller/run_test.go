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
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/acme/acmetest"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/testutil/freeport"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// freeAddr returns a loopback address whose port was free a moment ago.
func freeAddr(t *testing.T) string { return freeport.Addr(t) }

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
	acmeRoots             *x509.CertPool
	firstUserLink         string
	logger                *slog.Logger
	release               release.Source
}

// runSetup varies startRunWith.
type runSetup struct {
	// host is the public URL's host, with no certificate files; "" is 127.0.0.1 with files.
	host        string
	https, http string           // the listeners; "" picks free ports
	acmeRoots   *x509.CertPool   // RunOptions.ACMERoots
	prepare     func(r *running) // after the initialisation, before Run
	logger      *slog.Logger     // RunOptions.Logger
	release     release.Source   // RunOptions.ReleaseSource
}

// startRun initialises a controller in a temporary directory and runs it.
func startRun(t *testing.T) *running { return startRunWith(t, runSetup{}) }

func startRunWith(t *testing.T, o runSetup) *running {
	t.Helper()
	controller.SetRunTimers(t, 500*time.Millisecond, 50*time.Millisecond)
	h := newHost(t)
	r := &running{h: h, https: o.https, http: o.http, admin: freeAddr(t), ca: newWebCA(t),
		certFile: filepath.Join(h.dir, "ui.crt"), keyFile: filepath.Join(h.dir, "ui.key"), acmeRoots: o.acmeRoots, logger: o.logger, release: o.release}
	if r.https == "" {
		r.https = freeAddr(t)
	}
	if r.http == "" {
		r.http = freeAddr(t)
	}
	r.url = "https://" + r.https
	files := "tls: {cert_file: " + r.certFile + ", key_file: " + r.keyFile + "}\n"
	if o.host != "" {
		_, port, _ := net.SplitHostPort(r.https)
		r.url, files = "https://"+o.host+":"+port, ""
	} else {
		r.ca.issue(t, r.certFile, r.keyFile, "first")
	}
	if err := os.MkdirAll(filepath.Dir(h.db), 0o750); err != nil {
		t.Fatal(err)
	}
	boot := "version: 1\npublic_url: " + r.url + "\ndatabase: {dsn: " + h.db + "}\n" + h.fileKEK() +
		"listen: {https: \"" + r.https + "\", http: \"" + r.http + "\", admin: \"" + r.admin + "\"}\n" + files
	if err := os.WriteFile(h.cfg, []byte(boot), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := controller.Init(context.Background(), h.opts())
	if err != nil {
		t.Fatal(err)
	}
	r.pin, r.trustDomain, r.firstUserLink = res.RootPin, res.TrustDomain, res.FirstUserLink
	if err := config.Load(h.cfg, &r.cfg); err != nil {
		t.Fatal(err)
	}
	r.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: r.ca.pool, MinVersion: tls.VersionTLS13}}}
	if o.prepare != nil {
		o.prepare(r)
	}
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
			ACMERoots: r.acmeRoots, Logger: r.logger, ReleaseSource: r.release, Listening: func() { close(listening) }})
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

// warnings is a log handler that keeps the warnings and errors.
type warnings struct {
	mu  sync.Mutex
	got []string
}

func (w *warnings) Enabled(context.Context, slog.Level) bool { return true }
func (w *warnings) WithAttrs([]slog.Attr) slog.Handler       { return w }
func (w *warnings) WithGroup(string) slog.Handler            { return w }
func (w *warnings) Handle(_ context.Context, rec slog.Record) error {
	if rec.Level >= slog.LevelWarn {
		msg := rec.Message
		rec.Attrs(func(a slog.Attr) bool { msg += " " + a.String(); return true })
		w.mu.Lock()
		w.got = append(w.got, msg)
		w.mu.Unlock()
	}
	return nil
}

func (w *warnings) all() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.got)
}

// stalledRelease is a release source that answers no request until it is cancelled.
type stalledRelease struct{}

func (stalledRelease) Open(ctx context.Context, _ string) (io.ReadCloser, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestRun_CleanStop: a controller that stops while its background jobs run, and a release check
// waits for its source, logs no warning or error, also after Run has returned: it waits for the
// jobs before it closes the database.
func TestRun_CleanStop(t *testing.T) {
	for i := range 3 {
		w := &warnings{}
		r := startRunWith(t, runSetup{logger: slog.New(w), release: stalledRelease{}})
		time.Sleep(time.Duration(100+100*i) * time.Millisecond) // the jobs take their leases and run
		r.stop(t)
		time.Sleep(300 * time.Millisecond) // what still runs after Run has returned
		if got := w.all(); len(got) != 0 {
			t.Fatalf("round %d: a clean stop logged:\n%s", i, strings.Join(got, "\n"))
		}
	}
}

// TestRun: a running controller serves the trust bundle over the public URL's certificate with
// HSTS, answers /dl/ from its release mirror, is backed up while it runs, enrolls an agent at its
// agent endpoint, redirects port 80, is ready on its admin listener and stops cleanly, its
// listeners closed once Run returns; a restart keeps its node identity.
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
	if v := resp.Header.Get("Strict-Transport-Security"); v != "max-age=31536000" {
		t.Fatalf("HSTS with certificate files: %q", v)
	}
	// The UI on every other path, with its CSP; an unknown API service is not the UI.
	for path, want := range map[string]int{"/": http.StatusOK, "/routes/rt_1": http.StatusOK, "/rpmgr.v1.NoService/Get": http.StatusNotFound} {
		resp, err := r.client.Get(r.url + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
			resp.Header.Get("Strict-Transport-Security") == "" {
			t.Fatalf("%s: %s %v", path, resp.Status, resp.Header)
		}
	}

	// /dl/ is the release mirror, not the UI, which would answer 200; without release root keys
	// in this build the mirror holds nothing.
	resp, err = r.client.Get(r.url + "/dl/0.1.0/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Content-Security-Policy") != "" {
		t.Fatalf("/dl/: %s %v", resp.Status, resp.Header)
	}

	// A backup alongside the running controller, which holds the database's lifetime lock.
	if _, err := controller.Backup(context.Background(), r.h.cfg, filepath.Join(t.TempDir(), "run.backup"), "0.1.0", time.Now); err != nil {
		t.Fatalf("a backup while the controller runs: %v", err)
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
	for _, a := range []string{r.https, r.http, r.admin} {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			t.Fatalf("a listener's address after Run returned: %v", err)
		}
		_ = ln.Close()
	}
	r.start(t)
	again, _ := os.ReadFile(filepath.Join(filepath.Dir(r.h.db), "controller-node.id"))
	if string(again) != string(node) {
		t.Fatalf("node identity %q after a restart, want %q", again, node)
	}
}

// TestRun_ControllerEndpoints: an agent gets the public URL at enrollment while the instance
// settings list no controller endpoints, and the listed ones, in order, once they do; its snapshots
// name them too, and a change of the list reaches it with its next snapshot, an emptied list the
// public URL again.
func TestRun_ControllerEndpoints(t *testing.T) {
	r := startRun(t)
	sys := storetest.SystemCtx(t)
	db, err := store.OpenSQLite(context.Background(), r.h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	org := storetest.Org(t, db, "org-a")
	enroll := func() agent.Loaded {
		t.Helper()
		tok, _ := token.New(token.Enrollment)
		db.Client().EnrollmentToken.Create().SetOrgID(org).SetTokenHash(token.Hash(tok)).SetRole("connector").
			SetExpiresAt(time.Now().Add(time.Hour)).SetCreatedBy("usr_test").ExecX(sys)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		dir := filepath.Join(t.TempDir(), "id")
		if _, err := agent.Enroll(ctx, agent.EnrollOptions{Controller: r.url, Pin: r.pin, Token: tok, IdentityDir: dir,
			HTTPClient: r.client, Host: &agentv1.HostFacts{Hostname: "test"}, Version: "0.1.0"}); err != nil {
			t.Fatalf("enrollment: %v", err)
		}
		id, err := agent.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	setEndpoints := func(eps ...string) {
		t.Helper()
		if _, err := settings.UpdateInstance(sys, db, &rpmgrv1.InstanceSettings{ControllerEndpoints: eps},
			&fieldmaskpb.FieldMask{Paths: []string{"controller_endpoints"}}, 0); err != nil {
			t.Fatal(err)
		}
	}

	if id := enroll(); !slices.Equal(id.Endpoints, []string{r.url}) {
		t.Fatalf("enrolled without the setting with the endpoints %v, want the public URL", id.Endpoints)
	}
	listed := []string{r.url, "https://gw.example.net:8443"}
	setEndpoints(listed...)
	id := enroll()
	if !slices.Equal(id.Endpoints, listed) {
		t.Fatalf("enrolled with the endpoints %v, want %v", id.Endpoints, listed)
	}

	// The agent's control session: every snapshot's endpoints, without applying it.
	got := make(chan []string, 8)
	c := agent.NewClient(agent.ClientOptions{Identity: id, Endpoints: id.Endpoints, Version: "0.1.0", BootID: "boot-1",
		OnMessage: func(m *agentv1.ControllerMessage) {
			if s := m.GetSnapshot(); s != nil {
				snap := &agentv1.Snapshot{}
				if err := proto.Unmarshal(s.GetPayload(), snap); err != nil {
					snap.ControllerEndpoints = []string{"undecodable: " + err.Error()}
				}
				got <- snap.GetControllerEndpoints()
			}
		}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	expect := func(what string, want []string) {
		t.Helper()
		select {
		case eps := <-got:
			if !slices.Equal(eps, want) {
				t.Fatalf("snapshot %s: endpoints %v, want %v", what, eps, want)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("no snapshot %s", what)
		}
	}
	expect("at the session's start", listed)
	changed := []string{"https://gw.example.net:8443", r.url}
	setEndpoints(changed...)
	expect("after the change", changed)
	setEndpoints()
	expect("after emptying the list", []string{r.url})
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

// TestRun_ACME: without certificate files, a controller whose public URL has a public DNS name
// serves a self-signed certificate without HSTS while its ACME CA cannot be reached; once it can,
// the controller obtains the certificate, validated on its own ports 80 and 443, serves it with
// HSTS and keeps redirecting port 80; after a restart it serves the stored certificate without a
// new order.
func TestRun_ACME(t *testing.T) {
	dns, err := acmetest.StartDNS([]string{"example.com"}, func(string) []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dns.Close)
	https, plain := freeAddr(t), freeAddr(t)
	port := func(addr string) int { p, _ := strconv.Atoi(addr[strings.LastIndex(addr, ":")+1:]); return p }
	pebble, err := acmetest.Start(acmetest.Options{HTTPPort: port(plain), TLSPort: port(https), Resolver: dns.Addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pebble.Close)
	setCA := func(r *running, dir string) {
		t.Helper()
		db, err := store.OpenSQLite(context.Background(), r.h.db, store.SQLiteOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		if _, err := settings.UpdateInstance(storetest.SystemCtx(t), db, &rpmgrv1.InstanceSettings{AcmeDirectoryUrl: proto.String(dir)},
			&fieldmaskpb.FieldMask{Paths: []string{"acme_directory_url"}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	r := startRunWith(t, runSetup{host: "panel.example.com", https: https, http: plain, acmeRoots: pebble.ServerRoots,
		prepare: func(r *running) { setCA(r, "https://127.0.0.1:1/directory") }})
	client := func(roots *x509.CertPool) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if strings.HasPrefix(addr, "panel.example.com:") {
						addr = https
					}
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				}}}
	}
	hsts := func(c *http.Client) (string, error) {
		resp, err := c.Get(r.url + "/.well-known/rpmgr/trust-bundle")
		if err != nil {
			return "", err
		}
		_ = resp.Body.Close()
		return resp.Header.Get("Strict-Transport-Security"), nil
	}

	// The CA cannot be reached: a self-signed certificate, which clients do not trust, and no HSTS.
	untrusted, err := client(x509.NewCertPool()).Get(r.url + "/")
	if err == nil {
		_ = untrusted.Body.Close()
	}
	var unverified *tls.CertificateVerificationError
	if !errors.As(err, &unverified) {
		t.Fatalf("without a CA: %v", err)
	}
	self := unverified.UnverifiedCertificates[0]
	if self.Issuer.CommonName != "panel.example.com" || self.Subject.CommonName != "panel.example.com" {
		t.Fatalf("without a CA the controller serves %s from %s", self.Subject, self.Issuer)
	}
	selfPool := x509.NewCertPool()
	selfPool.AddCert(self)
	if v, err := hsts(client(selfPool)); err != nil || v != "" {
		t.Fatalf("HSTS with a self-signed certificate: %q %v", v, err)
	}

	r.stop(t)
	setCA(r, pebble.DirectoryURL)
	r.start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	roots, err := pebble.IssuanceRoots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	trusting := client(roots)
	var v string
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(100 * time.Millisecond) {
		if v, err = hsts(trusting); err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil || v != "max-age=31536000" {
		t.Fatalf("with the ACME certificate: HSTS %q, %v", v, err)
	}
	resp, err := trusting.Get("http://" + plain + "/some/path")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != r.url+"/some/path" {
		t.Fatalf("port 80 with ACME: %s %s", resp.Status, resp.Header.Get("Location"))
	}

	orders := pebble.OrdersFor("panel.example.com")
	r.stop(t)
	r.start(t)
	if v, err := hsts(trusting); err != nil || v != "max-age=31536000" {
		t.Fatalf("after a restart: HSTS %q, %v", v, err)
	}
	if n := pebble.OrdersFor("panel.example.com"); n != orders {
		t.Fatalf("a restart ordered again: %d orders, were %d", n, orders)
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
