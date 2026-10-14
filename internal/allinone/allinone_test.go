// SPDX-License-Identifier: Apache-2.0

package allinone_test

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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/acme/acmetest"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
	"github.com/felix-homelab/rpmgr/internal/testutil/freeport"
	"github.com/felix-homelab/rpmgr/internal/token"
)

func freePort(t *testing.T) int { return freeport.Port(t) }

// webFiles writes a certificate for localhost from a new CA and returns the CA's pool.
func webFiles(t *testing.T, certFile, keyFile string) *x509.CertPool {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test web CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool
}

// host is an all-in-one installation in a temporary directory, with its public URL at
// https://localhost:<port>.
type host struct {
	dir, boot, publicURL string
	port, port80         int
	cfg                  config.AllInOne
	web                  *http.Client
	acmeRoots            *x509.CertPool     // RunOptions.ACMERoots
	registry             telemetry.Registry // RunOptions.Registry
}

func newHost(t *testing.T) *host { return newHostAt(t, "") }

// newHostAt is newHost with the public URL at https://<name>:<port> and no certificate files, for
// ACME; "" is localhost with files.
func newHostAt(t *testing.T, name string) *host {
	t.Helper()
	h := &host{dir: t.TempDir(), port: freePort(t), port80: freePort(t)}
	h.boot = filepath.Join(h.dir, "all-in-one.yaml")
	h.publicURL = "https://localhost:" + strconv.Itoa(h.port)
	state := filepath.Join(h.dir, "lib")
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(h.dir, "ui.crt"), filepath.Join(h.dir, "ui.key")
	files := fmt.Sprintf("tls: {cert_file: %s, key_file: %s}\n", certFile, keyFile)
	if name == "" {
		pool := webFiles(t, certFile, keyFile)
		h.web = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	} else {
		h.publicURL, files = "https://"+name+":"+strconv.Itoa(h.port), ""
	}
	boot := fmt.Sprintf(`version: 1
public_url: %s
listen: {tcp: ":%d", udp: ":%d", http: "127.0.0.1:%d", admin: "127.0.0.1:%d"}
database: {dsn: %s}
kek: {source: file, path: %s}
%sstate_dir: %s
`, h.publicURL, h.port, h.port, h.port80, freePort(t), filepath.Join(state, "controller.db"), filepath.Join(h.dir, "kek"), files, state)
	if err := os.WriteFile(h.boot, []byte(boot), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *host) init(t *testing.T) allinone.InitResult {
	t.Helper()
	r, err := allinone.Init(context.Background(), controller.InitOptions{ConfigPath: h.boot, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := config.Load(h.boot, &h.cfg); err != nil {
		t.Fatal(err)
	}
	return r
}

// run runs the installation until the returned function stops it.
func (h *host) run(t *testing.T) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	listening, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- allinone.Run(ctx, allinone.RunOptions{Config: h.cfg, Version: "0.1.0", Getenv: func(string) string { return "" },
			DrainPeriod: 200 * time.Millisecond, ACMERoots: h.acmeRoots, Registry: h.registry, Listening: func() { close(listening) }})
	}()
	select {
	case <-listening:
	case err := <-done:
		cancel()
		t.Fatalf("Run: %v", err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run ended with %v", err)
		}
	}
	t.Cleanup(stop)
	return stop
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal(what)
}

func (h *host) ready() bool {
	resp, err := http.Get("http://" + h.cfg.Listen.Admin + "/readyz")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func echoService(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func ping(c net.Conn, msg string) error {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	b := make([]byte, len(msg))
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if string(b) != msg {
		return errors.New("wrong echo")
	}
	return nil
}

// TestInit_GroupHostnames (D79): init gives the gateway group "default" the public URL's host,
// in lower case, as its public hostname, unless the group refuses it, as it does a single label.
func TestInit_GroupHostnames(t *testing.T) {
	for _, c := range []struct {
		host string
		want []string
	}{
		{"localhost", nil},
		{"panel", nil},
		{"Panel.Example.COM", []string{"panel.example.com"}},
		{"panel.example.com.", []string{"panel.example.com"}},
		{"localhost.", nil},
		{"203.0.113.7", []string{"203.0.113.7"}},
		{"[2001:db8::7]", []string{"2001:db8::7"}},
	} {
		t.Run(c.host, func(t *testing.T) {
			h := newHostAt(t, c.host)
			h.init(t)
			db, err := store.OpenSQLite(context.Background(), h.cfg.Database.DSN, store.SQLiteOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			g, err := db.Client().GatewayGroup.Query().Where(gatewaygroup.Name(allinone.GroupName)).Only(storetest.SystemCtx(t))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(g.PublicHostnames, c.want) {
				t.Errorf("public hostnames %q, want %q", g.PublicHostnames, c.want)
			}
		})
	}
}

// TestInit_SystemdCredential (docs/16-cli.md, `all-in-one init`): with the KEK in a new systemd
// credential, init enrolls its gateway through the in-memory controller with the KEK it has just
// made: outside a service no credential is loaded (no CREDENTIALS_DIRECTORY), so the controller
// cannot load it again.
func TestInit_SystemdCredential(t *testing.T) {
	h := newHost(t)
	boot, err := os.ReadFile(h.boot)
	if err != nil {
		t.Fatal(err)
	}
	fileKEK := fmt.Sprintf("kek: {source: file, path: %s}\n", filepath.Join(h.dir, "kek"))
	if !strings.Contains(string(boot), fileKEK) {
		t.Fatalf("boot file %q", boot)
	}
	boot = []byte(strings.Replace(string(boot), fileKEK, "kek: {source: systemd-credential}\n", 1))
	if err := os.WriteFile(h.boot, boot, 0o600); err != nil { //nolint:gosec // G703: the test's own boot file
		t.Fatal(err)
	}
	credstore := filepath.Join(h.dir, "credstore")
	var encrypted []string
	r, err := allinone.Init(context.Background(), controller.InitOptions{ConfigPath: h.boot, CredentialsDir: credstore,
		Getenv: func(string) string { return "" }, SystemdVersion: func() int { return 255 },
		Encrypt: func(_ context.Context, name, path string, b []byte) error {
			encrypted = append(encrypted, name)
			return os.WriteFile(path, b, 0o600) // stands in for systemd-creds encrypt
		}})
	if err != nil {
		t.Fatalf("init with a new systemd credential: %v", err)
	}
	if len(encrypted) != 1 || encrypted[0] != "rpmgr-kek" || r.GatewayID == "" {
		t.Fatalf("credentials %v, gateway %q", encrypted, r.GatewayID)
	}
	if err := config.Load(h.boot, &h.cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Load(h.cfg.Gateway().IdentityDir); err != nil {
		t.Fatalf("the gateway's identity: %v", err)
	}
}

// TestInit_GivesStateToOwner (docs/10-operations.md, "Install"): init runs as root, so what it
// creates in the state directory goes to the directory's owner, the service user: last, when the
// in-memory controller has stopped and the gateway's identity is there. An init that cannot do it
// fails.
func TestInit_GivesStateToOwner(t *testing.T) {
	ctx := context.Background()
	h := newHost(t)
	state := filepath.Join(h.dir, "lib")
	var given []string
	var identity bool
	own := func(dir string) error {
		given = append(given, dir)
		_, err := os.Stat(filepath.Join(state, "gateway", "identity", agent.AgentFile))
		identity = err == nil
		// No controller holds the database: its lock is free.
		db, err := store.OpenSQLite(ctx, filepath.Join(state, "controller.db"), store.SQLiteOptions{Lock: true})
		if err != nil {
			return err
		}
		return db.Close()
	}
	if _, err := allinone.Init(ctx, controller.InitOptions{ConfigPath: h.boot, Getenv: func(string) string { return "" },
		OwnState: own}); err != nil {
		t.Fatal(err)
	}
	// The controller's part gives it away, then the all-in-one's once more.
	if want := []string{state, state}; !slices.Equal(given, want) || !identity {
		t.Fatalf("given %v, the gateway's identity there at the end: %v; want %v and true", given, identity, want)
	}

	h = newHost(t)
	calls := 0
	refuseSecond := func(string) error {
		if calls++; calls == 2 {
			return errors.New("chown refused")
		}
		return nil
	}
	if _, err := allinone.Init(ctx, controller.InitOptions{ConfigPath: h.boot, Getenv: func(string) string { return "" },
		OwnState: refuseSecond}); err == nil || !strings.Contains(err.Error(), "stays root's") {
		t.Fatalf("init that cannot give the state directory away: %v", err)
	}
}

// TestInit_FailureIsUndone (docs/10-operations.md, "Install"): when the gateway's part of init
// fails, the database and what init created beside it go again, while the boot file, the KEK and
// what was there before stay; init then runs again.
func TestInit_FailureIsUndone(t *testing.T) {
	ctx := context.Background()
	h := newHost(t)
	state := filepath.Join(h.dir, "lib")
	// A file where the gateway's state directory belongs makes the gateway's part fail.
	blocker := filepath.Join(state, "gateway")
	if err := os.WriteFile(blocker, []byte("in the way\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := controller.InitOptions{ConfigPath: h.boot, Getenv: func(string) string { return "" }}
	if _, err := allinone.Init(ctx, o); err == nil {
		t.Fatal("init with the gateway's state directory blocked succeeded")
	}
	left, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || left[0].Name() != "gateway" || left[0].IsDir() {
		t.Fatalf("after the failure, the state directory holds %v; want only the file that was there", left)
	}
	for _, f := range []string{h.boot, filepath.Join(h.dir, "kek")} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("the boot file or KEK after the failure: %v", err)
		}
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	r, err := allinone.Init(ctx, o)
	if err != nil || r.GatewayID == "" {
		t.Fatalf("init after the cause is gone: %+v, %v", r, err)
	}
}

// TestAllInOne: `init` sets up the controller and enrolls its gateway through it; `Run` serves the
// controller through the gateway's port 443, so a connector enrolls and runs against the public URL;
// a tcp route on the default group then reaches a service behind the connector, also after a
// restart, which finds the admin address free once Run has returned.
func TestAllInOne(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	if _, err := agent.Load(h.cfg.Gateway().IdentityDir); err != nil {
		t.Fatalf("the gateway's identity: %v", err)
	}
	if _, err := allinone.Init(context.Background(), controller.InitOptions{ConfigPath: h.boot}); !errors.Is(err, controller.ErrInitialised) {
		t.Fatalf("a second init: %v", err)
	}
	aio := newRecorder()
	h.registry = aio
	stop := h.run(t)
	h.registry = nil // a restart registers anew
	waitFor(t, "not ready", h.ready)

	// Port 80 is the gateway's: the controller's own name, which no route serves, gets its
	// redirect; any other name no route serves gets the gateway's page (D87).
	noFollow := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	port80 := func(host string) (int, http.Header) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/setup?step=1", h.port80), nil)
		req.Host = host
		req.Header.Set("Accept", "text/html")
		resp, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header
	}
	if code, header := port80(fmt.Sprintf("localhost:%d", h.port80)); code != http.StatusMovedPermanently ||
		header.Get("Location") != h.publicURL+"/setup?step=1" {
		t.Fatalf("port 80, the controller's name: %d %q", code, header.Get("Location"))
	}
	if code, header := port80("unrouted.example.net"); code != http.StatusNotFound || header.Get("Location") != "" ||
		header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("port 80, another name: %d %v", code, header)
	}

	// Enroll a connector through the public URL, which the gateway hands to the controller.
	db, err := store.OpenSQLite(context.Background(), h.cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sys := storetest.SystemCtx(t)
	group := db.Client().GatewayGroup.Query().Where(gatewaygroup.Name(allinone.GroupName)).OnlyX(sys)
	tok, _ := token.New(token.Enrollment)
	db.Client().EnrollmentToken.Create().SetOrgID(group.OrgID).SetTokenHash(token.Hash(tok)).SetRole("connector").
		SetExpiresAt(time.Now().Add(time.Hour)).SetCreatedBy("usr_test").ExecX(sys)
	conDir := filepath.Join(h.dir, "con")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	con, err := agent.Enroll(ctx, agent.EnrollOptions{Controller: h.publicURL, Pin: r.RootPin, Token: tok, IdentityDir: conDir,
		HTTPClient: h.web, Host: &agentv1.HostFacts{Hostname: "test"}, Version: "0.1.0"})
	if err != nil {
		t.Fatalf("enrolling a connector through the all-in-one's port 443: %v", err)
	}

	svc, public := echoService(t), freePort(t)
	if _, err := store.ConfigTx(sys, db, func(tx *ent.Tx) ([]string, error) {
		if _, err := routes.AddPool(sys, tx, group.OrgID, group.ID, routes.TCP, public, public); err != nil {
			return nil, err
		}
		alloc, err := routes.Allocate(sys, tx, group.OrgID, group.ID, routes.TCP, public)
		if err != nil {
			return nil, err
		}
		rt, err := tx.Route.Create().SetOrgID(group.OrgID).SetName("echo").SetType("tcp").SetGatewayGroupID(group.ID).Save(sys)
		if err != nil {
			return nil, err
		}
		if err := tx.RouteTCP.Create().SetOrgID(group.OrgID).SetRouteID(rt.ID).SetPortAllocationID(alloc.ID).Exec(sys); err != nil {
			return nil, err
		}
		return []string{rt.ID}, tx.RouteTarget.Create().SetOrgID(group.OrgID).SetRouteID(rt.ID).SetConnectorID(con.AgentID).
			SetKind("address").SetHost("127.0.0.1").SetPort(svc).Exec(sys)
	}); err != nil {
		t.Fatal(err)
	}

	var cc config.Connector
	cc.Version = 1
	cc.Controller.Endpoints = []string{h.publicURL}
	cc.IdentityDir, cc.StateDir, cc.PolicyFile = conDir, t.TempDir(), filepath.Join(h.dir, "policy.yaml")
	cc.Listen.Admin = net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))
	if err := os.WriteFile(cc.PolicyFile, fmt.Appendf(nil, "version: 1\nallow_targets:\n  - cidr: 127.0.0.1/32\n    ports: [%d]\n", svc), 0o600); err != nil {
		t.Fatal(err)
	}
	conReg := newRecorder()
	cctx, ccancel := context.WithCancel(context.Background())
	cdone := make(chan error, 1)
	go func() {
		cdone <- connector.Run(cctx, connector.RunOptions{Config: cc, Version: "0.1.0", Getenv: func(string) string { return "" }, Registry: conReg})
	}()
	defer func() { ccancel(); <-cdone }()

	served := func() bool {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(public)))
		if err != nil {
			return false
		}
		defer func() { _ = c.Close() }()
		return ping(c, "through the all-in-one") == nil
	}
	waitFor(t, "the route is not served", served)
	checkP1Metrics(t, aio, conReg, h.cfg.Listen.Admin, cc.Listen.Admin)

	stop()
	ln, err := net.Listen("tcp", h.cfg.Listen.Admin)
	if err != nil {
		t.Fatalf("the admin address after Run returned: %v", err)
	}
	_ = ln.Close()
	h.run(t)
	waitFor(t, "the route is not served after a restart", served)
}

// TestAllInOne_ACME: without certificate files, all-in-one's controller obtains the public URL's
// certificate through its gateway, which hands the CA's HTTP-01 requests for the name on port 80
// and its TLS-ALPN-01 connections on port 443 to the controller; the controller then serves the
// certificate through the gateway, with HSTS.
func TestAllInOne_ACME(t *testing.T) {
	h := newHostAt(t, "panel.example.com")
	h.init(t)
	dns, err := acmetest.StartDNS([]string{"example.com"}, func(string) []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dns.Close)
	pebble, err := acmetest.Start(acmetest.Options{HTTPPort: h.port80, TLSPort: h.port, Resolver: dns.Addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pebble.Close)
	db, err := store.OpenSQLite(context.Background(), h.cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = settings.UpdateInstance(storetest.SystemCtx(t), db, &rpmgrv1.InstanceSettings{AcmeDirectoryUrl: proto.String(pebble.DirectoryURL)},
		&fieldmaskpb.FieldMask{Paths: []string{"acme_directory_url"}}, 0)
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	h.acmeRoots = pebble.ServerRoots
	h.run(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	roots, err := pebble.IssuanceRoots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, "127.0.0.1:"+strconv.Itoa(h.port))
		}}}
	var (
		hsts string
		last error
	)
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(100 * time.Millisecond) {
		resp, err := client.Get(h.publicURL + "/.well-known/rpmgr/trust-bundle")
		if last = err; err == nil {
			_ = resp.Body.Close()
			hsts = resp.Header.Get("Strict-Transport-Security")
			break
		}
		if time.Now().After(deadline) {
			break
		}
	}
	if last != nil || hsts != "max-age=31536000" {
		t.Fatalf("the ACME certificate through the gateway: HSTS %q, %v", hsts, last)
	}
}
