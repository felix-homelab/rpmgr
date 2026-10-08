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
	"strconv"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/token"
)

func freePort(t *testing.T) int {
	t.Helper()
	for range 20 {
		ln, err := net.Listen("tcp", ":0") //nolint:gosec // G102: the test gateway listens on every interface, as localhost may be ::1
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", ln.Addr().String())
		_ = ln.Close()
		if err == nil {
			_ = pc.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

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
	port                 int
	cfg                  config.AllInOne
	web                  *http.Client
}

func newHost(t *testing.T) *host {
	t.Helper()
	h := &host{dir: t.TempDir(), port: freePort(t)}
	h.boot = filepath.Join(h.dir, "all-in-one.yaml")
	h.publicURL = "https://localhost:" + strconv.Itoa(h.port)
	state := filepath.Join(h.dir, "lib")
	if err := os.MkdirAll(state, 0o750); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(h.dir, "ui.crt"), filepath.Join(h.dir, "ui.key")
	pool := webFiles(t, certFile, keyFile)
	h.web = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	boot := fmt.Sprintf(`version: 1
public_url: %s
listen: {tcp: ":%d", udp: ":%d", http: "", admin: "127.0.0.1:%d"}
database: {dsn: %s}
kek: {source: file, path: %s}
tls: {cert_file: %s, key_file: %s}
state_dir: %s
`, h.publicURL, h.port, h.port, freePort(t), filepath.Join(state, "controller.db"), filepath.Join(h.dir, "kek"), certFile, keyFile, state)
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
			DrainPeriod: 200 * time.Millisecond, Listening: func() { close(listening) }})
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

// TestAllInOne: `init` sets up the controller and enrolls its gateway through it; `Run` serves the
// controller through the gateway's port 443, so a connector enrolls and runs against the public URL;
// a tcp route on the default group then reaches a service behind the connector, also after a
// restart.
func TestAllInOne(t *testing.T) {
	h := newHost(t)
	r := h.init(t)
	if _, err := agent.Load(h.cfg.Gateway().IdentityDir); err != nil {
		t.Fatalf("the gateway's identity: %v", err)
	}
	if _, err := allinone.Init(context.Background(), controller.InitOptions{ConfigPath: h.boot}); !errors.Is(err, controller.ErrInitialised) {
		t.Fatalf("a second init: %v", err)
	}
	stop := h.run(t)
	waitFor(t, "not ready", h.ready)

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
	cctx, ccancel := context.WithCancel(context.Background())
	cdone := make(chan error, 1)
	go func() {
		cdone <- connector.Run(cctx, connector.RunOptions{Config: cc, Version: "0.1.0", Getenv: func(string) string { return "" }})
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

	stop()
	h.run(t)
	waitFor(t, "the route is not served after a restart", served)
}
