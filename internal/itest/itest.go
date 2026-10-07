// SPDX-License-Identifier: Apache-2.0

// Package itest runs a controller and its agents in one process for integration tests
// (docs/12-testing-and-quality.md, "Test layers"): a real database, CA, port 443 with the agent
// protocol and the web server, and agents enrolled through it.
package itest

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/enroll"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// Options configure a test controller.
type Options struct {
	Version   string           // the controller's version; "" is "dev"
	Now       func() time.Time // the controller's clock; nil is time.Now
	Admission int              // control sessions per second; 0 is the default
}

// Controller is a running test controller: its first replica, and those StartReplica adds.
type Controller struct {
	DB       *store.DB
	CA       *pki.CA
	Sessions *controller.Sessions // of the first replica
	URL      string               // https://127.0.0.1:<port> of the first replica
	Org      string
	Sys      context.Context
	opts     Options
	web      *http.Client
}

// StartController starts a controller on a loopback port; t's cleanup stops it.
func StartController(t testing.TB, o Options) *Controller {
	t.Helper()
	if o.Version == "" {
		o.Version = "dev"
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	td, err := pki.NewTrustDomain()
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	kek, err := secret.NewKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := secret.NewSealer(kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error { return pki.InitCA(sys, tx, sealer, td, time.Now()) }); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadCA(sys, db, sealer, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	c := &Controller{DB: db, CA: ca, Org: storetest.Org(t, db, "org-a"), Sys: sys, opts: o}
	c.URL, c.Sessions = c.StartReplica(t)
	return c
}

// StartReplica starts another controller replica on the same database and CA, as HA runs them,
// and returns its URL and its sessions.
func (c *Controller) StartReplica(t testing.TB) (string, *controller.Sessions) {
	t.Helper()
	td := c.CA.TrustDomain()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "https://" + ln.Addr().String()
	nodeID := ids.New("ctn")
	node, err := c.CA.NodeCertificate(c.Sys, c.DB, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.CA.Root())
	cfg := pki.AgentEndpointConfig(node, roots, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector, pki.KindGateway}},
		nil, pki.Reauth{})
	split := controller.NewSplitter(td, ln.Addr())
	agents := controller.NewAgentServer(cfg, td)
	sessions := controller.NewSessions(controller.SessionsOptions{DB: c.DB, CA: c.CA, Node: nodeID, Version: c.opts.Version,
		Sys: c.Sys, Now: c.opts.Now, Admission: c.opts.Admission})
	agentv1.RegisterControlServer(agents, sessions)
	agentv1.RegisterEnrollmentServer(agents, enroll.NewService(c.DB, c.CA, []string{url}, nil))
	mux := http.NewServeMux()
	mux.Handle("/.well-known/rpmgr/trust-bundle", enroll.TrustBundleHandler(c.CA.Root()))
	uiCert, uiRoots := webCertificate(t)
	web := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = agents.Serve(split.Agents()) }()
	go func() {
		_ = web.Serve(tls.NewListener(split.Web(), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{uiCert}}))
	}()
	go func() { _ = split.Serve(ln) }()
	t.Cleanup(func() { agents.Stop(); _ = web.Close(); _ = ln.Close() })
	if c.web == nil {
		c.web = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: uiRoots, MinVersion: tls.VersionTLS13}}}
	}
	return url, sessions
}

// EnrollConnector enrolls a connector into dir through the controller and loads its identity.
func (c *Controller) EnrollConnector(t testing.TB, dir string) agent.Loaded {
	t.Helper()
	tok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	c.DB.Client().EnrollmentToken.Create().SetOrgID(c.Org).SetTokenHash(token.Hash(tok)).SetRole("connector").
		SetExpiresAt(time.Now().Add(time.Hour)).SetCreatedBy("usr_itest").ExecX(c.Sys)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := agent.Enroll(ctx, agent.EnrollOptions{Controller: c.URL, Pin: pki.RootPin(c.CA.Root()), Token: tok,
		IdentityDir: dir, HTTPClient: c.web, Host: &agentv1.HostFacts{Hostname: "itest"}, Version: "0.1.0"}); err != nil {
		t.Fatal(err)
	}
	l, err := agent.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// webCertificate is a self-signed certificate for 127.0.0.1, as an operator might supply.
func webCertificate(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "itest"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, pool
}
