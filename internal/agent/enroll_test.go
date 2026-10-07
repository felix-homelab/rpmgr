// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
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

// installation is a database with an initialised CA and an org.
type installation struct {
	db  *store.DB
	ca  *pki.CA
	td  string
	org string
	sys context.Context
}

func newInstallation(t *testing.T) *installation {
	t.Helper()
	td, err := pki.NewTrustDomain()
	if err != nil {
		t.Fatal(err)
	}
	return newInstallationIn(t, td)
}

// newInstallationIn creates an installation in trust domain td; an attacker can pick the trust
// domain of the installation it imitates.
func newInstallationIn(t *testing.T, td string) *installation {
	t.Helper()
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	kek, _ := secret.NewKEK(raw)
	s, _ := secret.NewSealer(kek)
	if err := store.WriteTx(sys, db, func(tx *ent.Tx) error { return pki.InitCA(sys, tx, s, td, time.Now()) }); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadCA(sys, db, s, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return &installation{db: db, ca: ca, td: td, org: storetest.Org(t, db, "org-a"), sys: sys}
}

func (in *installation) mint(t *testing.T) string {
	t.Helper()
	tok, err := token.New(token.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	in.db.Client().EnrollmentToken.Create().SetOrgID(in.org).SetTokenHash(token.Hash(tok)).SetRole("connector").
		SetExpiresAt(time.Now().Add(time.Hour)).SetCreatedBy("usr_admin").ExecX(in.sys)
	return tok
}

// serve runs a controller's port 443 for in, presenting agentCA's node certificate on the agent
// names (in's own CA unless an attacker's is given), and returns its URL and an HTTP client that
// trusts the web server.
func serve(t *testing.T, in *installation, agentCA *installation) (string, *http.Client) {
	t.Helper()
	if agentCA == nil {
		agentCA = in
	}
	node, err := agentCA.ca.NodeCertificate(agentCA.sys, agentCA.db, ids.New("ctn"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(in.ca.Root())
	cfg := pki.AgentEndpointConfig(node, roots, pki.Expect{TrustDomain: in.td, Kinds: []pki.Kind{pki.KindConnector, pki.KindGateway}}, nil, pki.Reauth{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	split := controller.NewSplitter(in.td, ln.Addr())
	grpcSrv := controller.NewAgentServer(cfg, in.td)
	agentv1.RegisterEnrollmentServer(grpcSrv, enroll.NewService(in.db, in.ca, []string{"https://" + ln.Addr().String()}, nil))
	mux := http.NewServeMux()
	mux.Handle("/.well-known/rpmgr/trust-bundle", enroll.TrustBundleHandler(in.ca.Root()))
	uiCert, uiRoots := selfSigned(t)
	web := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = grpcSrv.Serve(split.Agents()) }()
	go func() {
		_ = web.Serve(tls.NewListener(split.Web(), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{uiCert}}))
	}()
	go func() { _ = split.Serve(ln) }()
	t.Cleanup(func() { grpcSrv.Stop(); _ = web.Close(); _ = ln.Close() })
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: uiRoots, MinVersion: tls.VersionTLS13}}}
	return "https://" + ln.Addr().String(), client
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ui"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: c}, pool
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func opts(in *installation, url string, client *http.Client, dir string) agent.EnrollOptions {
	return agent.EnrollOptions{Controller: url, Pin: pki.RootPin(in.ca.Root()), IdentityDir: dir, HTTPClient: client,
		Host: &agentv1.HostFacts{Hostname: "nas"}, Version: "0.1.0"}
}

func TestEnroll(t *testing.T) {
	in := newInstallation(t)
	url, client := serve(t, in, nil)
	dir := filepath.Join(t.TempDir(), "identity")
	o := opts(in, url, client, dir)
	o.Token = in.mint(t)
	id, err := agent.Enroll(ctx(t), o)
	if err != nil {
		t.Fatal(err)
	}
	if id.TrustDomain != in.td || id.Kind != "connector" || !ids.Valid("con", id.AgentID) || len(id.Endpoints) != 1 {
		t.Errorf("identity %+v", id)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("identity directory: %v, %v", st.Mode(), err)
	}
	if st, err := os.Stat(filepath.Join(dir, agent.KeyFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v, %v", st.Mode(), err)
	}
	var saved agent.Identity
	b, _ := os.ReadFile(filepath.Join(dir, agent.AgentFile))
	if err := json.Unmarshal(b, &saved); err != nil || saved.AgentID != id.AgentID {
		t.Errorf("agent.json: %s, %v", b, err)
	}
	roots := pemCerts(t, filepath.Join(dir, agent.RootsFile))
	if len(roots) != 1 || !roots[0].Equal(in.ca.Root()) {
		t.Errorf("roots.pem holds %d certificates", len(roots))
	}
	chain := pemCerts(t, filepath.Join(dir, agent.ChainFile))
	if got, err := in.ca.IdentityOf(chain[0], time.Now()); err != nil || got.ID != id.AgentID {
		t.Errorf("chain.pem: %v, %v", got, err)
	}

	o.Token = in.mint(t)
	if _, err := agent.Enroll(ctx(t), o); !errors.Is(err, agent.ErrAlreadyEnrolled) {
		t.Errorf("a second enrollment without --replace: %v", err)
	}
	o.Replace = true
	again, err := agent.Enroll(ctx(t), o)
	if err != nil || again.AgentID == id.AgentID {
		t.Errorf("enrollment with --replace: %+v, %v", again, err)
	}
}

func pemCerts(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			return out
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

// TestRejectsUnpinnedCA (enrollment): a bundle without the pinned root, and a controller whose
// agent certificate chains to another root, both fail, and nothing is written.
func TestRejectsUnpinnedCA(t *testing.T) {
	in := newInstallation(t)
	other := newInstallation(t)
	url, client := serve(t, in, nil)
	dir := filepath.Join(t.TempDir(), "identity")
	o := opts(in, url, client, dir)
	o.Token = in.mint(t)
	o.Pin = pki.RootPin(other.ca.Root())
	if _, err := agent.Enroll(ctx(t), o); !errors.Is(err, pki.ErrPinNotFound) {
		t.Errorf("a pin of another root: %v, want ErrPinNotFound", err)
	}
	impostorURL, impostorClient := serve(t, in, other) // serves in's bundle, other's agent certificate
	o = opts(in, impostorURL, impostorClient, dir)
	o.Token = in.mint(t)
	if _, err := agent.Enroll(ctx(t), o); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Errorf("a controller with another root's certificate: %v, want a failed connection", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a failed enrollment wrote %d files", len(entries))
	}
}

// TestEnroll_BundleWithExtraRootRejected: of a bundle with an extra root only the pinned one is
// kept, a controller presenting a chain to the extra root fails enrollment, and the response may
// add only roots the pinned root cross-signed.
func TestEnroll_BundleWithExtraRootRejected(t *testing.T) {
	in := newInstallation(t)
	attacker := newInstallationIn(t, in.td) // a CA of its own for the victim's trust domain
	bundle := append(pemOf(attacker.ca.Root()), pemOf(in.ca.Root())...)

	impostorURL, impostorClient := serve(t, in, attacker)
	o := opts(in, impostorURL, impostorClient, filepath.Join(t.TempDir(), "identity"))
	o.Token, o.Bundle = in.mint(t), bundle
	if _, err := agent.Enroll(ctx(t), o); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Fatalf("a controller whose chain leads to the extra root: %v, want a refused connection", err)
	}

	url, client := serve(t, in, nil)
	dir := filepath.Join(t.TempDir(), "identity")
	o = opts(in, url, client, dir)
	o.Token, o.Bundle = in.mint(t), bundle
	if _, err := agent.Enroll(ctx(t), o); err != nil {
		t.Fatal(err)
	}
	if roots := pemCerts(t, filepath.Join(dir, agent.RootsFile)); len(roots) != 1 || !roots[0].Equal(in.ca.Root()) {
		t.Errorf("roots.pem keeps %d roots, want only the pinned one", len(roots))
	}

	pinned, key := rootPair(t, "pinned")
	cross := crossSign(t, pinned, key)
	unrelated, _ := rootPair(t, "unrelated")
	got := agent.AcceptRoots(pinned, []*x509.Certificate{cross, unrelated, pinned})
	if len(got) != 2 || !got[0].Equal(pinned) || !got[1].Equal(cross) {
		t.Errorf("accepted %d roots, want the pinned one and the one it cross-signed", len(got))
	}
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func rootPair(t *testing.T, name string) (*x509.Certificate, any) {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

// crossSign issues a certificate for a new root key, signed by parent: what a planned root
// rotation hands out.
func crossSign(t *testing.T, parent *x509.Certificate, parentKey any) *x509.Certificate {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "next root"}, NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestEnroll_RefusedBeforeTheNetwork(t *testing.T) {
	dir := t.TempDir()
	good, _ := token.New(token.Enrollment)
	pat, _ := token.New(token.PersonalAPI)
	pin := "sha256:" + strings.Repeat("A", 43) + "="
	base := agent.EnrollOptions{Controller: "https://127.0.0.1:1", Pin: pin, Token: good, IdentityDir: filepath.Join(dir, "id")}
	cases := map[string]func(o *agent.EnrollOptions){
		"bad pin":               func(o *agent.EnrollOptions) { o.Pin = "sha256:abc" },
		"API token":             func(o *agent.EnrollOptions) { o.Token = pat },
		"mistyped token":        func(o *agent.EnrollOptions) { o.Token = good[:len(good)-1] + "x" },
		"http controller":       func(o *agent.EnrollOptions) { o.Controller = "http://127.0.0.1:1" },
		"relative identity dir": func(o *agent.EnrollOptions) { o.IdentityDir = "identity" },
		"open identity dir": func(o *agent.EnrollOptions) {
			o.IdentityDir = filepath.Join(dir, "open")
			_ = os.Mkdir(o.IdentityDir, 0o755)
		},
	}
	for name, edit := range cases {
		o := base
		edit(&o)
		start := time.Now()
		if _, err := agent.Enroll(context.Background(), o); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "trust bundle") || time.Since(start) > 2*time.Second {
			t.Errorf("%s: reached the network: %v", name, err)
		}
	}
}

func TestReadToken(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("  from-file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string { return map[string]string{"RPMGR_ENROLL_TOKEN": "from-env"}[k] }
	none := func(string) string { return "" }
	prompt := func() (string, error) { return "from-tty\n", nil }
	var warned []string
	warn := func(s string) { warned = append(warned, s) }
	if got, err := agent.ReadToken(file, env, prompt, warn); err != nil || got != "from-file" || len(warned) != 1 {
		t.Errorf("file: %q, %v, warnings %v", got, err, warned)
	}
	if got, err := agent.ReadToken("", env, prompt, warn); err != nil || got != "from-env" {
		t.Errorf("environment: %q, %v", got, err)
	}
	if got, err := agent.ReadToken("", none, prompt, warn); err != nil || got != "from-tty" {
		t.Errorf("terminal: %q, %v", got, err)
	}
	if _, err := agent.ReadToken("", none, nil, warn); err == nil {
		t.Error("no source gave a token")
	}
	if _, err := agent.ReadToken(filepath.Join(dir, "missing"), env, prompt, warn); err == nil {
		t.Error("a missing token file fell back to another source")
	}
}
