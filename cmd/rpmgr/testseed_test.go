// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/org"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routeudp"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/testseed"
	"github.com/felix-homelab/rpmgr/internal/token"
)

func seed(t *testing.T, boot string, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cli.Main(context.Background(), commands(), append([]string{"testseed"}, args...), &cli.Env{Stdout: &out, Stderr: &errOut,
		Getenv: func(k string) string { return map[string]string{"RPMGR_CONFIG": boot}[k] }})
	if code != cli.ExitOK {
		t.Fatalf("testseed %s: exit %d: %s", strings.Join(args, " "), code, errOut.String())
	}
	return strings.TrimSpace(out.String())
}

// TestTestseed: the seeding command writes gateways, tokens, routes, their changes and revocations
// into an initialised controller's database, each as a new revision.
func TestTestseed(t *testing.T) {
	dir := t.TempDir()
	boot, db := filepath.Join(dir, "controller.yaml"), filepath.Join(dir, "lib", "controller.db")
	if err := os.MkdirAll(filepath.Dir(db), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(boot, []byte("version: 1\npublic_url: https://panel.example.com\ndatabase: {dsn: "+db+"}\nkek: {source: file, path: "+
		filepath.Join(dir, "kek")+"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Init(context.Background(), controller.InitOptions{ConfigPath: boot, Getenv: func(string) string { return "" }}); err != nil {
		t.Fatal(err)
	}
	tok := seed(t, boot, "gateway", "--group", "eu", "--name", "gw1", "--endpoint", "gw1.test:443", "--endpoint", "gw1.test:8443")
	if k, err := token.Parse(tok); err != nil || k != token.Enrollment {
		t.Fatalf("gateway token %q: %v", tok, err)
	}
	if k, err := token.Parse(seed(t, boot, "connector-token", "--uses", "2")); err != nil || k != token.Enrollment {
		t.Fatalf("connector token: %v", err)
	}

	st, err := store.OpenSQLite(context.Background(), db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	sys := storetest.SystemCtx(t)
	c := st.Client()
	gw := c.Gateway.Query().Where(gateway.Name("gw1")).OnlyX(sys)
	if len(gw.TunnelEndpoints) != 2 {
		t.Fatalf("gateway %+v", gw)
	}
	o := c.Org.Query().Where(org.Slug(testseed.OrgSlug)).OnlyX(sys)
	con := c.Connector.Create().SetOrgID(o.ID).SetName("con1").SetSpiffeID("spiffe://x/con1").SetPubkeySha256("x").SaveX(sys)
	seed(t, boot, "route", "--name", "echo", "--group", "eu", "--port", "20001", "--connector", "con1", "--target", "10.0.0.5:7",
		"--transport", "h2", "--idle", "90s")
	rt := c.Route.Query().Where(route.Name("echo")).OnlyX(sys)
	targets := c.RouteTarget.Query().Where(routetarget.RouteID(rt.ID)).AllX(sys)
	tcp := c.RouteTCP.Query().Where(routetcp.RouteID(rt.ID)).WithPort().OnlyX(sys)
	if *rt.Transport != "h2" || len(targets) != 1 || targets[0].ConnectorID != con.ID || targets[0].Port != 7 ||
		tcp.IdleTimeoutSeconds != 90 || tcp.Edges.Port.Port != 20001 {
		t.Fatalf("route %+v, targets %+v, tcp %+v", rt, targets, tcp)
	}
	seed(t, boot, "route-update", "--name", "echo", "--idle", "120s", "--transport", "quic", "--enabled", "false")
	rt = c.Route.Query().Where(route.Name("echo")).OnlyX(sys)
	tcp = c.RouteTCP.Query().Where(routetcp.RouteID(rt.ID)).OnlyX(sys)
	if *rt.Transport != "quic" || rt.Enabled || tcp.IdleTimeoutSeconds != 120 {
		t.Fatalf("updated route %+v, tcp %+v", rt, tcp)
	}
	seed(t, boot, "tcp-udp-route", "--name", "dns", "--group", "eu", "--port", "20053", "--connector", "con1", "--target", "10.0.0.5:53")
	dns := c.Route.Query().Where(route.Name("dns")).OnlyX(sys)
	dnsTCP := c.RouteTCP.Query().Where(routetcp.RouteID(dns.ID)).WithPort().OnlyX(sys)
	dnsUDP := c.RouteUDP.Query().Where(routeudp.RouteID(dns.ID)).WithPort().OnlyX(sys)
	if dns.Type != route.TypeTCPUDP || dnsTCP.Edges.Port.Port != 20053 || dnsUDP.Edges.Port.Port != 20053 ||
		dnsTCP.IdleTimeoutSeconds != 3600 || dnsUDP.FlowIdleTimeoutSeconds != 60 {
		t.Fatalf("tcp_udp route %+v, tcp %+v, udp %+v", dns, dnsTCP, dnsUDP)
	}
	seed(t, boot, "revoke", "--kind", "connector", "--name", "con1")
	if n := c.RevokedIdentity.Query().CountX(sys); n != 1 {
		t.Fatalf("%d revoked identities", n)
	}
	entries, err := revlog.Read(filepath.Join(filepath.Dir(db), "revocations.log"))
	if err != nil || len(entries) != 1 || entries[0].Kind != revlog.IdentityRevoked {
		t.Fatalf("revocation log %v %v", entries, err)
	}
	if seq := c.ConfigRevision.Query().CountX(sys); seq != 5 {
		t.Fatalf("%d revisions, want one per configuration write", seq)
	}

	var errOut bytes.Buffer
	code := cli.Main(context.Background(), commands(), []string{"testseed", "--config", boot, "revoke", "--kind", "controller", "--name", "x"},
		&cli.Env{Stdout: &bytes.Buffer{}, Stderr: &errOut, Getenv: func(string) string { return "" }})
	if code == cli.ExitOK {
		t.Fatal("revoking a controller")
	}
}

// TestTestseed_GatewayWSS: gateway-wss gives gateways their WSS hostnames under a verified domain,
// uploading the certificate that covers them once; it refuses a missing or second hostname, an
// unknown gateway and a hostname another gateway has.
func TestTestseed_GatewayWSS(t *testing.T) {
	dir := t.TempDir()
	boot, db := filepath.Join(dir, "controller.yaml"), filepath.Join(dir, "lib", "controller.db")
	if err := os.MkdirAll(filepath.Dir(db), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(boot, []byte("version: 1\npublic_url: https://panel.example.com\ndatabase: {dsn: "+db+"}\nkek: {source: file, path: "+
		filepath.Join(dir, "kek")+"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Init(context.Background(), controller.InitOptions{ConfigPath: boot, Getenv: func(string) string { return "" }}); err != nil {
		t.Fatal(err)
	}
	seed(t, boot, "gateway", "--group", "eu", "--name", "gw1", "--endpoint", "gw1.test:443")
	seed(t, boot, "gateway", "--group", "eu", "--name", "gw2", "--endpoint", "gw2.test:443")
	crt, key := wssCertificate(t, dir, "wss1.example.test", "wss2.example.test")
	seed(t, boot, "gateway-wss", "--name", "gw1", "--hostname", "wss1.example.test", "--cert-file", crt, "--key-file", key)
	seed(t, boot, "gateway-wss", "--name", "gw2", "--hostname", "wss2.example.test")

	st, err := store.OpenSQLite(context.Background(), db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	sys := storetest.SystemCtx(t)
	c := st.Client()
	for gw, want := range map[string]string{"gw1": "wss1.example.test", "gw2": "wss2.example.test"} {
		if g := c.Gateway.Query().Where(gateway.Name(gw)).OnlyX(sys); g.WssHostname == nil || *g.WssHostname != want {
			t.Fatalf("%s: WSS hostname %v, want %s", gw, g.WssHostname, want)
		}
	}
	if d := c.Domain.Query().Where(domain.Fqdn("example.test")).OnlyX(sys); d.Status != domain.StatusVerified {
		t.Fatalf("domain %+v", d)
	}
	if n := c.Certificate.Query().CountX(sys); n != 1 {
		t.Fatalf("%d certificates, want the one uploaded", n)
	}

	for _, args := range [][]string{
		{"--name", "gw1"},
		{"--name", "gw1", "--hostname", "a.example.test", "--hostname", "b.example.test"},
		{"--name", "gw9", "--hostname", "wss9.example.test"},
		{"--name", "gw2", "--hostname", "wss1.example.test"},
		{"--name", "gw2", "--hostname", "wss2.example.test", "--cert-file", filepath.Join(dir, "missing.pem")},
	} {
		var errOut bytes.Buffer
		code := cli.Main(context.Background(), commands(), append([]string{"testseed", "gateway-wss", "--config", boot}, args...),
			&cli.Env{Stdout: &bytes.Buffer{}, Stderr: &errOut, Getenv: func(string) string { return "" }})
		if code == cli.ExitOK {
			t.Errorf("gateway-wss %v succeeded", args)
		}
	}
	if g := c.Gateway.Query().Where(gateway.Name("gw2")).OnlyX(sys); *g.WssHostname != "wss2.example.test" {
		t.Fatalf("a refused change kept gw2's WSS hostname as %s", *g.WssHostname)
	}
}

// wssCertificate writes a self-signed certificate for names and its key, and returns their paths.
func wssCertificate(t *testing.T, dir string, names ...string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	crt, kf := filepath.Join(dir, "wss.crt"), filepath.Join(dir, "wss.key")
	if err := os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return crt, kf
}
