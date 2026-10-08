// SPDX-License-Identifier: Apache-2.0

package itest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
)

// TestHTTPRoute_EndToEnd: an http route configured on the controller, with an uploaded
// certificate, serves HTTPS on the gateway's port 443 from a web app behind the connector, over
// HTTP/1.1 and HTTP/2.
func TestHTTPRoute_EndToEnd(t *testing.T) {
	p := newDataPlane(t)
	c := p.c
	app := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // G705: the test app echoes the request as plain text
		_, _ = fmt.Fprintf(w, "hello %s %s via %s", r.Host, r.URL.Path, r.Header.Get("X-Forwarded-Proto"))
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Serve(ln) }()
	t.Cleanup(func() { _ = app.Close() })
	appPort := ln.Addr().(*net.TCPAddr).Port
	policy := fmt.Sprintf("version: 1\nallow_targets:\n  - cidr: 127.0.0.1/32\n    ports: [%d]\n", appPort)
	if err := os.WriteFile(p.conCfg.PolicyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "app.example.com"},
		DNSNames: []string{"app.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(k)
	if _, err := store.ConfigTx(c.Sys, c.DB, func(tx *ent.Tx) ([]string, error) {
		tcp, err := tx.Route.Get(c.Sys, p.routeID)
		if err != nil {
			return nil, err
		}
		d, err := domains.Claim(c.Sys, tx, c.Org, "example.com", true)
		if err != nil {
			return nil, err
		}
		if err := tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Exec(c.Sys); err != nil {
			return nil, err
		}
		crt, err := certs.Upload(c.Sys, tx, c.Sealer(), c.Org, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), time.Now())
		if err != nil {
			return nil, err
		}
		r, err := tx.Route.Create().SetOrgID(c.Org).SetName("web").SetType("http").SetGatewayGroupID(tcp.GatewayGroupID).Save(c.Sys)
		if err != nil {
			return nil, err
		}
		if err := tx.RouteHTTP.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetTLSMode(routehttp.TLSModeCertificate).
			SetCertificateID(crt.ID).Exec(c.Sys); err != nil {
			return nil, err
		}
		if _, err := routes.AddHostname(c.Sys, tx, r.ID, "app.example.com", ""); err != nil {
			return nil, err
		}
		return []string{r.ID, crt.ID}, tx.RouteTarget.Create().SetOrgID(c.Org).SetRouteID(r.ID).SetConnectorID(p.connector).
			SetKind("address").SetHost("127.0.0.1").SetPort(appPort).SetUpstreamProtocol(routetarget.UpstreamProtocolHTTP).Exec(c.Sys)
	}); err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(der)
	pool.AddCert(leaf)
	for _, h2 := range []bool{false, true} {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(!h2)
		protocols.SetHTTP2(h2)
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Protocols: protocols,
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, p.gwCfg.Listen.TCP)
			}}}
		var body string
		waitFor(t, fmt.Sprintf("the http route does not answer (HTTP/2 %v): %s", h2, body), func() bool {
			resp, err := client.Get("https://app.example.com/page")
			if err != nil {
				body = err.Error()
				return false
			}
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(resp.Body)
			body = string(b)
			return resp.StatusCode == http.StatusOK && resp.ProtoMajor == map[bool]int{false: 1, true: 2}[h2]
		})
		if body != "hello app.example.com /page via https" {
			t.Fatalf("body %q", body)
		}
	}
}
