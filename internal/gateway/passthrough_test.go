// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// backend is a TLS service with its own certificate for the passthrough hostnames, from a CA the
// test's clients trust; it echoes inside TLS.
func backend(t *testing.T, names ...string) (string, *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "backend CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "the backend"}, DNSNames: names,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
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
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return ln.Addr().String(), pool
}

// TestPassthrough: a TLS connection whose SNI is a passthrough hostname, exactly or under a
// wildcard, reaches the backend still encrypted, so the client sees the backend's own certificate;
// another name gets the default certificate; a removed route's connections are reset after the
// drain period.
func TestPassthrough(t *testing.T) {
	gateway.SetRouteTimers(t, 500*time.Millisecond, time.Second)
	addr, pool := backend(t, "db.example.com", "x.pg.example.com")
	p := newPlaneWith(t, addr, "none", "rt_db")
	pass := gateway.NewPassthrough(p.sessions, nil, nil)
	t.Cleanup(pass.Close)
	def, err := gateway.DefaultTLS()
	if err != nil {
		t.Fatal(err)
	}
	front := serve(t, &gateway.Router{TrustDomain: td, GatewayID: "gw_01", Routes: pass, DefaultTLS: def})
	pass.Apply([]gateway.PassthroughRoute{{ID: "rt_db", Hostnames: []string{"*.pg.example.com", "db.example.com"}}})

	dial := func(sni string) (*tls.Conn, error) {
		return tls.Dial("tcp", front, &tls.Config{ServerName: sni, RootCAs: pool, MinVersion: tls.VersionTLS13})
	}
	var held *tls.Conn
	for _, sni := range []string{"db.example.com", "x.pg.example.com"} {
		var c *tls.Conn
		eventually(t, "no passthrough to the backend for "+sni, func() bool {
			var err error
			c, err = dial(sni)
			return err == nil
		})
		if cn := c.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "the backend" {
			t.Fatalf("%s: the client saw %q, not the backend's certificate", sni, cn)
		}
		if _, err := c.Write([]byte("inside TLS")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 10)
		if _, err := io.ReadFull(c, b); err != nil || string(b) != "inside TLS" {
			t.Fatalf("%s: echo %q %v", sni, b, err)
		}
		held = c
	}
	if _, err := dial("other.example.com"); err == nil || !strings.Contains(err.Error(), "default.invalid") {
		t.Fatalf("a name no route serves: %v, want the default certificate", err)
	}
	if _, err := dial("a.b.pg.example.com"); err == nil {
		t.Fatal("a wildcard matched two labels")
	}

	pass.Apply(nil)
	if _, err := dial("db.example.com"); err == nil {
		t.Fatal("a removed route still answers")
	}
	if _, err := held.Write([]byte("x")); err != nil {
		t.Fatalf("an open connection during the drain period: %v", err)
	}
	_, _ = io.ReadFull(held, make([]byte, 1))
	time.Sleep(800 * time.Millisecond)
	_ = held.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = held.Write([]byte("late"))
	if err == nil {
		_, err = io.ReadFull(held, make([]byte, 4))
	}
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("after the drain period: %v, want a reset", err)
	}
	if pass.Conns() != 0 {
		t.Fatalf("%d connections counted", pass.Conns())
	}
}

// TestApplier_Passthrough: the applier validates passthrough routes and serves them.
func TestApplier_Passthrough(t *testing.T) {
	a, assign := gateway.NewApplier()
	res := func(id string, hostnames ...string) *agentv1.Resource {
		return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_GatewayPassthroughRoute{GatewayPassthroughRoute: &agentv1.GatewayPassthroughRoute{
			Hostnames: hostnames, Connectors: []string{cid("con_p")}}}}
	}
	if errs := a.Validate(gatewaySnapshot(1, res("rt_1", "db.example.com", "*.pg.example.com"), tcpResource("rt_2", 5432, cid("con_p")))); len(errs) != 0 {
		t.Fatal(errs)
	}
	for _, tc := range []struct {
		name string
		snap *agentv1.Snapshot
		want string
	}{
		{"no hostnames", gatewaySnapshot(1, res("rt_1")), "without hostnames"},
		{"not normalised", gatewaySnapshot(1, res("rt_1", "DB.example.com")), "not normalised"},
		{"not a name", gatewaySnapshot(1, res("rt_1", "bad_name.example.com")), "not normalised"},
		{"a hostname twice", gatewaySnapshot(1, res("rt_1", "db.example.com"), res("rt_2", "db.example.com")), "also a hostname of rt_1"},
	} {
		errs := a.Validate(tc.snap)
		if len(errs) == 0 || !strings.Contains(errs[0].GetMessage(), tc.want) {
			t.Errorf("%s: %v, want an error about %q", tc.name, errs, tc.want)
		}
	}
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: assign})
	t.Cleanup(m.Close)
	pass := gateway.NewPassthrough(m, a.Revision, nil)
	t.Cleanup(pass.Close)
	a.Bind(gateway.Served{Passthrough: pass, Sessions: m})
	a.Apply(t.Context(), gatewaySnapshot(3, res("rt_1", "db.example.com")), agent.Changes{})
	if _, ok := pass.Passthrough("db.example.com"); !ok || !assign.Known(cid("con_p")) {
		t.Fatal("the applied passthrough route is not served")
	}
	if _, ok := pass.Passthrough("www.example.com"); ok {
		t.Fatal("another name is served")
	}
}
