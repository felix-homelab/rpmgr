// SPDX-License-Identifier: Apache-2.0

package pki_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

// agent is what an agent holds: its leaf and the tls.Certificate with the chain.
type agent struct {
	cert *x509.Certificate
	tls  tls.Certificate
}

func (c *ca) clock() time.Time { return c.now }

func (c *ca) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.root.Cert)
	return p
}

func (c *ca) agent(t *testing.T, id pki.Identity, lifetime time.Duration) agent {
	t.Helper()
	k := newKey(t)
	cert, err := c.is.IssueLeaf(csrFor(t, k, nil), id, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	return agent{cert: cert, tls: tls.Certificate{Certificate: [][]byte{cert.Raw, c.inter.Cert.Raw}, PrivateKey: k, Leaf: cert}}
}

func (c *ca) forged(t *testing.T, uris, dns []string) agent {
	t.Helper()
	cert, key := forgeLeafWithKey(t, c.inter, uris, dns)
	return agent{cert: cert, tls: tls.Certificate{Certificate: [][]byte{cert.Raw, c.inter.Cert.Raw}, PrivateKey: key, Leaf: cert}}
}

func gateway(org, id string) pki.Identity {
	return pki.Identity{TrustDomain: td, Org: org, Kind: pki.KindGateway, ID: id}
}

func node(id string) pki.Identity {
	return pki.Identity{TrustDomain: td, Kind: pki.KindController, ID: id}
}

// denyList is a test deny-list by serial and by identity.
type denyList struct {
	mu   sync.Mutex
	deny map[string]bool
}

func (d *denyList) add(s string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.deny == nil {
		d.deny = map[string]bool{}
	}
	d.deny[s] = true
}

func (d *denyList) denied(c *x509.Certificate) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.deny[c.SerialNumber.String()] || (len(c.URIs) == 1 && d.deny[c.URIs[0].String()])
}

// counter wraps a configuration's VerifyConnection and counts its calls, and those on resumed
// handshakes.
type counter struct{ calls, resumed atomic.Int32 }

func (n *counter) wrap(cfg *tls.Config) *tls.Config {
	next := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		n.calls.Add(1)
		if cs.DidResume {
			n.resumed.Add(1)
		}
		return next(cs)
	}
	return cfg
}

type result struct {
	srv, cli       tls.ConnectionState
	srvErr, cliErr error
}

func (r result) ok() bool { return r.srvErr == nil && r.cliErr == nil }

// run performs one TLS connection over loopback TCP. After the handshake the server writes a byte
// and the client answers one, so the client processes the server's NewSessionTicket and a later
// connection can resume.
func run(t *testing.T, srvCfg, cliCfg *tls.Config) result {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var r result
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			r.srvErr = err
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		tc := tls.Server(c, srvCfg)
		if r.srvErr = tc.Handshake(); r.srvErr != nil {
			return
		}
		r.srv = tc.ConnectionState()
		if _, r.srvErr = tc.Write([]byte{1}); r.srvErr == nil {
			_, r.srvErr = io.ReadFull(tc, make([]byte, 1))
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	tc := tls.Client(c, cliCfg)
	if r.cliErr = tc.Handshake(); r.cliErr == nil {
		r.cli = tc.ConnectionState()
		if _, r.cliErr = io.ReadFull(tc, make([]byte, 1)); r.cliErr == nil {
			_, r.cliErr = tc.Write([]byte{1})
		}
	}
	_ = tc.Close()
	<-done
	return r
}

// TestTLS_VerifyConnectionOnResumption: Go runs VerifyConnection on resumed TLS 1.3 handshakes on
// both sides, so an identity revoked after the first handshake is refused on resumption, and a
// ticket is not resumed after its certificate expired.
func TestTLS_VerifyConnectionOnResumption(t *testing.T) {
	c := newCA(t, td)
	conID, gwID := connector(orgA, con1), gateway(orgA, gw1)
	con := c.agent(t, conID, pki.DefaultLeafLifetime)
	gw := c.agent(t, gwID, pki.MaxLeafLifetime)
	setup := func(cliCert agent) (srv, cli *tls.Config, sn, cn *counter, sd, cd *denyList) {
		sn, cn, sd, cd = &counter{}, &counter{}, &denyList{}, &denyList{}
		srv = sn.wrap(pki.ServerConfig(gw.tls, c.pool(), pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}, Denied: sd.denied}, c.clock))
		cli = cn.wrap(pki.ClientConfig(cliCert.tls, c.pool(), gwID.DNSName(), pki.Expect{TrustDomain: td, Exact: &gwID, Denied: cd.denied},
			c.clock, tls.NewLRUClientSessionCache(8)))
		return
	}
	t.Run("both sides verify the resumed handshake", func(t *testing.T) {
		srv, cli, sn, cn, _, _ := setup(con)
		r1, r2 := run(t, srv, cli), run(t, srv, cli)
		if !r1.ok() || !r2.ok() {
			t.Fatalf("%v %v %v %v", r1.srvErr, r1.cliErr, r2.srvErr, r2.cliErr)
		}
		if r1.srv.DidResume || !r2.srv.DidResume || !r2.cli.DidResume {
			t.Fatalf("resumed: first %v, second server %v client %v", r1.srv.DidResume, r2.srv.DidResume, r2.cli.DidResume)
		}
		for name, n := range map[string]*counter{"server": sn, "client": cn} {
			if n.calls.Load() != 2 || n.resumed.Load() != 1 {
				t.Errorf("%s: VerifyConnection %d times, %d resumed; want 2 and 1", name, n.calls.Load(), n.resumed.Load())
			}
		}
	})
	t.Run("connector revoked after the first handshake", func(t *testing.T) {
		srv, cli, sn, _, sd, _ := setup(con)
		if r := run(t, srv, cli); !r.ok() {
			t.Fatal(r.srvErr, r.cliErr)
		}
		sd.add(conID.String())
		if r := run(t, srv, cli); !errors.Is(r.srvErr, pki.ErrDenied) || r.cliErr == nil {
			t.Fatalf("server %v, client %v", r.srvErr, r.cliErr)
		}
		if sn.resumed.Load() != 1 {
			t.Fatalf("the refused handshake was no resumption (%d resumed)", sn.resumed.Load())
		}
	})
	t.Run("gateway revoked after the first handshake", func(t *testing.T) {
		srv, cli, _, cn, _, cd := setup(con)
		if r := run(t, srv, cli); !r.ok() {
			t.Fatal(r.srvErr, r.cliErr)
		}
		cd.add(gw.cert.SerialNumber.String())
		if r := run(t, srv, cli); !errors.Is(r.cliErr, pki.ErrDenied) {
			t.Fatalf("client %v", r.cliErr)
		}
		if cn.resumed.Load() != 1 {
			t.Fatalf("the refused handshake was no resumption (%d resumed)", cn.resumed.Load())
		}
	})
	t.Run("ticket of an expired client certificate", func(t *testing.T) {
		defer func() { c.now = t0 }()
		short := c.agent(t, conID, pki.MinLeafLifetime) // tickets and ticket keys outlive it
		srv, cli, sn, _, _, _ := setup(short)
		if r := run(t, srv, cli); !r.ok() {
			t.Fatal(r.srvErr, r.cliErr)
		}
		c.now = short.cert.NotAfter.Add(-time.Minute)
		if r := run(t, srv, cli); !r.ok() || !r.srv.DidResume {
			t.Fatalf("control: resumption before the expiry: %v %v %v", r.srvErr, r.cliErr, r.srv.DidResume)
		}
		c.now = short.cert.NotAfter.Add(time.Minute)
		r := run(t, srv, cli)
		var cie x509.CertificateInvalidError
		if r.srv.DidResume || !errors.As(r.srvErr, &cie) || cie.Reason != x509.Expired || sn.resumed.Load() != 1 {
			t.Fatalf("server %v, resumed %v; want an expiry error from a full handshake", r.srvErr, r.srv.DidResume)
		}
	})
}

// TestSPIFFE_TrustDomainExact: a URI SAN whose host is a sub-domain of the trust domain, or the
// trust domain in other case, passes the name constraints and is refused by VerifyConnection; a
// URI or DNS name outside the trust domain is refused by the name constraints. Both sides check.
func TestSPIFFE_TrustDomainExact(t *testing.T) {
	c := newCA(t, td)
	gwID := gateway(orgA, gw1)
	con := c.agent(t, connector(orgA, con1), pki.DefaultLeafLifetime)
	gw := c.agent(t, gwID, pki.DefaultLeafLifetime)
	path := "/org/" + orgA + "/gateway/" + gw1
	cli := func(own agent) *tls.Config {
		return pki.ClientConfig(own.tls, c.pool(), gwID.DNSName(), pki.Expect{TrustDomain: td, Exact: &gwID}, c.clock, nil)
	}
	srv := func(own agent) *tls.Config {
		return pki.ServerConfig(own.tls, c.pool(), pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}}, c.clock)
	}
	for name, uri := range map[string]string{
		"sub-domain host":         "spiffe://evil." + td + path,
		"host in another case":    "spiffe://" + strings.ToUpper(td) + path,
		"trust domain only":       "spiffe://" + td,
		"signing key URI":         pki.SignerURI(td, pki.PurposeConfigSigning).String(),
		"identity of another org": "spiffe://" + td + "/org/" + ids.New("org") + "/gateway/" + gw1,
	} {
		t.Run(name, func(t *testing.T) {
			f := c.forged(t, []string{uri}, []string{gwID.DNSName()})
			if r := run(t, srv(f), cli(con)); !errors.Is(r.cliErr, pki.ErrWrongIdentity) {
				t.Fatalf("client: %v, want ErrWrongIdentity", r.cliErr)
			}
			if r := run(t, srv(gw), cli(f)); !errors.Is(r.srvErr, pki.ErrWrongIdentity) {
				t.Fatalf("server: %v, want ErrWrongIdentity", r.srvErr)
			}
			if _, err := pki.ParseSPIFFE(f.cert.URIs[0], td); err == nil {
				return // a well-formed identity: only Exact or Kinds refuse it
			}
			anyRole := pki.ServerConfig(gw.tls, c.pool(), pki.Expect{TrustDomain: td}, c.clock)
			if r := run(t, anyRole, cli(f)); !errors.Is(r.srvErr, pki.ErrWrongIdentity) {
				t.Fatalf("server accepting every role: %v, want ErrWrongIdentity", r.srvErr)
			}
		})
	}
	for name, names := range map[string][2]string{
		"URI in another trust domain": {"spiffe://rpmgr-aaaaaaaa" + path, gwID.DNSName()},
		"URI host x<td>":              {"spiffe://x" + td + path, gwID.DNSName()},
		"DNS name in another domain":  {gwID.String(), gw1 + ".gateway.rpmgr-aaaaaaaa"},
	} {
		t.Run(name, func(t *testing.T) {
			f := c.forged(t, []string{names[0]}, []string{gwID.DNSName(), names[1]})
			var cie x509.CertificateInvalidError
			if r := run(t, srv(f), cli(con)); !errors.As(r.cliErr, &cie) || cie.Reason != x509.CANotAuthorizedForThisName {
				t.Fatalf("client: %v, want a name-constraint error", r.cliErr)
			}
		})
	}
}

// TestServerNamePerPeer: a client names the peer it expects; a valid certificate of another
// gateway, a wrong SPIFFE ID, a denied serial or identity, a missing ServerName and TLS 1.2 are
// refused.
func TestServerNamePerPeer(t *testing.T) {
	c := newCA(t, td)
	conID, g1ID, g2ID := connector(orgA, con1), gateway(orgA, gw1), gateway(ids.New("org"), ids.New("gw"))
	con := c.agent(t, conID, pki.DefaultLeafLifetime)
	g1 := c.agent(t, g1ID, pki.DefaultLeafLifetime)
	g2 := c.agent(t, g2ID, pki.DefaultLeafLifetime)
	gwSide := func(own agent, d *denyList) *tls.Config {
		return pki.ServerConfig(own.tls, c.pool(), pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}, Denied: d.denied}, c.clock)
	}
	conSide := func(own agent, sni string, d *denyList) *tls.Config {
		return pki.ClientConfig(own.tls, c.pool(), sni, pki.Expect{TrustDomain: td, Exact: &g1ID, Denied: d.denied}, c.clock, nil)
	}
	none := &denyList{}
	if r := run(t, gwSide(g1, none), conSide(con, g1ID.DNSName(), none)); !r.ok() || r.cli.Version != tls.VersionTLS13 {
		t.Fatalf("expected gateway: %v %v, version %x", r.srvErr, r.cliErr, r.cli.Version)
	}
	var he x509.HostnameError
	if r := run(t, gwSide(g2, none), conSide(con, g1ID.DNSName(), none)); !errors.As(r.cliErr, &he) {
		t.Errorf("valid certificate of another gateway: %v, want a hostname error", r.cliErr)
	}
	f := c.forged(t, []string{g2ID.String()}, []string{g1ID.DNSName()})
	if r := run(t, gwSide(f, none), conSide(con, g1ID.DNSName(), none)); !errors.Is(r.cliErr, pki.ErrWrongIdentity) {
		t.Errorf("right DNS name, wrong SPIFFE ID: %v", r.cliErr)
	}
	for name, key := range map[string]string{"serial": g1.cert.SerialNumber.String(), "identity": g1ID.String()} {
		d := &denyList{}
		d.add(key)
		if r := run(t, gwSide(g1, none), conSide(con, g1ID.DNSName(), d)); !errors.Is(r.cliErr, pki.ErrDenied) {
			t.Errorf("gateway %s on the connector's deny-list: %v", name, r.cliErr)
		}
	}
	d := &denyList{}
	d.add(con.cert.SerialNumber.String())
	if r := run(t, gwSide(g1, d), conSide(con, g1ID.DNSName(), none)); !errors.Is(r.srvErr, pki.ErrDenied) || r.cliErr == nil {
		t.Errorf("connector on the gateway's deny-list: server %v, client %v", r.srvErr, r.cliErr)
	}
	if r := run(t, gwSide(g1, none), conSide(g2, g1ID.DNSName(), none)); !errors.Is(r.srvErr, pki.ErrWrongIdentity) {
		t.Errorf("a gateway certificate opening a data session: %v", r.srvErr)
	}
	if r := run(t, gwSide(g1, none), conSide(con, "", none)); r.cliErr == nil || !strings.Contains(r.cliErr.Error(), "ServerName") {
		t.Errorf("no ServerName: %v", r.cliErr)
	}
	old := conSide(con, g1ID.DNSName(), none)
	old.MinVersion, old.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	if r := run(t, gwSide(g1, none), old); r.ok() {
		t.Error("a TLS 1.2 handshake succeeded")
	}
	other := newCA(t, td).agent(t, g1ID, pki.DefaultLeafLifetime)
	var ua x509.UnknownAuthorityError
	if r := run(t, gwSide(other, none), conSide(con, g1ID.DNSName(), none)); !errors.As(r.cliErr, &ua) {
		t.Errorf("a gateway certificate of another CA: %v, want an unknown-authority error", r.cliErr)
	}

	ctl := c.agent(t, node(ctn1), pki.ControllerLifetime)
	ctlSrv := pki.ServerConfig(ctl.tls, c.pool(), pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector, pki.KindGateway}}, c.clock)
	toCtl := func(sni string) *tls.Config {
		return pki.ClientConfig(con.tls, c.pool(), sni, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindController}}, c.clock, nil)
	}
	for _, sni := range []string{"controller." + td, "reauth.controller." + td, ctn1 + ".controller." + td} {
		if r := run(t, ctlSrv, toCtl(sni)); !r.ok() {
			t.Errorf("controller name %s: %v %v", sni, r.srvErr, r.cliErr)
		}
	}
	posing := pki.ServerConfig(g2.tls, c.pool(), pki.Expect{TrustDomain: td}, c.clock)
	if r := run(t, posing, toCtl("controller."+td)); !errors.As(r.cliErr, &he) {
		t.Errorf("a gateway posing as the controller: %v", r.cliErr)
	}
}

// reauthEnv is a controller agent endpoint with a Reauth verifier and an agent leaf.
type reauthEnv struct {
	c        *ca
	agent    agent
	grace    time.Duration
	checkErr error
}

func (e *reauthEnv) server(t *testing.T) *tls.Config {
	t.Helper()
	ctl := e.c.agent(t, node(ctn1), pki.ControllerLifetime) // valid at the current fake time
	return pki.AgentEndpointConfig(ctl.tls, e.c.pool(), pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector, pki.KindGateway}},
		e.c.clock, pki.Reauth{
			Grace: func() time.Duration { return e.grace },
			Check: func(*x509.Certificate) error { return e.checkErr },
		})
}

func (e *reauthEnv) client(own agent, sni string, cache tls.ClientSessionCache) *tls.Config {
	return pki.ClientConfig(own.tls, e.c.pool(), sni, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindController}}, e.c.clock, cache)
}

// TestReauth: SNI reauth.controller.<td> accepts a client certificate expired at most the grace
// period ago and nothing older, runs the database check, and verifies the chain; the normal name
// never accepts an expired certificate.
func TestReauth(t *testing.T) {
	c := newCA(t, td)
	e := &reauthEnv{c: c, agent: c.agent(t, connector(orgA, con1), pki.DefaultLeafLifetime), grace: 30 * 24 * time.Hour}
	expiry := e.agent.cert.NotAfter
	normal, reauth := "controller."+td, "reauth.controller."+td
	at := func(t time.Time) { c.now = t }
	defer at(t0)

	at(expiry.Add(29 * 24 * time.Hour))
	var cie x509.CertificateInvalidError
	if r := run(t, e.server(t), e.client(e.agent, normal, nil)); !errors.As(r.srvErr, &cie) || cie.Reason != x509.Expired {
		t.Errorf("normal name with an expired certificate: %v", r.srvErr)
	}
	if r := run(t, e.server(t), e.client(e.agent, reauth, nil)); !r.ok() {
		t.Errorf("reauth name, expired 29 days ago: %v %v", r.srvErr, r.cliErr)
	}
	if r := run(t, e.server(t), e.client(e.agent, strings.ToUpper(reauth[:6])+reauth[6:], nil)); !r.ok() {
		t.Errorf("reauth name in another case: %v %v", r.srvErr, r.cliErr)
	}
	at(expiry.Add(e.grace))
	if r := run(t, e.server(t), e.client(e.agent, reauth, nil)); !r.ok() {
		t.Errorf("at the end of the grace period: %v %v", r.srvErr, r.cliErr)
	}
	at(expiry.Add(e.grace + time.Second))
	if r := run(t, e.server(t), e.client(e.agent, reauth, nil)); !errors.Is(r.srvErr, pki.ErrExpiredGrace) {
		t.Errorf("one second after the grace period: %v", r.srvErr)
	}
	e.grace = 0
	at(expiry.Add(time.Second))
	if r := run(t, e.server(t), e.client(e.agent, reauth, nil)); !errors.Is(r.srvErr, pki.ErrExpiredGrace) {
		t.Errorf("grace 0, expired: %v", r.srvErr)
	}
	at(t0.Add(time.Hour))
	if r := run(t, e.server(t), e.client(e.agent, reauth, nil)); !r.ok() {
		t.Errorf("grace 0, not expired: %v %v", r.srvErr, r.cliErr)
	}
	e.grace = 30 * 24 * time.Hour
	e.checkErr = errors.New("superseded")
	if r := run(t, e.server(t), e.client(e.agent, reauth, nil)); !errors.Is(r.srvErr, e.checkErr) {
		t.Errorf("database check refused: %v", r.srvErr)
	}
	e.checkErr = nil
	at(t0.Add(2 * time.Hour))
	future := c.agent(t, connector(orgA, con1), pki.DefaultLeafLifetime)
	at(t0.Add(time.Hour))
	if r := run(t, e.server(t), e.client(future, reauth, nil)); r.srvErr == nil || !strings.Contains(r.srvErr.Error(), "not yet valid") {
		t.Errorf("a certificate that is not yet valid: %v", r.srvErr)
	}
	at(expiry.Add(24 * time.Hour))
	foreign := newCA(t, td).agent(t, connector(orgA, con1), pki.DefaultLeafLifetime)
	if r := run(t, e.server(t), e.client(foreign, reauth, nil)); r.srvErr == nil || !strings.Contains(r.srvErr.Error(), "chain") {
		t.Errorf("a certificate of another CA: %v", r.srvErr)
	}
	nodeLeaf := c.agent(t, node(ids.New("ctn")), pki.ControllerLifetime)
	if r := run(t, e.server(t), e.client(nodeLeaf, reauth, nil)); !errors.Is(r.srvErr, pki.ErrWrongIdentity) {
		t.Errorf("a controller node certificate at Reauth: %v", r.srvErr)
	}
	unconfigured := pki.AgentEndpointConfig(c.agent(t, node(ctn1), pki.ControllerLifetime).tls, c.pool(),
		pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}}, c.clock, pki.Reauth{})
	if r := run(t, unconfigured, e.client(e.agent, reauth, nil)); r.srvErr == nil {
		t.Error("Reauth without a database check accepted a certificate")
	}
}

// TestReauth_NoSessionTickets: the reauth.controller.<td> configuration issues no session ticket
// and resumes none, not even a ticket from controller.<td>.
func TestReauth_NoSessionTickets(t *testing.T) {
	c := newCA(t, td)
	e := &reauthEnv{c: c, agent: c.agent(t, connector(orgA, con1), pki.DefaultLeafLifetime), grace: 30 * 24 * time.Hour}
	srv := e.server(t)
	normal, reauth := "controller."+td, "reauth.controller."+td
	normalCache := tls.NewLRUClientSessionCache(4)
	if r := run(t, srv, e.client(e.agent, normal, normalCache)); !r.ok() {
		t.Fatal(r.srvErr, r.cliErr)
	}
	session, ok := normalCache.Get(normal)
	if !ok || session == nil {
		t.Fatal("control: controller.<td> issued no ticket")
	}
	if r := run(t, srv, e.client(e.agent, normal, normalCache)); !r.ok() || !r.srv.DidResume {
		t.Fatalf("control: the ticket does not resume at controller.<td>: %v %v", r.srvErr, r.cliErr)
	}
	cache := &offeringCache{offer: session}
	r := run(t, srv, e.client(e.agent, reauth, cache))
	if !r.ok() || r.srv.DidResume || r.cli.DidResume {
		t.Fatalf("server %v, client %v, resumed %v", r.srvErr, r.cliErr, r.srv.DidResume)
	}
	if !cache.offered.Load() || cache.stored.Load() != 0 {
		t.Fatalf("ticket offered %v, tickets received %d", cache.offered.Load(), cache.stored.Load())
	}
}

// offeringCache offers one session for every server name and counts the tickets it receives.
type offeringCache struct {
	offer   *tls.ClientSessionState
	offered atomic.Bool
	stored  atomic.Int32
}

func (c *offeringCache) Get(string) (*tls.ClientSessionState, bool) {
	c.offered.Store(true)
	return c.offer, true
}

func (c *offeringCache) Put(_ string, cs *tls.ClientSessionState) {
	if cs != nil {
		c.stored.Add(1)
	}
}

// recorder keeps every byte the client writes.
type recorder struct {
	net.Conn
	mu  sync.Mutex
	out bytes.Buffer
}

func (r *recorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.out.Write(b)
	r.mu.Unlock()
	return r.Conn.Write(b)
}

// TestNoReplayableHandshake: a recorded control-session handshake, full or resumed, replayed later
// yields no session and delivers none of its data. crypto/tls implements early data (0-RTT) only
// for QUIC (tls.QUICConn), never over TCP, and the constructors allow TLS 1.3 only, so every
// recorded connection is a complete handshake: the server answers a replay with a fresh random
// and key share, every key the client derived for the recording differs, and the replayed
// encrypted flight does not decrypt before any certificate is verified.
func TestNoReplayableHandshake(t *testing.T) {
	c := newCA(t, td)
	con := c.agent(t, connector(orgA, con1), pki.DefaultLeafLifetime)
	ctl := c.agent(t, node(ctn1), pki.ControllerLifetime)
	n := &counter{}
	srv := n.wrap(pki.ServerConfig(ctl.tls, c.pool(), pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}}, c.clock))
	cli := pki.ClientConfig(con.tls, c.pool(), "controller."+td, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindController}},
		c.clock, tls.NewLRUClientSessionCache(4))
	secret := []byte("control-session command")

	record := func() ([]byte, bool) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		got := make(chan []byte, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				got <- nil
				return
			}
			defer func() { _ = conn.Close() }()
			tc := tls.Server(conn, srv)
			b := make([]byte, len(secret))
			if _, err := tc.Write([]byte{1}); err != nil { // carries the session ticket
				got <- nil
				return
			}
			if _, err := io.ReadFull(tc, b); err != nil {
				got <- nil
				return
			}
			got <- b
		}()
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		rec := &recorder{Conn: raw}
		tc := tls.Client(rec, cli)
		if _, err := io.ReadFull(tc, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		if _, err := tc.Write(secret); err != nil {
			t.Fatal(err)
		}
		if b := <-got; !bytes.Equal(b, secret) {
			t.Fatal("control: the recorded session did not deliver its data")
		}
		resumed := tc.ConnectionState().DidResume
		_ = tc.Close()
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return bytes.Clone(rec.out.Bytes()), resumed
	}
	replay := func(recording []byte) (int, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = raw.Close() }()
		go func() { _, _ = io.Copy(io.Discard, raw) }()
		go func() { _, _ = raw.Write(recording) }()
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		tc := tls.Server(conn, srv)
		herr := tc.Handshake()
		b, _ := io.ReadAll(io.LimitReader(tc, int64(len(secret))))
		return len(b), herr
	}

	full, resumed := record()
	if resumed {
		t.Fatal("control: the first recording resumed")
	}
	again, resumed := record()
	if !resumed {
		t.Fatal("control: the second recording did not resume")
	}
	before := n.calls.Load()
	got, err := replay(full)
	if err == nil || got != 0 {
		t.Errorf("full handshake replayed: handshake error %v, %d bytes of data delivered", err, got)
	}
	t.Logf("full handshake replayed: %v", err)
	if n.calls.Load() != before {
		t.Error("a replayed full handshake reached VerifyConnection: its certificate decrypted")
	}
	// On resumption the server checks the ticket's identity before it reads the client's Finished
	// (crypto/tls/handshake_server_tls13.go, readClientCertificate), so the replay reaches
	// VerifyConnection; the Finished of the recording does not verify, and the handshake fails.
	got, err = replay(again)
	if err == nil || got != 0 {
		t.Errorf("resumed handshake replayed: handshake error %v, %d bytes of data delivered", err, got)
	}
	t.Logf("resumed handshake replayed: %v", err)
}

// TestConfigs: the constructors' observable properties.
func TestConfigs(t *testing.T) {
	c := newCA(t, td)
	con := c.agent(t, connector(orgA, con1), pki.DefaultLeafLifetime)
	e := pki.Expect{TrustDomain: td}
	cli := pki.ClientConfig(con.tls, c.pool(), "controller."+td, e, nil, nil)
	srv := pki.ServerConfig(con.tls, c.pool(), e, nil)
	ep := pki.AgentEndpointConfig(con.tls, c.pool(), e, nil, pki.Reauth{})
	for name, cfg := range map[string]*tls.Config{"client": cli, "server": srv, "agent endpoint": ep} {
		if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 || cfg.VerifyConnection == nil {
			t.Errorf("%s: versions %x–%x, VerifyConnection set %v", name, cfg.MinVersion, cfg.MaxVersion, cfg.VerifyConnection != nil)
		}
	}
	if !cli.RootCAs.Equal(c.pool()) || cli.ServerName != "controller."+td || cli.Certificates[0].Leaf != con.cert {
		t.Error("client: roots, ServerName or certificate")
	}
	if srv.ClientAuth != tls.RequireAndVerifyClientCert || !srv.ClientCAs.Equal(c.pool()) {
		t.Errorf("server: client auth %v", srv.ClientAuth)
	}
	for sni, wantReauth := range map[string]bool{"reauth.controller." + td: true, "Reauth.Controller." + td: true, "controller." + td: false, "": false} {
		got, err := ep.GetConfigForClient(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil || (got != nil) != wantReauth {
			t.Errorf("SNI %q: reauth configuration %v, %v", sni, got != nil, err)
			continue
		}
		if got != nil && (!got.SessionTicketsDisabled || got.ClientAuth != tls.RequireAnyClientCert ||
			got.MinVersion != tls.VersionTLS13 || got.GetConfigForClient != nil) {
			t.Errorf("reauth configuration: tickets disabled %v, client auth %v", got.SessionTicketsDisabled, got.ClientAuth)
		}
	}
}
