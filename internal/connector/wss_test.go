// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/policy"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// wssHost is the gateways' WSS hostname in these tests.
const wssHost = "tunnel.example.com"

// publicCA is a CA of the public web PKI, as issues a WSS hostname's certificate, or the CA of a
// proxy that intercepts TLS, which the connector's host trusts.
type publicCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newPublicCA(t *testing.T, name string) *publicCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	ca := &publicCA{cert: cert, key: key, pool: x509.NewCertPool()}
	ca.pool.AddCert(cert)
	return ca
}

// leaf issues a server certificate for host.
func (ca *publicCA) leaf(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// serveWSS makes the gateway serve the WSS transport on a listener of its own, which stands for
// port 443 of its WSS hostname, with a certificate of ca for wssHost; it returns the address.
func (g *testGateway) serveWSS(t *testing.T, ca *publicCA) string {
	t.Helper()
	cert, err := ca.leaf(wssHost)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	outer := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			g.wssConns.Add(1)
			g.track(c)
			go gateway.ServeWSS(tls.Server(c, outer), g.h2, g.serveH2)
		}
	}()
	return ln.Addr().String()
}

// dialVia dials addresses as hosts maps them, and others directly, counting the dials per
// address.
type dialVia struct {
	hosts map[string]string
	mu    sync.Mutex
	dials map[string]int
}

func (d *dialVia) dial(ctx context.Context, addr string) (net.Conn, error) {
	d.mu.Lock()
	if d.dials == nil {
		d.dials = map[string]int{}
	}
	d.dials[addr]++
	d.mu.Unlock()
	if to, ok := d.hosts[addr]; ok {
		addr = to
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", addr)
}

func (d *dialVia) count(addr string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials[addr]
}

// TestWSS_PinnedRootMismatch: the inner TLS over WSS pins the controller's root as over TCP: a
// gateway whose certificate, with the right identity, chains to another root gets no session,
// although the outer TLS is valid, and the pinned route is transport_unavailable: wss.
func TestWSS_PinnedRootMismatch(t *testing.T) {
	w := newWorld(t)
	root, _ := pki.NewRoot(td, time.Now())
	inter, _ := pki.NewIntermediate(root, time.Now())
	is, err := pki.NewIssuer(root.Cert, inter, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, is, inter, id))
	ca := newPublicCA(t, "public root")
	via := &dialVia{hosts: map[string]string{wssHost + ":443": g.serveWSS(t, ca)}}
	m := newConnectorOptions(t, w, func(o *connector.Options) { o.Dial, o.PublicRoots = via.dial, ca.pool })
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr}, WSSHostname: wssHost,
		Routes: map[string]string{"rt_1": connector.TransportWSS}}})
	select {
	case err := <-g.tcpErrs:
		t.Logf("the inner handshake failed as expected: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no inner handshake failed")
	}
	eventually(t, "the pinned route is not transport_unavailable: wss", func() bool {
		st := m.Status()
		return len(st) == 1 && st[0].GetResourceId() == "rt_1" && st[0].GetDetail() == connector.TransportWSS &&
			st[0].GetReason() == agentv1.NotReadyReason_NOT_READY_REASON_TRANSPORT_UNAVAILABLE
	})
	if got := m.Count(); len(got) != 0 || len(g.sessions.Load().Count()) != 0 {
		t.Fatalf("sessions %v to a gateway of another root", got)
	}
}

// TestWSS_PinWithoutHostname: a route pinned to wss on a gateway without a WSS hostname never
// dials and is transport_unavailable: wss.
func TestWSS_PinWithoutHostname(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	via := &dialVia{}
	m := newConnectorOptions(t, w, func(o *connector.Options) { o.Dial = via.dial })
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_1": connector.TransportWSS}}})
	eventually(t, "the pinned route is not transport_unavailable: wss", func() bool {
		st := m.Status()
		return len(st) == 1 && st[0].GetDetail() == connector.TransportWSS
	})
	if via.count(g.addr) != 0 || g.tcpConns.Load() != 0 {
		t.Fatal("a pin to wss fell back to the tunnel endpoint")
	}
}

// interceptor is an HTTP CONNECT proxy that intercepts TLS, as some corporate proxies do: it ends
// the client's TLS with a certificate of its own CA for the requested name, opens its own TLS to
// the target, trusting upstream, and records the plaintext both ways.
type interceptor struct {
	addr    string
	mu      sync.Mutex
	targets []string
	plain   bytes.Buffer
	refused atomic.Int64 // client handshakes that failed
}

func (p *interceptor) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.plain.Write(b)
}

func (p *interceptor) saw(s string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Contains(p.plain.Bytes(), []byte(s))
}

func (p *interceptor) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.targets)
}

// startInterceptor starts the proxy; route maps a CONNECT target to the address it dials.
func startInterceptor(t *testing.T, ca *publicCA, upstream *x509.CertPool, route func(string) string) *interceptor {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	p := &interceptor{addr: ln.Addr().String()}
	var conns sync.WaitGroup
	t.Cleanup(conns.Wait)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Go(func() { p.serve(c, ca, upstream, route) })
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *interceptor) serve(c net.Conn, ca *publicCA, upstream *x509.CertPool, route func(string) string) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect || br.Buffered() != 0 {
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, req.Host)
	p.mu.Unlock()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var sni string
	down := tls.Server(c, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni = hi.ServerName
			cert, err := ca.leaf(hi.ServerName)
			return &cert, err
		}})
	if err := down.Handshake(); err != nil {
		p.refused.Add(1)
		return
	}
	up, err := tls.Dial("tcp", route(req.Host), &tls.Config{MinVersion: tls.VersionTLS12, ServerName: sni, RootCAs: upstream,
		NextProtos: []string{"http/1.1"}})
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	_ = c.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.MultiWriter(up, p), down)
		_ = up.CloseWrite()
		close(done)
	}()
	_, _ = io.Copy(io.MultiWriter(down, p), up)
	_ = down.Close()
	<-done
}

// TestWSS_AutoThroughInterceptingProxy: behind an HTTPS_PROXY that intercepts TLS and with UDP
// blocked, auto's TLS over TCP fails in its handshake, because the proxy's certificate does not
// chain to the pinned root; auto then reaches the gateway over WSS through the same proxy, which
// verifies the WSS hostname's public certificate and sees the upgrade, but no byte of the data
// session in the clear.
func TestWSS_AutoThroughInterceptingProxy(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	public, corporate := newPublicCA(t, "public root"), newPublicCA(t, "corporate proxy root")
	wssAddr := g.serveWSS(t, public)
	_, port, _ := net.SplitHostPort(g.addr)
	ep := net.JoinHostPort("gw.test", port)
	p := startInterceptor(t, corporate, public.pool, func(target string) string {
		if target == wssHost+":443" {
			return wssAddr
		}
		return loopback(target)
	})
	dial, err := connector.ProxyDialer(env(map[string]string{"HTTPS_PROXY": "http://" + p.addr}))
	if err != nil {
		t.Fatal(err)
	}
	// No QUIC transport: UDP is blocked.
	m := connector.New(connector.Options{TLS: w.clientTLS, Dial: dial, PublicRoots: corporate.pool, Streams: echoStream,
		LocalAddr: func(context.Context, string) (netip.Addr, error) { return netip.MustParseAddr("192.0.2.1"), nil }})
	t.Cleanup(m.Close)
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true})
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{ep}, WSSHostname: wssHost,
		Routes: map[string]string{"rt_1": connector.TransportAuto}}})
	eventually(t, "auto did not reach the gateway over WSS", func() bool {
		return m.Count()[id.ID+"/wss"] == 2 && g.sessions.Load().Count()["h2"] == 2
	})
	if err := echo(t, g.sessions.Load(), "rt_1"); err != nil {
		t.Fatalf("a stream over WSS: %v", err)
	}
	if p.refused.Load() == 0 || g.tcpConns.Load() != 0 {
		t.Fatalf("TLS over TCP: %d handshakes refused at the proxy, %d connections at the gateway; want some and none",
			p.refused.Load(), g.tcpConns.Load())
	}
	if got := p.seen(); !slices.Contains(got, ep) || !slices.Contains(got, wssHost+":443") {
		t.Fatalf("the proxy carried %v", got)
	}
	if !p.saw("GET " + tunnel.WSSPath) {
		t.Fatal("the proxy did not see the upgrade")
	}
	if p.saw("hello") {
		t.Fatal("the proxy read the data session")
	}
}

// TestWSS_AutoOnlyAfterHandshakeFailure: auto does not try WSS when TLS over TCP failed before
// its handshake, such as on a refused connection.
func TestWSS_AutoOnlyAfterHandshakeFailure(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	ca := newPublicCA(t, "public root")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	via := &dialVia{hosts: map[string]string{wssHost + ":443": g.serveWSS(t, ca)}}
	m := connector.New(connector.Options{TLS: w.clientTLS, Dial: via.dial, PublicRoots: ca.pool, Streams: echoStream,
		LocalAddr: func(context.Context, string) (netip.Addr, error) { return netip.MustParseAddr("192.0.2.1"), nil }})
	t.Cleanup(m.Close)
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{closed}, WSSHostname: wssHost,
		Routes: map[string]string{"rt_1": connector.TransportAuto}}})
	eventually(t, "no dial of the tunnel endpoint", func() bool { return via.count(closed) > 0 })
	time.Sleep(300 * time.Millisecond)
	if n := via.count(wssHost + ":443"); n != 0 || len(m.Count()) != 0 {
		t.Fatalf("WSS after a refused connection: %d dials, sessions %v", n, m.Count())
	}
}

// TestApplier_WSS: a route on wss and its gateway's WSS hostname reach the sessions from the
// snapshot; a hostname that is not normalised is refused.
func TestApplier_WSS(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	ca := newPublicCA(t, "public root")
	via := &dialVia{hosts: map[string]string{wssHost + ":443": g.serveWSS(t, ca)}}
	svc := startService(t, echoService)
	var cur atomic.Pointer[policy.Policy]
	cur.Store(allowLoopback(t, svc.port()))
	var m *connector.Sessions
	targets := connector.NewTargets(connector.TargetsOptions{Policy: cur.Load, OnHealth: func(h *tunnelv1.RouteHealth) { m.SetReady(h) }})
	m = newConnectorOptions(t, w, func(o *connector.Options) {
		o.Streams, o.Dial, o.PublicRoots = targets.Handle, via.dial, ca.pool
	})
	a := connector.NewApplier(targets, m)
	snap := func(host string) *agentv1.Snapshot {
		gw := gatewayResource(id.ID, []string{g.addr}, "rt_1")
		gw.GetConnectorGateway().WssHostname = host
		return &agentv1.Snapshot{Resources: []*agentv1.Resource{
			routeResource("rt_1", agentv1.TransportPolicy_TRANSPORT_POLICY_WSS, addrTarget("127.0.0.1", uint32(svc.port()))), gw}}
	}
	for _, bad := range []string{"Tunnel.example.com", "tunnel.example.com.", "-x.example.com", "a b"} {
		if errs := a.Validate(snap(bad)); len(errs) != 1 || !strings.Contains(errs[0].GetMessage(), "WSS hostname") {
			t.Errorf("%q: %v", bad, errs)
		}
	}
	if errs := a.Validate(snap("")); len(errs) != 0 {
		t.Fatal(errs)
	}
	if errs := a.Validate(snap(wssHost)); len(errs) != 0 {
		t.Fatal(errs)
	}
	a.Apply(t.Context(), snap(wssHost), agent.Changes{})
	eventually(t, "no stream over WSS", func() bool {
		return m.Count()[id.ID+"/wss"] == 2 && echo(t, g.sessions.Load(), "rt_1") == nil
	})
	if g.tcpConns.Load() != 0 {
		t.Fatal("the route on wss dialled the tunnel endpoint")
	}
}
