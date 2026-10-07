// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

const td = "rpmgr-7f3k2q6m"

// world is a test CA, an organisation and a connector.
type world struct {
	roots *x509.CertPool
	is    *pki.Issuer
	inter pki.KeyPair
	org   string
	con   pki.Identity
	cert  tls.Certificate
}

func newWorld(t *testing.T) *world {
	t.Helper()
	now := time.Now()
	root, err := pki.NewRoot(td, now)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := pki.NewIntermediate(root, now)
	if err != nil {
		t.Fatal(err)
	}
	is, err := pki.NewIssuer(root.Cert, inter, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{roots: x509.NewCertPool(), is: is, inter: inter, org: ids.New("org")}
	w.roots.AddCert(root.Cert)
	w.con = pki.Identity{TrustDomain: td, Org: w.org, Kind: pki.KindConnector, ID: ids.New("con")}
	w.cert = w.leaf(t, w.is, w.inter, w.con)
	return w
}

func (w *world) leaf(t *testing.T, is *pki.Issuer, inter pki.KeyPair, id pki.Identity) tls.Certificate {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr, _ := x509.ParseCertificateRequest(der)
	c, err := is.IssueLeaf(csr, id, pki.DefaultLeafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{c.Raw, inter.Cert.Raw}, PrivateKey: key, Leaf: c}
}

func (w *world) gatewayID() pki.Identity {
	return pki.Identity{TrustDomain: td, Org: w.org, Kind: pki.KindGateway, ID: ids.New("gw")}
}

// clientTLS is the connector's configuration for a gateway: exactly that gateway's identity.
func (w *world) clientTLS(gatewayID string) (*tls.Config, error) {
	id := pki.Identity{TrustDomain: td, Org: w.org, Kind: pki.KindGateway, ID: gatewayID}
	return pki.ClientConfig(w.cert, w.roots, id.DNSName(), pki.Expect{TrustDomain: td, Exact: &id}, nil, nil), nil
}

// assignment assigns every route to the world's connector.
type assignment struct{ con string }

func (a assignment) Known(id string) bool       { return id == a.con }
func (a assignment) Connectors(string) []string { return []string{a.con} }
func (w *world) assignment() gateway.Assignment { return assignment{w.con.ID} }
func (w *world) sessions(id pki.Identity) *gateway.Sessions {
	return gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: id.ID, Assignment: w.assignment()})
}

// testGateway listens on one port for TCP and UDP, as a gateway does on 443, and serves data
// sessions with its current Sessions.
type testGateway struct {
	id         pki.Identity
	addr       string
	sessions   atomic.Pointer[gateway.Sessions]
	serverName chan string // the SNI of every TCP handshake
	tcpErrs    chan error  // failed TCP handshakes
	quicConns  atomic.Int64
}

// startGateway serves data sessions for the gateway id with the certificate cert, which a test
// may take from another gateway or CA.
func startGateway(t *testing.T, w *world, id pki.Identity, cert tls.Certificate) *testGateway {
	t.Helper()
	g := &testGateway{id: id, serverName: make(chan string, 64), tcpErrs: make(chan error, 64)}
	g.sessions.Store(w.sessions(id))
	server := pki.ServerConfig(cert, w.roots, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}}, nil)
	var (
		ln net.Listener
		pc net.PacketConn
	)
	for range 20 { // the same port for TCP and UDP
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p, err := net.ListenPacket("udp", l.Addr().String())
		if err == nil {
			ln, pc = l, p
			break
		}
		_ = l.Close()
	}
	if ln == nil {
		t.Fatal("no port free for both TCP and UDP")
	}
	g.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	tr := &quic.Transport{Conn: pc}
	qln, err := tunnel.ListenQUIC(tr, gateway.QUICTLS(td, id.ID, server), tunnel.NewBudget(tunnel.DefaultWindowBudget))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		_ = qln.Close()
		_ = tr.Close()
		g.sessions.Load().Close()
	})
	go func() {
		for {
			s, err := qln.Accept(ctx)
			if err != nil {
				return
			}
			g.quicConns.Add(1)
			go func() { _ = g.sessions.Load().Serve(ctx, s, s.PeerCertificate()) }()
		}
	}()
	h2 := server.Clone()
	h2.NextProtos = []string{tunnel.ALPNH2}
	h2.GetConfigForClient = func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		g.serverName <- hi.ServerName
		return nil, nil
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := tls.Server(c, h2)
				if err := tc.HandshakeContext(ctx); err != nil {
					g.tcpErrs <- err
					_ = c.Close()
					return
				}
				s, err := tunnel.NewH2Gateway(tc, tunnel.DefaultH2Windows())
				if err != nil {
					_ = tc.Close()
					return
				}
				_ = g.sessions.Load().Serve(ctx, s, tc.ConnectionState().PeerCertificates[0])
			}()
		}
	}()
	return g
}

// newConnector returns the world's connector sessions with an echo handler.
func newConnector(t *testing.T, w *world) *connector.Sessions {
	t.Helper()
	return newConnectorWith(t, w, func(_ context.Context, _ string, st tunnel.Stream, _ *tunnelv1.StreamOpen) {
		defer func() { _ = st.Close() }()
		if tunnel.WriteMessage(st, &tunnelv1.StreamResult{}) != nil {
			return
		}
		_, _ = io.Copy(st, st)
		_ = st.CloseWrite()
	})
}

// newConnectorWith returns the world's connector sessions with the stream handler streams.
func newConnectorWith(t *testing.T, w *world, streams func(context.Context, string, tunnel.Stream, *tunnelv1.StreamOpen)) *connector.Sessions {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	m := connector.New(connector.Options{TLS: w.clientTLS, QUIC: tr, Streams: streams})
	t.Cleanup(func() {
		m.Close()
		_ = tr.Close()
	})
	return m
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatal(what)
}

// echo opens a stream for route through the gateway's sessions and checks the echo.
func echo(t *testing.T, s *gateway.Sessions, route string) error {
	t.Helper()
	st, code, err := s.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: route})
	if err != nil {
		return err
	}
	if code != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		return errors.New(code.String())
	}
	defer func() { _ = st.Close() }()
	if _, err := st.Write([]byte("hello")); err != nil {
		return err
	}
	_ = st.CloseWrite()
	b, err := io.ReadAll(st)
	if err != nil || string(b) != "hello" {
		t.Fatalf("echo %q %v", b, err)
	}
	return nil
}

// TestGateway_PerGatewayTunnelEndpoints: the connector dials each gateway at that gateway's own
// tunnel endpoint with ServerName <gateway-id>.gateway.<td> and holds a session to every gateway:
// one QUIC session, or two TCP connections on h2.
func TestGateway_PerGatewayTunnelEndpoints(t *testing.T) {
	w := newWorld(t)
	id1, id2 := w.gatewayID(), w.gatewayID()
	g1 := startGateway(t, w, id1, w.leaf(t, w.is, w.inter, id1))
	g2 := startGateway(t, w, id2, w.leaf(t, w.is, w.inter, id2))
	m := newConnector(t, w)
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true})
	m.Set([]connector.Gateway{
		{ID: id1.ID, Endpoints: []string{g1.addr}, Transports: []string{connector.TransportQUIC}, Routes: []string{"rt_1"}},
		{ID: id2.ID, Endpoints: []string{g2.addr}, Transports: []string{connector.TransportH2}, Routes: []string{"rt_1"}},
	})
	// The gateway counts a session before its SessionWelcome, the connector after it: wait for both.
	eventually(t, "not every gateway has its sessions", func() bool {
		got := m.Count()
		return g1.sessions.Load().Count()["quic"] == 1 && g2.sessions.Load().Count()["h2"] == 2 &&
			got[id1.ID+"/quic"] == 1 && got[id2.ID+"/h2"] == 2 && len(got) == 2
	})
	for range 2 {
		if sni := <-g2.serverName; sni != id2.DNSName() {
			t.Fatalf("ServerName %q, want %q", sni, id2.DNSName())
		}
	}
	// gateway.QUICTLS completes a handshake only for its own name, so the QUIC session proves it.
	for _, g := range []*testGateway{g1, g2} {
		if err := echo(t, g.sessions.Load(), "rt_1"); err != nil {
			t.Fatalf("a stream through %s: %v", g.id.ID, err)
		}
	}
	if len(g1.serverName) != 0 || g2.quicConns.Load() != 0 {
		t.Fatal("a gateway was dialled with a transport its entry does not ask for")
	}
}

// refusedEverywhere checks that the connector holds no session to a gateway entry whose endpoint
// presents cert, on either transport, and that the TCP handshake failed.
func refusedEverywhere(t *testing.T, w *world, entry pki.Identity, cert tls.Certificate) {
	t.Helper()
	g := startGateway(t, w, entry, cert)
	m := newConnector(t, w)
	m.Set([]connector.Gateway{{ID: entry.ID, Endpoints: []string{g.addr},
		Transports: []string{connector.TransportQUIC, connector.TransportH2}}})
	select {
	case err := <-g.tcpErrs:
		t.Logf("the gateway's TCP handshake failed as expected: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no TCP handshake failed")
	}
	time.Sleep(500 * time.Millisecond)
	if got := m.Count(); len(got) != 0 {
		t.Fatalf("sessions %v to a gateway with the wrong certificate", got)
	}
	if got := g.sessions.Load().Count(); len(got) != 0 || g.quicConns.Load() != 0 {
		t.Fatalf("the gateway admitted %v and completed %d QUIC handshakes", got, g.quicConns.Load())
	}
}

// TestTLS_WrongGatewayIDRejected: a connector dialling gateway G1 rejects a valid certificate of
// gateway G2 from another organisation, on QUIC and on TCP.
func TestTLS_WrongGatewayIDRejected(t *testing.T) {
	w := newWorld(t)
	g1 := w.gatewayID()
	g2 := pki.Identity{TrustDomain: td, Org: ids.New("org"), Kind: pki.KindGateway, ID: ids.New("gw")}
	refusedEverywhere(t, w, g1, w.leaf(t, w.is, w.inter, g2))
}

// TestRejectsUnpinnedCA: data sessions fail against a gateway whose certificate, with the right
// identity, chains to a root other than the pinned one.
func TestRejectsUnpinnedCA(t *testing.T) {
	w := newWorld(t)
	root, _ := pki.NewRoot(td, time.Now())
	inter, _ := pki.NewIntermediate(root, time.Now())
	is, err := pki.NewIssuer(root.Cert, inter, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	id := w.gatewayID()
	refusedEverywhere(t, w, id, w.leaf(t, is, inter, id))
}

// TestSessions_RouteHealth: the SessionHello carries the ready routes of the gateway entry, and a
// change of readiness reaches the gateway; without a handler a stream is answered ROUTE_UNKNOWN.
func TestSessions_RouteHealth(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	m := newConnector(t, w)
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true})
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_other", Ready: true})
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr}, Transports: []string{connector.TransportQUIC},
		Routes: []string{"rt_1", "rt_2"}}})
	eventually(t, "no session", func() bool { return g.sessions.Load().Count()["quic"] == 1 })
	gs := g.sessions.Load()
	if err := echo(t, gs, "rt_1"); err != nil {
		t.Fatalf("a route ready at the start: %v", err)
	}
	if err := echo(t, gs, "rt_2"); !errors.Is(err, gateway.ErrNoSession) {
		t.Fatalf("a route never reported ready: %v", err)
	}
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_2", Ready: true})
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: false})
	eventually(t, "RouteHealth did not reach the gateway", func() bool {
		return echo(t, gs, "rt_2") == nil && errors.Is(echo(t, gs, "rt_1"), gateway.ErrNoSession)
	})

	// Without a stream handler: ROUTE_UNKNOWN.
	bare := connector.New(connector.Options{TLS: w.clientTLS, Dial: nil})
	t.Cleanup(bare.Close)
	g2id := w.gatewayID()
	g2 := startGateway(t, w, g2id, w.leaf(t, w.is, w.inter, g2id))
	bare.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true})
	bare.Set([]connector.Gateway{{ID: g2id.ID, Endpoints: []string{g2.addr}, Transports: []string{connector.TransportAuto},
		Routes: []string{"rt_1"}}})
	eventually(t, "auto without a UDP socket did not fall back to h2", func() bool { return g2.sessions.Load().Count()["h2"] == 1 })
	if _, code, err := g2.sessions.Load().OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "rt_1"}); err != nil ||
		code != tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN {
		t.Fatalf("%s %v, want ROUTE_UNKNOWN", code, err)
	}
}

// TestSessions_Reconnect: after the gateway closes the session, and after a Drain, the connector
// dials again; a draining session keeps serving until the gateway closes it.
func TestSessions_Reconnect(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	m := newConnector(t, w)
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true})
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr}, Transports: []string{connector.TransportQUIC},
		Routes: []string{"rt_1"}}})
	eventually(t, "no session", func() bool { return g.sessions.Load().Count()["quic"] == 1 })
	g.sessions.Load().Close()
	eventually(t, "no session after the gateway closed it", func() bool {
		return g.sessions.Load().Count()["quic"] == 1 && g.quicConns.Load() == 2
	})

	// A planned restart: Drain, then a new process.
	old := g.sessions.Load()
	old.Drain(time.Now().Add(gateway.DrainPeriod))
	g.sessions.Store(w.sessions(id))
	eventually(t, "no session to the restarted gateway", func() bool { return g.sessions.Load().Count()["quic"] == 1 })
	if old.Count()["quic"] != 1 {
		t.Fatal("the draining session closed before its deadline")
	}
	if _, err := old.Open(context.Background(), &tunnelv1.StreamOpen{RouteId: "rt_1"}); !errors.Is(err, gateway.ErrDraining) {
		t.Fatalf("draining gateway: %v", err)
	}
	if err := echo(t, g.sessions.Load(), "rt_1"); err != nil {
		t.Fatal(err)
	}
}

// TestSessions_Set: a removed gateway's session keeps its open streams, then closes; a changed
// endpoint moves the session; Close ends everything.
func TestSessions_Set(t *testing.T) {
	connector.SetRetireAfter(t, 5*time.Second)
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	moved := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	m := newConnector(t, w)
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true})
	entry := connector.Gateway{ID: id.ID, Endpoints: []string{g.addr}, Transports: []string{connector.TransportQUIC}, Routes: []string{"rt_1"}}
	m.Set([]connector.Gateway{entry})
	eventually(t, "no session", func() bool { return g.sessions.Load().Count()["quic"] == 1 })
	m.Set([]connector.Gateway{entry}) // unchanged: untouched
	if g.quicConns.Load() != 1 {
		t.Fatal("an unchanged entry was redialled")
	}

	st, _, err := g.sessions.Load().OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "rt_1"})
	if err != nil {
		t.Fatal(err)
	}
	m.Set(nil)
	time.Sleep(300 * time.Millisecond)
	if g.sessions.Load().Count()["quic"] != 1 {
		t.Fatal("a removed gateway's session closed with a stream still open")
	}
	if _, err := st.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseWrite()
	if b, err := io.ReadAll(st); err != nil || string(b) != "late" {
		t.Fatalf("the open stream after removal: %q %v", b, err)
	}
	_ = st.Close()
	eventually(t, "the retired session did not close after its last stream", func() bool { return len(g.sessions.Load().Count()) == 0 })

	entry.Endpoints = []string{moved.addr}
	m.Set([]connector.Gateway{entry})
	eventually(t, "no session at the new endpoint", func() bool { return moved.sessions.Load().Count()["quic"] == 1 })
	m.Close()
	eventually(t, "Close left a session", func() bool { return len(moved.sessions.Load().Count()) == 0 })
	if len(m.Count()) != 0 {
		t.Fatal("Close: still counted")
	}
}

// TestSessions_Endpoints: endpoints are tried in order; a dead first endpoint does not prevent
// the session.
func TestSessions_Endpoints(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()
	m := newConnector(t, w)
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{deadAddr, "not-a-port:x", g.addr}, Transports: []string{connector.TransportH2}}})
	eventually(t, "the third endpoint was not used", func() bool { return g.sessions.Load().Count()["h2"] == 2 })
}
