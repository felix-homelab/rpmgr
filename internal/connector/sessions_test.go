// SPDX-License-Identifier: Apache-2.0

package connector_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
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

func (a assignment) Known(id string) bool { return id == a.con }
func (a assignment) Connectors(string) []gateway.RouteConnector {
	return []gateway.RouteConnector{{ID: a.con, Weight: 1}}
}
func (w *world) assignment() gateway.Assignment { return assignment{w.con.ID} }
func (w *world) sessions(id pki.Identity) *gateway.Sessions {
	return gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: id.ID, Assignment: w.assignment()})
}

// testGateway listens on one port for TCP and UDP, as a gateway does on 443, and serves data
// sessions with its current Sessions.
type testGateway struct {
	id       pki.Identity
	addr     string
	server   *tls.Config
	h2       *tls.Config // the data session's TLS over TCP and inside WSS
	ctx      context.Context
	sessions atomic.Pointer[gateway.Sessions]
	// quicSessions, if set, serves the QUIC sessions, so that a test sees which transport carries
	// a route.
	quicSessions atomic.Pointer[gateway.Sessions]
	udpPackets   atomic.Int64 // dropped by a blackhole
	mu           sync.Mutex
	closers      []io.Closer
	serverName   chan string // the SNI of every TCP handshake
	tcpErrs      chan error  // failed TCP handshakes
	quicConns    atomic.Int64
	tcpEnded     atomic.Int64                       // TCP sessions the gateway served and removed
	tcpConns     atomic.Int64                       // connections to the tunnel endpoint
	wssConns     atomic.Int64                       // connections to the WSS listener
	lastQUIC     atomic.Pointer[tunnel.QUICSession] // the last QUIC session accepted, for a gateway that misbehaves
	// quicLimit, if set, refuses a QUIC session while quicLive sessions are served, as a gateway
	// at its cap of sessions per connector does.
	quicLimit atomic.Int64
	quicLive  atomic.Int64
	// handshakeLimit, if set, fails every QUIC handshake after that many, so that a dial fails.
	handshakeLimit atomic.Int64
	handshakes     atomic.Int64
}

// startGateway serves data sessions for the gateway id with the certificate cert, which a test
// may take from another gateway or CA.
func startGateway(t *testing.T, w *world, id pki.Identity, cert tls.Certificate) *testGateway {
	t.Helper()
	return startGatewayWith(t, w, id, cert, false)
}

// startGatewayWith is startGateway; with blackhole, UDP packets are read and dropped, as on a path
// that blocks UDP, until enableQUIC.
func startGatewayWith(t *testing.T, w *world, id pki.Identity, cert tls.Certificate, blackhole bool) *testGateway {
	t.Helper()
	g := &testGateway{id: id, serverName: make(chan string, 64), tcpErrs: make(chan error, 64)}
	g.sessions.Store(w.sessions(id))
	g.server = pki.ServerConfig(cert, w.roots, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}}, nil)
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
	var cancel context.CancelFunc
	g.ctx, cancel = context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		g.mu.Lock()
		for _, c := range g.closers {
			_ = c.Close()
		}
		g.mu.Unlock()
		g.sessions.Load().Close()
		if q := g.quicSessions.Load(); q != nil {
			q.Close()
		}
	})
	if blackhole {
		g.track(pc)
		go func() {
			buf := make([]byte, 2048)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
				g.udpPackets.Add(1)
			}
		}()
	} else {
		g.serveQUIC(t, pc)
	}
	g.h2 = g.server.Clone()
	g.h2.NextProtos = []string{tunnel.ALPNH2}
	g.h2.GetConfigForClient = func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		g.serverName <- hi.ServerName
		return nil, nil
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			g.tcpConns.Add(1)
			go g.serveH2(tls.Server(c, g.h2))
		}
	}()
	return g
}

// serveH2 serves a data session over TLS and reverse HTTP/2, over TCP or inside WSS.
func (g *testGateway) serveH2(tc *tls.Conn) {
	if err := tc.HandshakeContext(g.ctx); err != nil {
		g.tcpErrs <- err
		_ = tc.Close()
		return
	}
	s, err := tunnel.NewH2Gateway(tc, tunnel.DefaultH2Windows())
	if err != nil {
		_ = tc.Close()
		return
	}
	_ = g.sessions.Load().Serve(g.ctx, s, tc.ConnectionState().PeerCertificates[0])
	g.tcpEnded.Add(1)
}

func (g *testGateway) track(c io.Closer) {
	g.mu.Lock()
	g.closers = append(g.closers, c)
	g.mu.Unlock()
}

// serveQUIC serves QUIC data sessions on pc, with quicSessions if set, else sessions.
func (g *testGateway) serveQUIC(t *testing.T, pc net.PacketConn) {
	t.Helper()
	tr := &quic.Transport{Conn: pc}
	cfg := gateway.QUICTLS(td, g.id.ID, g.server)
	inner := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if limit := g.handshakeLimit.Load(); limit > 0 && g.handshakes.Add(1) > limit {
			return nil, errors.New("test gateway: handshake refused")
		}
		return inner(hello)
	}
	qln, err := tunnel.ListenQUIC(tr, cfg, tunnel.NewBudget(tunnel.DefaultWindowBudget))
	if err != nil {
		t.Fatal(err)
	}
	g.track(qln)
	g.track(tr)
	go func() {
		for {
			s, err := qln.Accept(g.ctx)
			if err != nil {
				return
			}
			g.quicConns.Add(1)
			if limit := g.quicLimit.Load(); limit > 0 && g.quicLive.Load() >= limit {
				_ = s.Close()
				continue
			}
			g.lastQUIC.Store(s)
			sessions := g.sessions.Load()
			if q := g.quicSessions.Load(); q != nil {
				sessions = q
			}
			g.quicLive.Add(1)
			go func() {
				_ = sessions.Serve(g.ctx, s, s.PeerCertificate())
				g.quicLive.Add(-1)
			}()
		}
	}()
}

// enableQUIC ends the blackhole: the UDP port now serves QUIC.
func (g *testGateway) enableQUIC(t *testing.T) {
	t.Helper()
	g.mu.Lock()
	for _, c := range g.closers {
		_ = c.Close()
	}
	g.closers = nil
	g.mu.Unlock()
	pc, err := net.ListenPacket("udp", g.addr)
	if err != nil {
		t.Fatal(err)
	}
	g.serveQUIC(t, pc)
}

// echoStream answers a stream and echoes it.
func echoStream(_ context.Context, _ string, st tunnel.Stream, _ *tunnelv1.StreamOpen) {
	defer func() { _ = st.Close() }()
	if tunnel.WriteMessage(st, &tunnelv1.StreamResult{}) != nil {
		return
	}
	_, _ = io.Copy(st, st)
	_ = st.CloseWrite()
}

// newConnector returns the world's connector sessions with an echo handler.
func newConnector(t *testing.T, w *world) *connector.Sessions {
	t.Helper()
	return newConnectorOptions(t, w, func(*connector.Options) {})
}

// newConnectorWith returns the world's connector sessions with the stream handler streams.
func newConnectorWith(t *testing.T, w *world, streams func(context.Context, string, tunnel.Stream, *tunnelv1.StreamOpen)) *connector.Sessions {
	t.Helper()
	return newConnectorOptions(t, w, func(o *connector.Options) { o.Streams = streams })
}

// newConnectorOptions returns the world's connector sessions with a UDP socket and an echo
// handler, as opt changes them.
func newConnectorOptions(t *testing.T, w *world, opt func(*connector.Options)) *connector.Sessions {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	o := connector.Options{TLS: w.clientTLS, QUIC: tr, Streams: echoStream}
	opt(&o)
	m := connector.New(o)
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
	st, code, err := s.OpenStream(context.Background(), &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_TCP, RouteId: route})
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
// tunnel endpoint, or for WSS at port 443 of its own WSS hostname, with ServerName
// <gateway-id>.gateway.<td>, and holds a session to every gateway: four QUIC sessions, or two TCP
// connections on h2 or on WSS.
func TestGateway_PerGatewayTunnelEndpoints(t *testing.T) {
	w := newWorld(t)
	id1, id2, id3 := w.gatewayID(), w.gatewayID(), w.gatewayID()
	g1 := startGateway(t, w, id1, w.leaf(t, w.is, w.inter, id1))
	g2 := startGateway(t, w, id2, w.leaf(t, w.is, w.inter, id2))
	g3 := startGateway(t, w, id3, w.leaf(t, w.is, w.inter, id3))
	ca := newPublicCA(t, "public root")
	via := &dialVia{hosts: map[string]string{wssHost + ":443": g3.serveWSS(t, ca)}}
	m := newConnectorOptions(t, w, func(o *connector.Options) { o.Dial, o.PublicRoots = via.dial, ca.pool })
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true})
	m.Set([]connector.Gateway{
		{ID: id1.ID, Endpoints: []string{g1.addr}, Routes: map[string]string{"rt_1": connector.TransportQUIC}},
		{ID: id2.ID, Endpoints: []string{g2.addr}, Routes: map[string]string{"rt_1": connector.TransportH2}},
		{ID: id3.ID, Endpoints: []string{g3.addr}, WSSHostname: wssHost, Routes: map[string]string{"rt_1": connector.TransportWSS}},
	})
	// The gateway counts a session before its SessionWelcome, the connector after it: wait for both.
	eventually(t, "not every gateway has its sessions", func() bool {
		got := m.Count()
		return g1.sessions.Load().Count()["quic"] == connector.QUICSessions && g2.sessions.Load().Count()["h2"] == 2 &&
			g3.sessions.Load().Count()["h2"] == 2 && got[id1.ID+"/quic"] == connector.QUICSessions && got[id2.ID+"/h2"] == 2 &&
			got[id3.ID+"/wss"] == 2 && len(got) == 3
	})
	for _, g := range []*testGateway{g2, g3} {
		for range 2 {
			if sni := <-g.serverName; sni != g.id.DNSName() {
				t.Fatalf("ServerName %q, want %q", sni, g.id.DNSName())
			}
		}
	}
	// gateway.QUICTLS completes a handshake only for its own name, so the QUIC session proves it.
	for _, g := range []*testGateway{g1, g2, g3} {
		if err := echo(t, g.sessions.Load(), "rt_1"); err != nil {
			t.Fatalf("a stream through %s: %v", g.id.ID, err)
		}
	}
	if len(g1.serverName) != 0 || g2.quicConns.Load() != 0 || g3.quicConns.Load() != 0 || g3.tcpConns.Load() != 0 {
		t.Fatal("a gateway was dialled with a transport its entry does not ask for")
	}
	if n := via.count(wssHost + ":443"); n != 2 || g3.wssConns.Load() != 2 {
		t.Fatalf("%d dials of the WSS hostname, %d at the gateway; want 2", n, g3.wssConns.Load())
	}
}

// refusedEverywhere checks that the connector holds no session to a gateway entry whose endpoint
// presents cert, on either transport, and that the TCP handshake failed.
func refusedEverywhere(t *testing.T, w *world, entry pki.Identity, cert tls.Certificate) {
	t.Helper()
	g := startGateway(t, w, entry, cert)
	m := newConnector(t, w)
	m.Set([]connector.Gateway{{ID: entry.ID, Endpoints: []string{g.addr},
		Routes: map[string]string{"rt_q": connector.TransportQUIC, "rt_h": connector.TransportH2}}})
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
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr},
		Routes: map[string]string{"rt_1": connector.TransportQUIC, "rt_2": connector.TransportQUIC}}})
	eventually(t, "no session", func() bool { return g.sessions.Load().Count()["quic"] == connector.QUICSessions })
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
	bare.Set([]connector.Gateway{{ID: g2id.ID, Endpoints: []string{g2.addr}, Routes: map[string]string{"rt_1": connector.TransportAuto}}})
	eventually(t, "auto without a UDP socket did not fall back to h2", func() bool { return g2.sessions.Load().Count()["h2"] == 2 })
	if _, code, err := g2.sessions.Load().OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "rt_1"}); err != nil ||
		code != tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN {
		t.Fatalf("%s %v, want ROUTE_UNKNOWN", code, err)
	}
}

// rankedAssignment ranks the world's connector at priorities 0 and 5 of every route.
type rankedAssignment struct{ con string }

func (a rankedAssignment) Known(id string) bool { return id == a.con }
func (a rankedAssignment) Connectors(string) []gateway.RouteConnector {
	return []gateway.RouteConnector{{ID: a.con, Weight: 1, Ranked: true}, {ID: a.con, Priority: 5, Weight: 1, Ranked: true}}
}

// TestSessions_ReadyPriorities (D133): the priorities with a healthy target reach the gateway, also
// for a route ready before the session: its hello leaves such a route out, as a gateway takes a
// route of the hello as ready at every priority, and RouteHealth names it with its priorities after
// the welcome; a later change of the priorities alone reaches the gateway too.
func TestSessions_ReadyPriorities(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	gs := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: id.ID, Assignment: rankedAssignment{w.con.ID}})
	g.sessions.Store(gs)
	m := newConnector(t, w)
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true, ReadyPriorities: []uint32{5}})
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_1": connector.TransportQUIC}}})
	best := func(want uint32) func() bool {
		return func() bool { p, ok := gs.BestPriority("rt_1"); return ok && p == want }
	}
	eventually(t, "the gateway never saw priority 5 alone", best(5))
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true, ReadyPriorities: []uint32{0, 5}})
	eventually(t, "priority 0 healthy again never reached the gateway", best(0))
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true, ReadyPriorities: []uint32{5}})
	eventually(t, "priority 0 unhealthy again never reached the gateway", best(5))
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true})
	eventually(t, "readiness at every priority never reached the gateway", best(0))
	if err := echo(t, gs, "rt_1"); err != nil {
		t.Fatalf("a stream: %v", err)
	}
}

// TestSessions_ManyReadyRoutes (docs/03-connections.md, "Framing"): a connector with more ready
// routes than one SessionHello can list within the message limit still establishes its sessions,
// on both transports; the hello carries what fits and RouteHealth the rest, so every route is
// served.
func TestSessions_ManyReadyRoutes(t *testing.T) {
	w := newWorld(t)
	for _, tr := range []string{connector.TransportQUIC, connector.TransportH2} {
		t.Run(tr, func(t *testing.T) {
			id := w.gatewayID()
			g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
			m := newConnector(t, w)
			routes := map[string]string{}
			var ids []string
			for i := range 1500 { // about 46 KB of route IDs, almost three times the limit
				r := fmt.Sprintf("rt_%026d", i)
				ids = append(ids, r)
				routes[r] = tr
				m.SetReady(&tunnelv1.RouteHealth{RouteId: r, Ready: true})
			}
			m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr}, Routes: routes}})
			eventually(t, "no session with 1500 ready routes", func() bool { return g.sessions.Load().Count()[tr] > 0 })
			gs := g.sessions.Load()
			for _, r := range []string{ids[0], ids[len(ids)/2], ids[len(ids)-1]} {
				eventually(t, r+" is not served", func() bool { return echo(t, gs, r) == nil })
			}
		})
	}
}

// TestSessions_Reconnect: after the gateway closes the session, and after a Drain, the connector
// dials again; a draining session with a stream open lasts until its deadline.
func TestSessions_Reconnect(t *testing.T) {
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	m := newConnector(t, w)
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true})
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_1": connector.TransportQUIC}}})
	eventually(t, "no session", func() bool { return g.sessions.Load().Count()["quic"] == connector.QUICSessions })
	g.sessions.Load().Close()
	eventually(t, "no session after the gateway closed it", func() bool {
		return g.sessions.Load().Count()["quic"] == connector.QUICSessions && g.quicConns.Load() == 2*connector.QUICSessions
	})

	// A planned restart: Drain, then a new process. A stream open on the draining session keeps
	// it: the connector closes a draining session it no longer needs once it has moved, so only a
	// session with streams must last until the deadline.
	old := g.sessions.Load()
	held, _, err := old.OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "rt_1"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	old.Drain(time.Now().Add(gateway.DrainPeriod))
	g.sessions.Store(w.sessions(id))
	eventually(t, "no session to the restarted gateway", func() bool { return g.sessions.Load().Count()["quic"] == connector.QUICSessions })
	if old.Count()["quic"] < 1 {
		t.Fatal("the draining session closed before its deadline with a stream open")
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
	w := newWorld(t)
	id := w.gatewayID()
	g := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	moved := startGateway(t, w, id, w.leaf(t, w.is, w.inter, id))
	m := newConnector(t, w)
	m.SetReady(&tunnelv1.RouteHealth{RouteId: "rt_1", Ready: true})
	entry := connector.Gateway{ID: id.ID, Endpoints: []string{g.addr}, Routes: map[string]string{"rt_1": connector.TransportQUIC}}
	m.Set([]connector.Gateway{entry})
	eventually(t, "no session", func() bool { return g.sessions.Load().Count()["quic"] == connector.QUICSessions })
	m.Set([]connector.Gateway{entry}) // unchanged: untouched
	if g.quicConns.Load() != connector.QUICSessions {
		t.Fatal("an unchanged entry was redialled")
	}

	st, _, err := g.sessions.Load().OpenStream(context.Background(), &tunnelv1.StreamOpen{RouteId: "rt_1"})
	if err != nil {
		t.Fatal(err)
	}
	m.Set(nil)
	time.Sleep(300 * time.Millisecond)
	if g.sessions.Load().Count()["quic"] < 1 {
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
	eventually(t, "no session at the new endpoint", func() bool { return moved.sessions.Load().Count()["quic"] == connector.QUICSessions })
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
	m.Set([]connector.Gateway{{ID: id.ID, Endpoints: []string{deadAddr, "not-a-port:x", g.addr}, Routes: map[string]string{"rt_1": connector.TransportH2}}})
	eventually(t, "the third endpoint was not used", func() bool { return g.sessions.Load().Count()["h2"] == 2 })
}

// rawOpen opens a stream for route on s as a gateway that ignores what the connector announced
// would, and returns the connector's StreamResult code.
func rawOpen(t *testing.T, s tunnel.Session, route string) tunnelv1.ResultCode {
	t.Helper()
	st, err := s.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := tunnel.WriteMessage(st, &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_TCP, RouteId: route}); err != nil {
		t.Fatal(err)
	}
	res := &tunnelv1.StreamResult{}
	if err := tunnel.ReadMessage(st, res); err != nil {
		t.Fatal(err)
	}
	return res.GetCode()
}

// TestSessions_StreamsOnlyForTheGatewaysRoutes: the connector serves a stream only for a route
// that the opening gateway serves by the connector's snapshot. A gateway that opens one for a
// route of another gateway group, as a compromised gateway would, gets ROUTE_UNKNOWN; a route that
// both groups serve works through either. A route taken from the gateway by a newer snapshot, as
// when the gateway moves to another group, still works for the route drain period and then no
// longer.
func TestSessions_StreamsOnlyForTheGatewaysRoutes(t *testing.T) {
	connector.SetRouteDrain(t, 500*time.Millisecond)
	w := newWorld(t)
	idA, idB := w.gatewayID(), w.gatewayID()
	a := startGateway(t, w, idA, w.leaf(t, w.is, w.inter, idA))
	b := startGateway(t, w, idB, w.leaf(t, w.is, w.inter, idB))
	m := newConnector(t, w)
	for _, r := range []string{"rt_a", "rt_b", "rt_both", "rt_next"} {
		m.SetReady(&tunnelv1.RouteHealth{RouteId: r, Ready: true})
	}
	quic := connector.TransportQUIC
	entryA := connector.Gateway{ID: idA.ID, Endpoints: []string{a.addr}, Routes: map[string]string{"rt_a": quic, "rt_both": quic}}
	entryB := connector.Gateway{ID: idB.ID, Endpoints: []string{b.addr}, Routes: map[string]string{"rt_b": quic, "rt_both": quic}}
	m.Set([]connector.Gateway{entryA, entryB})
	eventually(t, "no sessions", func() bool {
		return a.sessions.Load().Count()["quic"] == connector.QUICSessions && b.sessions.Load().Count()["quic"] == connector.QUICSessions
	})
	sa, sb := a.lastQUIC.Load(), b.lastQUIC.Load()
	for _, c := range []struct {
		s     tunnel.Session
		route string
		want  tunnelv1.ResultCode
	}{
		{sa, "rt_a", tunnelv1.ResultCode_RESULT_CODE_NO_ERROR},
		{sa, "rt_b", tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN}, // the other group's route
		{sb, "rt_a", tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN},
		{sa, "rt_both", tunnelv1.ResultCode_RESULT_CODE_NO_ERROR},
		{sb, "rt_both", tunnelv1.ResultCode_RESULT_CODE_NO_ERROR},
		{sa, "rt_nowhere", tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN},
	} {
		if got := rawOpen(t, c.s, c.route); got != c.want {
			t.Errorf("%s through %s: %s, want %s", c.route, map[tunnel.Session]string{sa: "A", sb: "B"}[c.s], got, c.want)
		}
	}

	// Gateway A moves to another group: its routes are now rt_next only.
	entryA.Routes = map[string]string{"rt_next": quic}
	m.Set([]connector.Gateway{entryA, entryB})
	if a.lastQUIC.Load() != sa {
		t.Fatal("the session was redialled")
	}
	if got := rawOpen(t, sa, "rt_a"); got != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Errorf("a route taken from the gateway, within the drain period: %s", got)
	}
	if got := rawOpen(t, sa, "rt_next"); got != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Errorf("the gateway's new route: %s", got)
	}
	time.Sleep(600 * time.Millisecond)
	for _, r := range []string{"rt_a", "rt_both"} {
		if got := rawOpen(t, sa, r); got != tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN {
			t.Errorf("%s after the drain period: %s", r, got)
		}
	}
	if got := rawOpen(t, sb, "rt_both"); got != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR {
		t.Errorf("rt_both through B after A moved: %s", got)
	}
}
