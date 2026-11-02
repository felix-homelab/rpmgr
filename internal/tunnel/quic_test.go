// SPDX-License-Identifier: Apache-2.0

package tunnel_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

const td = "rpmgr-7f3k2q6m"

// peers are a gateway's and a connector's TLS configurations from a test CA.
type peers struct {
	gateway, connector *tls.Config
}

func newPeers(t *testing.T) peers {
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
	org := ids.New("org")
	gw := pki.Identity{TrustDomain: td, Org: org, Kind: pki.KindGateway, ID: ids.New("gw")}
	con := pki.Identity{TrustDomain: td, Org: org, Kind: pki.KindConnector, ID: ids.New("con")}
	leaf := func(id pki.Identity) tls.Certificate {
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
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	return peers{
		gateway: pki.ServerConfig(leaf(gw), roots, pki.Expect{TrustDomain: td, Kinds: []pki.Kind{pki.KindConnector}}, nil),
		connector: pki.ClientConfig(leaf(con), roots, gw.DNSName(),
			pki.Expect{TrustDomain: td, Exact: &gw}, nil, nil),
	}
}

// gateway is a gateway's QUIC side on a UDP port.
type gateway struct {
	pc  net.PacketConn
	tr  *quic.Transport
	ln  *tunnel.QUICListener
	key *quic.StatelessResetKey
}

func startGateway(t *testing.T, p peers, addr string, key *quic.StatelessResetKey) *gateway {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc, StatelessResetKey: key}
	ln, err := tunnel.ListenQUIC(tr, p.gateway, tunnel.NewBudget(tunnel.DefaultWindowBudget))
	if err != nil {
		t.Fatal(err)
	}
	g := &gateway{pc: pc, tr: tr, ln: ln, key: key}
	t.Cleanup(func() { _ = ln.Close(); _ = tr.Close() })
	return g
}

// connect returns both ends of a fresh session.
func connect(t *testing.T) (gw, con *tunnel.QUICSession, g *gateway) {
	t.Helper()
	p := newPeers(t)
	g = startGateway(t, p, "127.0.0.1:0", nil)
	con = dial(t, p, g)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gw, err := g.ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	return gw, con, g
}

func dial(t *testing.T, p peers, g *gateway) *tunnel.QUICSession {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() { _ = tr.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := tunnel.DialQUIC(ctx, tr, g.pc.LocalAddr(), p.connector, tunnel.NewBudget(tunnel.DefaultWindowBudget))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func accept(t *testing.T, s tunnel.Session) tunnel.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := s.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// TestQUIC_HalfClose: each direction ends on its own; data still flows the other way.
func TestQUIC_HalfClose(t *testing.T) {
	gw, con, _ := connect(t)
	st, err := gw.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("client bytes")); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	in := accept(t, con)
	got, err := io.ReadAll(in)
	if err != nil || string(got) != "client bytes" {
		t.Fatalf("connector read %q, %v", got, err)
	}
	// The client's FIN does not end the other direction.
	if _, err := in.Write([]byte("service bytes")); err != nil {
		t.Fatal(err)
	}
	if err := in.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	back, err := io.ReadAll(st)
	if err != nil || string(back) != "service bytes" {
		t.Fatalf("gateway read %q, %v", back, err)
	}
	_ = st.Close()
	_ = in.Close()
}

// TestQUIC_ResetIsAnError: an aborted stream is an error at the peer, never a clean EOF, and a
// result written before SetReliableBoundary still arrives.
func TestQUIC_ResetIsAnError(t *testing.T) {
	gw, con, _ := connect(t)
	st, err := gw.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	in := accept(t, con)
	if err := tunnel.WriteMessage(in, &tunnelv1.StreamResult{Code: tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_RESET}); err != nil {
		t.Fatal(err)
	}
	in.SetReliableBoundary()
	in.Abort()
	res := &tunnelv1.StreamResult{}
	if err := tunnel.ReadMessage(st, res); err != nil || res.GetCode() != tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_RESET {
		t.Fatalf("the result before the reset: %v %v", res, err)
	}
	_, err = io.ReadAll(st)
	var se *quic.StreamError
	if !errors.As(err, &se) || !se.Remote {
		t.Fatalf("after the peer's reset: %v, want a stream error", err)
	}
}

// TestQUIC_StreamLimitNeverBlocks: the gateway opens up to the connector's 10 000-stream limit;
// the next OpenStream fails at once instead of waiting.
func TestQUIC_StreamLimitNeverBlocks(t *testing.T) {
	gw, _, _ := connect(t)
	for i := range tunnel.ConnectorIncomingStreams {
		if _, err := gw.OpenStream(context.Background()); err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
	}
	start := time.Now()
	if _, err := gw.OpenStream(context.Background()); !errors.Is(err, tunnel.ErrStreamLimit) {
		t.Fatalf("over the limit: %v", err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("OpenStream took %v at the limit", d)
	}
}

// TestStatelessReset_DetectedWithinPingInterval: after a gateway restart with its persisted reset
// key, an idle connector notices the dead session at its next padded Ping, long before the 30 s
// idle timeout.
func TestStatelessReset_DetectedWithinPingInterval(t *testing.T) {
	p := newPeers(t)
	key, err := tunnel.LoadResetKey(filepath.Join(t.TempDir(), "reset.key"))
	if err != nil {
		t.Fatal(err)
	}
	g := startGateway(t, p, "127.0.0.1:0", key)
	con := dial(t, p, g)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := g.ln.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	control, err := con.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	send := func(m *tunnelv1.SessionMessage) error {
		mu.Lock()
		defer mu.Unlock()
		return tunnel.WriteMessage(control, m)
	}
	const interval = 300 * time.Millisecond
	pingCtx, stopPings := context.WithCancel(context.Background())
	defer stopPings()
	go func() { _ = tunnel.SendPings(pingCtx, send, interval) }()

	// The gateway crashes: its socket goes away without a CONNECTION_CLOSE, and it comes back on
	// the same port with the same key.
	addr := g.pc.LocalAddr().String()
	_ = g.pc.Close()
	restarted := startGateway(t, p, addr, key)
	defer func() { _ = restarted.ln.Close() }()
	start := time.Now()
	select {
	case <-con.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the connector did not notice the restart")
	}
	if d := time.Since(start); d > 2*interval {
		t.Fatalf("noticed after %v, want within about one ping interval (%v)", d, interval)
	}
	if !errors.As(con.Err(), new(*quic.StatelessResetError)) {
		t.Fatalf("the session ended with %v, want a stateless reset", con.Err())
	}
}

func TestQUICConfig(t *testing.T) {
	w := tunnel.H2Windows{Stream: 4 << 20, Conn: 64 << 20}
	for _, connector := range []bool{true, false} {
		c := tunnel.QUICConfig(connector, w)
		want := int64(tunnel.GatewayIncomingStreams)
		if connector {
			want = tunnel.ConnectorIncomingStreams
		}
		// 0-RTT: tools/bannedapi refuses every use of Allow0RTT, so it stays at false.
		if !c.EnableDatagrams || !c.EnableStreamResetPartialDelivery || c.MaxIncomingStreams != want ||
			c.HandshakeIdleTimeout != 5*time.Second || c.MaxIdleTimeout != 30*time.Second || c.KeepAlivePeriod != 10*time.Second ||
			c.MaxStreamReceiveWindow != 4<<20 || c.InitialStreamReceiveWindow != 512<<10 ||
			c.InitialConnectionReceiveWindow != 64<<20 || c.MaxConnectionReceiveWindow != 64<<20 ||
			c.AllowConnectionWindowIncrease != nil {
			t.Errorf("connector %v: %+v", connector, c)
		}
	}
	// A stream window below the usual initial one lowers the initial one too.
	if c := tunnel.QUICConfig(true, tunnel.H2Windows{Stream: 64 << 10, Conn: 1 << 20}); c.InitialStreamReceiveWindow != 64<<10 {
		t.Errorf("initial stream window %d", c.InitialStreamReceiveWindow)
	}
}

func TestLoadResetKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reset.key")
	k1, err := tunnel.LoadResetKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}
	k2, err := tunnel.LoadResetKey(path)
	if err != nil || *k1 != *k2 {
		t.Fatal("the key changed across loads")
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tunnel.LoadResetKey(path); err == nil {
		t.Fatal("a short key was loaded")
	}
	if _, err := tunnel.LoadResetKey(filepath.Join(t.TempDir(), "missing", "reset.key")); err == nil {
		t.Fatal("a key was created in a missing directory")
	}
}

// TestQUIC_SessionAdmission: each QUIC session is admitted against the budget of its side with its
// own connection window; a gateway whose budget is spent refuses a further session, a connector
// whose budget is spent does not even dial, and what a session took returns when it ends.
func TestQUIC_SessionAdmission(t *testing.T) {
	p := newPeers(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	gwBudget := tunnel.NewBudget(2 << 20) // two sessions of the 1 MiB floor
	ln, err := tunnel.ListenQUIC(tr, p.gateway, gwBudget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = tr.Close() })
	cpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctr := &quic.Transport{Conn: cpc}
	t.Cleanup(func() { _ = ctr.Close() })
	conBudget := tunnel.NewBudget(tunnel.DefaultWindowBudget)
	dialOnce := func() (*tunnel.QUICSession, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return tunnel.DialQUIC(ctx, ctr, pc.LocalAddr(), p.connector, conBudget)
	}
	var cons, gws []*tunnel.QUICSession
	for range 2 {
		con, err := dialOnce()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		gw, err := ln.Accept(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		cons, gws = append(cons, con), append(gws, gw)
	}
	if got := gwBudget.Used(); got != 2<<20 {
		t.Fatalf("the gateway's budget holds %d after two sessions, want 2 MiB", got)
	}
	if _, err := dialOnce(); err == nil {
		t.Fatal("a third session was admitted into a spent budget")
	}
	if got := gwBudget.Used(); got != 2<<20 {
		t.Fatalf("the refused session changed the budget to %d", got)
	}
	// The windows of an admitted session are its own: the session works.
	st, err := cons[0].OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if got := accept(t, gws[0]); got == nil {
		t.Fatal("no stream")
	}

	// A session that ends gives its share back, and the next session is admitted again.
	_ = cons[0].Close()
	deadline := time.Now().Add(5 * time.Second)
	for gwBudget.Used() != 1<<20 {
		if time.Now().After(deadline) {
			t.Fatalf("the budget holds %d after a session ended, want 1 MiB", gwBudget.Used())
		}
		time.Sleep(10 * time.Millisecond)
	}
	con, err := dialOnce()
	if err != nil {
		t.Fatalf("a session after a release: %v", err)
	}
	cons = append(cons, con)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	gw, err := ln.Accept(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	gws = append(gws, gw)

	// The connector's own budget gates the dial.
	spent := tunnel.NewBudget(1 << 10)
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := tunnel.DialQUIC(ctx, ctr, pc.LocalAddr(), p.connector, spent); !errors.Is(err, tunnel.ErrBudget) {
		t.Fatalf("a dial with a spent budget: %v", err)
	}
	for _, s := range append(cons, gws...) {
		_ = s.Close()
	}
	for gwBudget.Used() != 0 || conBudget.Used() != 0 {
		if time.Now().After(deadline.Add(5 * time.Second)) {
			t.Fatalf("budgets hold %d and %d after every session ended", gwBudget.Used(), conBudget.Used())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestQUIC_FailedHandshakeReleasesAdmission: a connection admitted before its handshake whose
// handshake fails gives its reservation back when the connection ends, not after a timer.
func TestQUIC_FailedHandshakeReleasesAdmission(t *testing.T) {
	p := newPeers(t)
	other := newPeers(t) // another CA: the connector does not trust this gateway
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	budget := tunnel.NewBudget(tunnel.DefaultWindowBudget)
	ln, err := tunnel.ListenQUIC(tr, p.gateway, budget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = tr.Close() })
	cpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctr := &quic.Transport{Conn: cpc}
	t.Cleanup(func() { _ = ctr.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := tunnel.DialQUIC(ctx, ctr, pc.LocalAddr(), other.connector, tunnel.NewBudget(tunnel.DefaultWindowBudget)); err == nil {
		t.Fatal("the handshake with an untrusted gateway succeeded")
	}
	deadline := time.Now().Add(5 * time.Second)
	for budget.Used() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the budget holds %d after the handshake failed", budget.Used())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// quicPair is a gateway listener on one UDP socket and a connector transport on another.
type quicPair struct {
	p      peers
	ln     *tunnel.QUICListener
	addr   net.Addr
	budget *tunnel.Budget
}

func newQUICPair(t *testing.T, limit uint64) quicPair {
	t.Helper()
	p := newPeers(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	b := tunnel.NewBudget(limit)
	ln, err := tunnel.ListenQUIC(tr, p.gateway, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = tr.Close() })
	return quicPair{p: p, ln: ln, addr: pc.LocalAddr(), budget: b}
}

// dialFrom dials the gateway from a new transport on the local address ip.
func (q quicPair) dialFrom(t *testing.T, ip string) (*tunnel.QUICSession, error) {
	t.Helper()
	cpc, err := net.ListenPacket("udp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	ctr := &quic.Transport{Conn: cpc}
	t.Cleanup(func() { _ = ctr.Close() })
	return q.dialOn(ctr)
}

func (q quicPair) dialOn(ctr *quic.Transport) (*tunnel.QUICSession, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return tunnel.DialQUIC(ctx, ctr, q.addr, q.p.connector, tunnel.NewBudget(tunnel.DefaultWindowBudget))
}

func eventuallyUsed(t *testing.T, b *tunnel.Budget, want uint64, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for b.Used() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s: the budget holds %d, want %d", what, b.Used(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestQUIC_SameAddressHandshakesKeepTheirOwnAdmission: a connector redials from the same UDP socket
// before the gateway accepted the first session. Each accepted session is held to the windows and
// the budget share of its own handshake, whichever is accepted first, and ending one returns
// exactly its share.
func TestQUIC_SameAddressHandshakesKeepTheirOwnAdmission(t *testing.T) {
	const mib = 1 << 20
	q := newQUICPair(t, 64*mib)
	cpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctr := &quic.Transport{Conn: cpc}
	t.Cleanup(func() { _ = ctr.Close() })
	for range 2 {
		con, err := q.dialOn(ctr) // the same ip:port, the first not yet accepted
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = con.Close() })
	}
	got := map[int]*tunnel.QUICSession{}
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		gw, err := q.ln.Accept(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		got[tunnel.SessionWindows(gw).Conn] = gw
		t.Cleanup(func() { _ = gw.Close() })
	}
	big, small := 4*mib, 2*mib // a sixteenth of the budget, then half of what the prefix has left of its 8 MiB
	if got[big] == nil || got[small] == nil {
		t.Fatalf("the sessions hold windows %v, want one of %d and one of %d", got, big, small)
	}
	if want := uint64(big + small); q.budget.Used() != want { //nolint:gosec // G115: test windows
		t.Fatalf("the budget holds %d, want %d", q.budget.Used(), want)
	}
	if q.ln.PendingBytes() != 0 {
		t.Fatalf("%d bytes still count as unclaimed", q.ln.PendingBytes())
	}
	_ = got[small].Close()
	eventuallyUsed(t, q.budget, uint64(big), "after the smaller session ended") //nolint:gosec // G115: test windows
}

// TestQUIC_HalfOpenHandshakesAreCapped: handshakes whose session nobody accepted yet hold their
// reservations only up to a share of the budget per source prefix: further handshakes from that
// /24 are refused, another prefix is still admitted, and accepting (claiming) lets the first
// prefix dial again.
func TestQUIC_HalfOpenHandshakesAreCapped(t *testing.T) {
	q := newQUICPair(t, tunnel.DefaultWindowBudget)
	cpc, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	ctr := &quic.Transport{Conn: cpc}
	t.Cleanup(func() { _ = ctr.Close() })
	held := 0
	for ; held < 16; held++ { // a real source address, validated by Retry
		c, err := q.dialOn(ctr)
		if err != nil {
			break
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	if held == 0 || held == 16 {
		t.Fatalf("%d handshakes of one prefix were admitted, want the cap to stop them", held)
	}
	before := q.budget.Used()
	if _, err := q.dialFrom(t, "127.0.0.9"); err == nil { // the same /24
		t.Fatal("another host of the same /24 got past the prefix's share")
	}
	if q.budget.Used() != before {
		t.Fatalf("the refused handshake changed the budget from %d to %d", before, q.budget.Used())
	}
	other, err := q.dialFrom(t, "127.1.0.3") // a legitimate connector of another prefix
	if err != nil {
		t.Fatalf("another prefix while the first holds its share: %v", err)
	}
	t.Cleanup(func() { _ = other.Close() })
	for range held + 1 { // accepting claims
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		gw, err := q.ln.Accept(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = gw.Close() })
	}
	if q.ln.PendingBytes() != 0 {
		t.Fatalf("%d bytes still count as unclaimed", q.ln.PendingBytes())
	}
	again, err := q.dialOn(ctr)
	if err != nil {
		t.Fatalf("after the claims: %v", err)
	}
	_ = again.Close()
}

// TestQUIC_ConnectorOpensSessionsInParallel: a connector that opens eight sessions at once from one
// address gets all eight, with shrinking windows, each session held to the windows it was admitted
// with.
func TestQUIC_ConnectorOpensSessionsInParallel(t *testing.T) {
	q := newQUICPair(t, tunnel.DefaultWindowBudget)
	cpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctr := &quic.Transport{Conn: cpc}
	t.Cleanup(func() { _ = ctr.Close() })
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			c, err := q.dialOn(ctr)
			if err == nil {
				t.Cleanup(func() { _ = c.Close() })
			}
			errs <- err
		}()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatalf("a session of eight in parallel: %v", err)
		}
	}
	var total uint64
	for range 8 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		gw, err := q.ln.Accept(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = gw.Close() })
		w := tunnel.SessionWindows(gw)
		if w.Conn < 1<<20 || w.Stream != w.Conn/16 {
			t.Fatalf("windows %+v", w)
		}
		total += uint64(w.Conn) //nolint:gosec // G115: a window is positive
	}
	if total != q.budget.Used() || total > tunnel.DefaultWindowBudget/8 {
		t.Fatalf("the sessions hold %d, the budget %d", total, q.budget.Used())
	}
}

// TestQUIC_AdmissionCapsAndUnverified: the listener refuses an address that is not verified, caps
// the unclaimed reservations of one source prefix at an eighth of the budget and of all together at
// half of it, sizes an admission to what its prefix has left, and gives a reservation back when its
// connection ends.
func TestQUIC_AdmissionCapsAndUnverified(t *testing.T) {
	const mib = 1 << 20
	q := newQUICPair(t, 64*mib) // per prefix 8 MiB, all together 32 MiB
	if _, err := q.ln.Admit("203.0.113.1:1000", false); !errors.Is(err, tunnel.ErrUnverified) {
		t.Fatalf("an unverified address: %v", err)
	}
	if q.budget.Used() != 0 || q.ln.PendingBytes() != 0 {
		t.Fatal("a refused connection took a reservation")
	}
	fill := func(prefix string) (ends []func()) { // 4 + 2 + 1 + 1 MiB: the whole share of the prefix
		for i := range 4 {
			end, err := q.ln.Admit(prefix+strconv.Itoa(1+i)+":1000", true) // different hosts of the /24
			if err != nil {
				t.Fatalf("%s admission %d: %v", prefix, i, err)
			}
			ends = append(ends, end)
		}
		return ends
	}
	a := fill("203.0.113.")
	if q.budget.Used() != 8*mib {
		t.Fatalf("the budget holds %d after the first prefix, want 8 MiB", q.budget.Used())
	}
	for _, addr := range []string{"203.0.113.9:1000", "203.0.113.1:2000", "203.0.113.200:1000"} {
		if _, err := q.ln.Admit(addr, true); !errors.Is(err, tunnel.ErrBudget) {
			t.Fatalf("%s beyond its prefix's share: %v", addr, err)
		}
	}
	if q.budget.Used() != 8*mib {
		t.Fatal("a capped admission kept a share of the budget")
	}
	b := fill("198.51.100.") // a second flooding prefix at its maximum
	// A third prefix is still admitted, with what the budget leaves it.
	c, err := q.ln.Admit("192.0.2.1:1000", true)
	if err != nil {
		t.Fatalf("a third prefix beside two flooding ones: %v", err)
	}
	// IPv6 hosts of one /64 share an allowance; another /64 does not.
	var v6 []func()
	for i := range 4 {
		end, err := q.ln.Admit("[2001:db8:1:1::"+strconv.Itoa(1+i)+"]:1000", true)
		if err != nil {
			t.Fatalf("IPv6 admission %d: %v", i, err)
		}
		v6 = append(v6, end)
	}
	if _, err := q.ln.Admit("[2001:db8:1:1::99]:1000", true); !errors.Is(err, tunnel.ErrBudget) {
		t.Fatalf("a fifth host of one /64: %v", err)
	}
	if _, err := q.ln.Admit("[2001:db8:1:2::1]:1000", true); err != nil {
		t.Fatalf("another /64: %v", err)
	}
	if got := q.ln.PendingBytes(); got > 32*mib {
		t.Fatalf("%d bytes unclaimed, above half of the budget", got)
	}
	used := q.budget.Used()
	a[0]() // a connection ends: its reservation and its place count again
	eventuallyUsed(t, q.budget, used-4*mib, "after a connection ended")
	if _, err := q.ln.Admit("203.0.113.1:3000", true); err != nil {
		t.Fatalf("after a connection ended: %v", err)
	}
	for _, e := range append(append(append(a[1:], b...), c), v6...) {
		e()
	}
}

// TestQUIC_ListenerEdges: a transport that is configured already is refused; a connection nobody
// accepted gives its admission back when it ends, or when the listener closes with it queued; and
// an Accept that is cancelled while it waits loses nothing.
func TestQUIC_ListenerEdges(t *testing.T) {
	p := newPeers(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	busy := &quic.Transport{Conn: pc, VerifySourceAddress: func(net.Addr) bool { return false }}
	if _, err := tunnel.ListenQUIC(busy, p.gateway, tunnel.NewBudget(tunnel.DefaultWindowBudget)); err == nil {
		t.Fatal("a transport with its own source address check was taken over")
	}
	_ = busy.Close()

	q := newQUICPair(t, tunnel.DefaultWindowBudget)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	if _, err := q.ln.Accept(ctx); err == nil {
		t.Fatal("Accept returned a session from nothing")
	}
	cancel()
	// A connection that ends before it is accepted returns its reservation and its place.
	con, err := q.dialFrom(t, "127.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	_ = con.Close()
	eventuallyUsed(t, q.budget, 0, "a connection that ended unaccepted")
	if q.ln.PendingBytes() != 0 {
		t.Fatalf("%d bytes still count as unclaimed", q.ln.PendingBytes())
	}
	// The cancelled Accept lost nothing: the next session is accepted with its windows.
	con, err = q.dialFrom(t, "127.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = con.Close() })
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	gw, err := q.ln.Accept(ctx)
	cancel()
	if err != nil || tunnel.SessionWindows(gw).Conn == 0 {
		t.Fatalf("the session after a cancelled Accept: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	// Closing the listener with sessions queued closes them and returns their admissions.
	for range 3 {
		c, err := q.dialFrom(t, "127.0.0.6")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	_ = gw.Close()
	if err := q.ln.Close(); err != nil {
		t.Fatal(err)
	}
	eventuallyUsed(t, q.budget, 0, "a listener closed with queued sessions")
}
