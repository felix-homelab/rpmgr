// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/tlspeek"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// publicCA is a stand-in for a public CA, or for an intercepting proxy's own CA.
type publicCA struct {
	pool *x509.CertPool
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newPublicCA(t *testing.T, name string) *publicCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &publicCA{pool: pool, cert: c, key: k}
}

// leaf issues a server certificate for host.
func (ca *publicCA) leaf(t *testing.T, host string) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

const wssHost = "tunnel.example.com"

// wssGateway runs a router whose WSS hostname is wssHost, with a certificate of ca; its tunnel
// completes the inner mutual TLS within handshake and then echoes what the connector sends.
func wssGateway(t *testing.T, w *world, ca *publicCA, handshake time.Duration) (addr string, closed chan error) {
	t.Helper()
	def, err := gateway.DefaultTLS()
	if err != nil {
		t.Fatal(err)
	}
	var name gateway.WSSHostname
	name.Set(wssHost)
	inner := w.tunnelTLS.Clone()
	inner.NextProtos = []string{tunnel.ALPNH2}
	closed = make(chan error, 4)
	echo := func(c *tls.Conn) {
		defer func() { _ = c.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), handshake)
		err := c.HandshakeContext(ctx)
		cancel()
		if err != nil {
			closed <- err
			return
		}
		_, _ = io.Copy(c, c)
		closed <- nil
	}
	r := &gateway.Router{TrustDomain: td, GatewayID: w.gw.ID, TunnelTLS: inner, DefaultTLS: def, Tunnel: echo,
		WSSHostname: name.Get, WSS: func(c *tls.Conn) { gateway.ServeWSS(c, inner, echo) },
		WSSTLS: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{ca.leaf(t, wssHost)}, NextProtos: []string{"http/1.1"}}}
	return serve(t, r), closed
}

// dialWSS upgrades to the WebSocket at path through the TCP address dial, trusting roots for the
// outer TLS, and returns it as a net.Conn.
func dialWSS(t *testing.T, dial string, roots *x509.CertPool, path string) (net.Conn, error) {
	t.Helper()
	ws, err := dialWS(t, dial, roots, path)
	if err != nil {
		return nil, err
	}
	return websocket.NetConn(context.Background(), ws, websocket.MessageBinary), nil
}

// dialWS upgrades to the WebSocket at path through the TCP address dial, trusting roots for the
// outer TLS.
func dialWS(t *testing.T, dial string, roots *x509.CertPool, path string) (*websocket.Conn, error) {
	t.Helper()
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, dial)
		}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, resp, err := websocket.Dial(ctx, "wss://"+wssHost+path, &websocket.DialOptions{HTTPClient: hc})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return ws, nil
}

// TestDecide_WSS: the gateway's WSS hostname goes to WSS, before the routes; without one, or for
// another name, nothing changes.
func TestDecide_WSS(t *testing.T) {
	var name gateway.WSSHostname
	r := &gateway.Router{TrustDomain: td, GatewayID: "gw_01ABC", WSSHostname: name.Get, WSS: func(*tls.Conn) {},
		Routes: fakeRoutes{http: map[string]bool{"app.example.com": true}}}
	if got := r.Decide(&tlspeek.ClientHello{ServerName: wssHost}); got != gateway.DecideDefault {
		t.Fatalf("without a WSS hostname: %s", got)
	}
	name.Set(wssHost)
	for sni, want := range map[string]gateway.Decision{wssHost: gateway.DecideWSS, "TUNNEL.example.com.": gateway.DecideWSS,
		"app.example.com": gateway.DecideHTTP, "other.example.com": gateway.DecideDefault} {
		if got := r.Decide(&tlspeek.ClientHello{ServerName: sni, ALPN: []string{"http/1.1"}}); got != want {
			t.Errorf("%s: %s, want %s", sni, got, want)
		}
	}
}

// TestWSS: an upgrade at /.rpmgr/tunnel carries the data session's inner TLS, which pins the
// controller's root; another path is 404; an upgrade whose inner handshake never comes is closed
// after the handshake timeout.
func TestWSS(t *testing.T) {
	w := newWorld(t)
	ca := newPublicCA(t, "public root")
	addr, closed := wssGateway(t, w, ca, 300*time.Millisecond)

	nc, err := dialWSS(t, addr, ca.pool, gateway.WSSPath)
	if err != nil {
		t.Fatal(err)
	}
	inner := tls.Client(nc, w.conTLS(w.gw.DNSName(), tunnel.ALPNH2))
	if err := ping(inner, "over wss"); err != nil {
		t.Fatalf("the inner session: %v", err)
	}
	if st := inner.ConnectionState(); st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != tunnel.ALPNH2 {
		t.Fatalf("inner TLS %x, ALPN %q", st.Version, st.NegotiatedProtocol)
	}
	_ = inner.Close()

	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}}
	for _, path := range []string{"/", "/.rpmgr/tunnel/x", "/.rpmgr/", "/api"} {
		resp, err := hc.Get("https://" + wssHost + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, resp.StatusCode)
		}
	}

	// An upgrade that never starts the inner handshake.
	nc, err = dialWSS(t, addr, ca.pool, gateway.WSSPath)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := nc.Read(make([]byte, 1)); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("an upgrade without the inner handshake: %v after %s", err, time.Since(start))
	}
	drain(closed)
}

// TestWSS_MessageLimit: the gateway reads a WebSocket message of 64 KiB, and closes the
// connection on a larger one; the session's connection is on the network "wss", with the peer's
// address.
func TestWSS_MessageLimit(t *testing.T) {
	w := newWorld(t)
	ca := newPublicCA(t, "public root")
	var name gateway.WSSHostname
	name.Set(wssHost)
	read := make(chan error, 2)
	var total atomic.Int64
	r := &gateway.Router{TrustDomain: td, GatewayID: w.gw.ID, WSSHostname: name.Get,
		WSS: func(c *tls.Conn) {
			gateway.ServeWSS(c, w.tunnelTLS, func(inner *tls.Conn) {
				if a := inner.RemoteAddr(); a.Network() != "wss" || !strings.HasPrefix(a.String(), "127.0.0.1:") {
					read <- fmt.Errorf("remote address %s %s", a.Network(), a)
					return
				}
				n, err := io.Copy(io.Discard, inner.NetConn())
				total.Store(n)
				read <- err
			})
		},
		WSSTLS: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{ca.leaf(t, wssHost)}, NextProtos: []string{"http/1.1"}}}
	addr := serve(t, r)
	for _, tc := range []struct {
		size int
		big  bool
	}{{64 << 10, false}, {64<<10 + 1, true}} {
		ws, err := dialWS(t, addr, ca.pool, gateway.WSSPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := ws.Write(t.Context(), websocket.MessageBinary, make([]byte, tc.size)); err != nil {
			t.Fatal(err)
		}
		if !tc.big {
			_ = ws.Close(websocket.StatusNormalClosure, "")
		}
		select {
		case err := <-read:
			if got := errors.Is(err, websocket.ErrMessageTooBig); got != tc.big || (!tc.big && (err != nil || total.Load() != 65536)) {
				t.Fatalf("a message of %d bytes: %d read, %v", tc.size, total.Load(), err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("a message of %d bytes: the gateway still reads", tc.size)
		}
		_ = ws.CloseNow()
	}
}

// TestWSS_InnerClientWithoutCertificate: inside the WebSocket the gateway demands the connector's
// certificate as over TCP; an inner client without one gets no session.
func TestWSS_InnerClientWithoutCertificate(t *testing.T) {
	w := newWorld(t)
	ca := newPublicCA(t, "public root")
	addr, closed := wssGateway(t, w, ca, 2*time.Second)
	nc, err := dialWSS(t, addr, ca.pool, gateway.WSSPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := w.conTLS(w.gw.DNSName(), tunnel.ALPNH2)
	cfg.Certificates, cfg.GetClientCertificate = nil, nil
	inner := tls.Client(nc, cfg)
	_ = inner.SetDeadline(time.Now().Add(5 * time.Second))
	if err := ping(inner, "anonymous"); err == nil {
		t.Fatal("an inner client without a certificate got a session")
	}
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("the gateway served an inner client without a certificate")
		}
		t.Logf("refused as expected: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway did not end the session")
	}
}

func drain(c chan error) {
	for {
		select {
		case <-c:
		default:
			return
		}
	}
}

// interceptor is a TLS-intercepting proxy: it ends the client's TLS with a certificate of its own
// CA, which the client trusts, opens its own TLS to the gateway, and records the plaintext it sees
// both ways.
type interceptor struct {
	mu          sync.Mutex
	toGateway   bytes.Buffer // the connector's plaintext: the upgrade, then masked frames
	toConnector bytes.Buffer
}

// oneWay records one direction into its buffer.
type oneWay struct {
	i *interceptor
	b *bytes.Buffer
}

func (r oneWay) Write(p []byte) (int, error) {
	r.i.mu.Lock()
	defer r.i.mu.Unlock()
	return r.b.Write(p)
}

// saw reports whether the proxy could read s in either direction: as sent towards the connector,
// or in the connector's WebSocket frames once unmasked, as any proxy can.
func (i *interceptor) saw(s string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return bytes.Contains(i.toConnector.Bytes(), []byte(s)) || bytes.Contains(unmask(i.toGateway.Bytes()), []byte(s))
}

// unmask returns the connector's upgrade request followed by the payloads of its WebSocket frames,
// unmasked (RFC 6455, section 5.2); a frame cut short ends it.
func unmask(b []byte) []byte {
	head, frames, ok := bytes.Cut(b, []byte("\r\n\r\n"))
	if !ok {
		return b
	}
	out := append([]byte(nil), head...)
	for len(frames) >= 2 {
		n, at := uint64(frames[1]&0x7f), 2
		switch n {
		case 126:
			if len(frames) < 4 {
				return out
			}
			n, at = uint64(binary.BigEndian.Uint16(frames[2:])), 4
		case 127:
			if len(frames) < 10 {
				return out
			}
			n, at = binary.BigEndian.Uint64(frames[2:]), 10
		}
		var key []byte
		if frames[1]&0x80 != 0 {
			if len(frames) < at+4 {
				return out
			}
			key, at = frames[at:at+4], at+4
		}
		if uint64(len(frames)-at) < n { //nolint:gosec // G115: at is at most len(frames)
			return out
		}
		payload := append([]byte(nil), frames[at:at+int(n)]...)
		for j := range payload {
			if key != nil {
				payload[j] ^= key[j%4]
			}
		}
		out, frames = append(out, payload...), frames[at+int(n):]
	}
	return out
}

func (i *interceptor) run(t *testing.T, own *publicCA, gatewayAddr string, gatewayRoots *x509.CertPool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cert := own.leaf(t, wssHost)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				down := tls.Server(c, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
				up, err := tls.Dial("tcp", gatewayAddr, &tls.Config{ServerName: wssHost, RootCAs: gatewayRoots, MinVersion: tls.VersionTLS12,
					NextProtos: []string{"http/1.1"}})
				if err != nil {
					_ = down.Close()
					return
				}
				go func() { _, _ = io.Copy(io.MultiWriter(up, oneWay{i, &i.toGateway}), down); _ = up.Close() }()
				_, _ = io.Copy(io.MultiWriter(down, oneWay{i, &i.toConnector}), up)
				_ = down.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// TestWSS_InterceptorSeesOnlyInnerTLS (docs/12-testing-and-quality.md): through a TLS-intercepting
// proxy that the connector's outer TLS trusts, the data session's inner TLS 1.3 with mutual
// authentication completes only against the pinned root; the proxy's view, the WebSocket frames
// unmasked, holds the inner ClientHello, as TLS over TCP shows it, but no byte of the session; a
// wrong path is 404 and an upgrade without the inner handshake is closed (TestWSS).
func TestWSS_InterceptorSeesOnlyInnerTLS(t *testing.T) {
	w := newWorld(t)
	public := newPublicCA(t, "public root")
	addr, closed := wssGateway(t, w, public, 2*time.Second)
	proxyCA := newPublicCA(t, "corporate proxy")
	var mitm interceptor
	via := mitm.run(t, proxyCA, addr, public.pool)

	nc, err := dialWSS(t, via, proxyCA.pool, gateway.WSSPath)
	if err != nil {
		t.Fatal(err)
	}
	inner := tls.Client(nc, w.conTLS(w.gw.DNSName(), tunnel.ALPNH2))
	payload := "the session's own bytes, which no proxy may read"
	if err := ping(inner, payload); err != nil {
		t.Fatalf("the inner session through the proxy: %v", err)
	}
	if st := inner.ConnectionState(); st.Version != tls.VersionTLS13 || len(st.PeerCertificates) == 0 ||
		!strings.HasSuffix(st.PeerCertificates[0].URIs[0].String(), w.gw.ID) {
		t.Fatalf("the inner TLS: version %x, peer %v", st.Version, st.PeerCertificates)
	}
	_ = inner.Close()
	if !mitm.saw("Upgrade") || !mitm.saw(w.gw.DNSName()) {
		t.Fatal("the proxy saw neither the upgrade nor the inner ClientHello's name: the test does not intercept")
	}
	if mitm.saw(payload) {
		t.Fatal("the proxy read the inner session")
	}

	// The proxy's root does not pass the inner TLS: the connector pins the controller's root.
	nc, err = dialWSS(t, via, proxyCA.pool, gateway.WSSPath)
	if err != nil {
		t.Fatal(err)
	}
	wrong := w.conTLS(w.gw.DNSName(), tunnel.ALPNH2)
	wrong.RootCAs = proxyCA.pool
	bad := tls.Client(nc, wrong)
	_ = bad.SetDeadline(time.Now().Add(5 * time.Second))
	if err := bad.Handshake(); err == nil {
		t.Fatal("the inner TLS completed against another root")
	}
	_ = bad.Close()
	drain(closed)
}
