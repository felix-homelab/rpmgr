// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// httpFront serves h's routes on a TLS listener, as the router hands them over, and returns its
// address.
func httpFront(t *testing.T, h *gateway.HTTPRoutes) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := h.TLSConfig()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.Serve(tls.Server(c, cfg))
		}
	}()
	return ln.Addr().String()
}

// routeCert loads a certificate for names into a Certificates and returns it with a pool that
// trusts it.
func routeCert(t *testing.T, names ...string) (*gateway.Certificates, *x509.CertPool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(k)
	item, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.CertificateItem{Chain: [][]byte{der}, PrivateKey: pk})
	sum := sha256.Sum256(item)
	c := gateway.NewCertificates(gateway.CertificatesOptions{Fetch: func(context.Context, string, []byte) ([]byte, error) { return item, nil }})
	if st := c.Apply(t.Context(), []gateway.CertificateRoute{{ID: "crt_1", ContentSHA256: sum[:], Hostnames: names}}); len(st) != 0 {
		t.Fatal(st)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return c, pool
}

// httpEnv is a gateway serving one http route to an upstream behind a connector.
type httpEnv struct {
	routes *gateway.HTTPRoutes
	addr   string
	pool   *x509.CertPool
}

func newHTTPEnv(t *testing.T, upstream http.Handler, route gateway.HTTPRoute) *httpEnv {
	t.Helper()
	up := &http.Server{Handler: upstream, ReadHeaderTimeout: 5 * time.Second}
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if route.Upstream == "h2c" {
		p := new(http.Protocols)
		p.SetUnencryptedHTTP2(true)
		up.Protocols = p
	}
	go func() { _ = up.Serve(upLn) }()
	t.Cleanup(func() { _ = up.Close() })
	p := newPlaneWith(t, upLn.Addr().String(), "none", route.ID)
	return newHTTPEnvOn(t, p.sessions, route)
}

func newHTTPEnvOn(t *testing.T, sessions *gateway.Sessions, routes ...gateway.HTTPRoute) *httpEnv {
	t.Helper()
	certs, pool := routeCert(t, "app.example.com", "*.example.com")
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Sessions: sessions, Certificates: certs})
	t.Cleanup(h.Close)
	h.Apply(routes)
	addr := httpFront(t, h)
	return &httpEnv{routes: h, addr: addr, pool: pool}
}

// client returns an HTTP client of the env that speaks HTTP/2 when h2 is set.
func (e *httpEnv) client(h2 bool) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.pool, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, e.addr)
		}}
	p := new(http.Protocols)
	if h2 {
		p.SetHTTP2(true)
	} else {
		p.SetHTTP1(true)
	}
	tr.Protocols = p
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// reply is what a client got.
type reply struct {
	status int
	proto  int
	header http.Header
	body   string
}

func get(t *testing.T, c *http.Client, url string, header http.Header) reply {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return reply{status: resp.StatusCode, proto: resp.ProtoMajor, header: resp.Header, body: string(b)}
}

// TestHTTPRoutes_RoutePrecedence: an exact hostname before a wildcard one, and the longest path
// prefix at a segment boundary.
func TestHTTPRoutes_RoutePrecedence(t *testing.T) {
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{})
	t.Cleanup(h.Close)
	h.Apply([]gateway.HTTPRoute{
		{ID: "rt_app", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}},
		{ID: "rt_api", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com", PathPrefix: "/api"}}},
		{ID: "rt_v2", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com", PathPrefix: "/api/v2/"}}},
		{ID: "rt_wild", Hosts: []gateway.HTTPHost{{Hostname: "*.example.com"}, {Hostname: "docs.example.com", PathPrefix: "/guide"}}},
	})
	for _, tc := range []struct{ host, path, want string }{
		{"app.example.com", "/", "rt_app"},
		{"APP.example.com:443", "/x", "rt_app"},
		{"app.example.com", "/api", "rt_api"},
		{"app.example.com", "/api/users", "rt_api"},
		{"app.example.com", "/apix", "rt_app"},
		{"app.example.com", "/api/v2/x", "rt_v2"},
		{"app.example.com", "/api/v2", "rt_api"},
		{"www.example.com", "/", "rt_wild"},
		{"docs.example.com", "/guide/x", "rt_wild"},
		{"docs.example.com", "/other", ""}, // docs.example.com is named: no fallback to the wildcard
		{"a.b.example.com", "/", ""},
		{"example.com", "/", ""},
	} {
		if got := gateway.RouteFor(h, tc.host, tc.path); got != tc.want {
			t.Errorf("%s%s: %q, want %q", tc.host, tc.path, got, tc.want)
		}
	}
	if !h.Serves("www.example.com") || !h.Serves("app.example.com") || h.Serves("example.com") || h.Serves("other.net") {
		t.Error("Serves")
	}
}

// TestHTTPRoutes_Proxy: HTTP/1.1 and HTTP/2 clients reach the upstream over a tunnel stream with
// their Host kept and X-Forwarded-* set by the gateway, never taken from the client.
func TestHTTPRoutes_Proxy(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // G705: the test upstream echoes the request as plain text
		_, _ = fmt.Fprintf(w, "%s %s %s|%s|%s|%s", r.Method, r.Host, r.URL.Path, r.Header.Get("X-Forwarded-For"),
			r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Forwarded-Host"))
	})
	e := newHTTPEnv(t, upstream, gateway.HTTPRoute{ID: "rt_web", Upstream: "http", WebSocket: true,
		Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}})
	for _, h2 := range []bool{false, true} {
		r := get(t, e.client(h2), "https://app.example.com/hello", http.Header{"X-Forwarded-For": {"203.0.113.9"}})
		want := "GET app.example.com /hello|127.0.0.1|https|app.example.com"
		if r.status != http.StatusOK || r.body != want || r.proto != map[bool]int{false: 1, true: 2}[h2] {
			t.Errorf("h2 %v: %d %q (HTTP/%d), want %q", h2, r.status, r.body, r.proto, want)
		}
	}
	if r := get(t, e.client(false), "https://other.example.com/", nil); r.status != http.StatusNotFound {
		t.Errorf("a host without a route: %d", r.status)
	}
}

// TestHTTPRoutes_Errors: no ready connector is 503 with Retry-After; a refused upstream 502; an
// upstream that does not answer in time 504.
func TestHTTPRoutes_Errors(t *testing.T) {
	gateway.SetHTTPTimers(t, time.Second, 300*time.Millisecond)
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	// No data session at all.
	idle := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: routeAssignment{"con_x"}})
	t.Cleanup(idle.Close)
	e := newHTTPEnvOn(t, idle, route)
	if r := get(t, e.client(false), "https://app.example.com/", nil); r.status != http.StatusServiceUnavailable ||
		r.header.Get("Retry-After") != "5" {
		t.Errorf("no session: %d %v", r.status, r.header)
	}

	// A connector whose upstream refuses.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	refusedAddr := closed.Addr().String()
	_ = closed.Close()
	p := newPlaneWith(t, refusedAddr, "none", "rt_web")
	e = newHTTPEnvOn(t, p.sessions, route)
	if r := get(t, e.client(true), "https://app.example.com/", nil); r.status != http.StatusBadGateway {
		t.Errorf("refused: %d", r.status)
	}

	// An upstream that accepts and never answers.
	silent := service(t, func(c net.Conn, br *bufio.Reader, _ string) { _, _ = io.Copy(io.Discard, br) })
	p = newPlaneWith(t, silent, "none", "rt_web")
	e = newHTTPEnvOn(t, p.sessions, route)
	if r := get(t, e.client(false), "https://app.example.com/", nil); r.status != http.StatusGatewayTimeout {
		t.Errorf("silent upstream: %d", r.status)
	}
}

// TestHTTPRoutes_SlowHeaders: a client that does not finish its request headers in time is
// closed.
func TestHTTPRoutes_SlowHeaders(t *testing.T) {
	gateway.SetHTTPTimers(t, 300*time.Millisecond, time.Minute)
	e := newHTTPEnv(t, http.NotFoundHandler(), gateway.HTTPRoute{ID: "rt_web", Upstream: "http",
		Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}})
	c, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: "app.example.com", RootCAs: e.pool, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: app.example.com\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, err = io.ReadAll(c)
	if d := time.Since(start); err != nil || d > 3*time.Second {
		t.Fatalf("a slow client was kept %s (%v)", d, err)
	}
}

// websocketEcho answers an Upgrade with 101 and echoes the bytes that follow.
var websocketEcho = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "websocket" {
		http.Error(w, "not an upgrade", http.StatusBadRequest)
		return
	}
	c, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	_ = brw.Flush()
	_, _ = io.Copy(c, brw)
})

// upgrade sends a WebSocket upgrade over HTTP/1.1 and returns the status line and, after a 101,
// the echo of msg.
func upgrade(t *testing.T, e *httpEnv, msg string) (string, string) {
	t.Helper()
	c, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: "app.example.com", RootCAs: e.pool, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = c.Write([]byte("GET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A 101's body is the upgraded connection itself; anything else is read and closed here.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return resp.Status, ""
	}
	_, _ = c.Write([]byte(msg))
	b := make([]byte, len(msg))
	if _, err := io.ReadFull(br, b); err != nil {
		t.Fatal(err)
	}
	return resp.Status, string(b)
}

// TestHTTPRoutes_WebSocket: an upgrade passes through and carries bytes both ways; a route with
// upgrades off refuses it.
func TestHTTPRoutes_WebSocket(t *testing.T) {
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", WebSocket: true, Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	e := newHTTPEnv(t, websocketEcho, route)
	if status, echo := upgrade(t, e, "over the tunnel"); !strings.HasPrefix(status, "101") || echo != "over the tunnel" {
		t.Fatalf("%q %q", status, echo)
	}
	route.WebSocket = false
	e.routes.Apply([]gateway.HTTPRoute{route})
	if status, _ := upgrade(t, e, "x"); !strings.HasPrefix(status, "403") {
		t.Fatalf("upgrades off: %q", status)
	}
}

// TestHTTPRoutes_GRPC: gRPC passes through to an h2c upstream, trailers included.
func TestHTTPRoutes_GRPC(t *testing.T) {
	srv := grpc.NewServer()
	hs := health.NewServer()
	healthpb.RegisterHealthServer(srv, hs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	p := newPlaneWith(t, ln.Addr().String(), "none", "rt_grpc")
	e := newHTTPEnvOn(t, p.sessions, gateway.HTTPRoute{ID: "rt_grpc", Upstream: "h2c", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}})
	cc, err := grpc.NewClient("passthrough:///"+e.addr, grpc.WithTransportCredentials(credentials.NewTLS(
		&tls.Config{ServerName: "app.example.com", RootCAs: e.pool, MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("%v %v", resp, err)
	}
	// An unknown service is an error status carried in the trailers.
	if _, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{Service: "nope"}); err == nil ||
		!strings.Contains(err.Error(), "NotFound") {
		t.Fatalf("a gRPC error status: %v", err)
	}
}

// TestHTTPRoutes_TLS: TLS 1.2 clients get an AEAD suite with forward secrecy and nothing else;
// a name without a certificate gets the default one.
func TestHTTPRoutes_TLS(t *testing.T) {
	certs, pool := routeCert(t, "app.example.com")
	def, err := gateway.DefaultTLS()
	if err != nil {
		t.Fatal(err)
	}
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Certificates: certs, Default: &def.Certificates[0]})
	t.Cleanup(h.Close)
	addr := httpFront(t, h)
	//nolint:gosec // G402: the test checks what a TLS 1.2 client gets
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "app.example.com", RootCAs: pool, MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	if st := c.ConnectionState(); st.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 &&
		st.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 && st.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 {
		t.Errorf("TLS 1.2 suite %s", tls.CipherSuiteName(st.CipherSuite))
	}
	_ = c.Close()
	//nolint:gosec // G402: the test checks that a CBC suite is refused
	if c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "app.example.com", RootCAs: pool, MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}}); err == nil {
		_ = c.Close()
		t.Error("a CBC suite was accepted")
	}
	//nolint:gosec // G402: the test checks that TLS 1.1 is refused
	if c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "app.example.com", RootCAs: pool, MinVersion: tls.VersionTLS11,
		MaxVersion: tls.VersionTLS11}); err == nil {
		_ = c.Close()
		t.Error("TLS 1.1 was accepted")
	}
	c, err = tls.Dial("tcp", addr, &tls.Config{ServerName: "other.example.com", RootCAs: pool, MinVersion: tls.VersionTLS13})
	var wrongName x509.HostnameError
	if !errors.As(err, &wrongName) || !slices.Contains(wrongName.Certificate.DNSNames, "default.invalid") {
		t.Errorf("a name without a certificate: %v", err)
	}
	if c != nil {
		_ = c.Close()
	}
}

// TestHTTPRoutes_ApplyWhileServing: snapshots change a route while requests are served.
func TestHTTPRoutes_ApplyWhileServing(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", WebSocket: true, Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	e := newHTTPEnv(t, upstream, route)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 50 {
			route.WebSocket = i%2 == 0
			e.routes.Apply([]gateway.HTTPRoute{route})
		}
	}()
	c := e.client(true)
	for range 20 {
		if r := get(t, c, "https://app.example.com/", nil); r.status != http.StatusOK || r.body != "ok" {
			t.Fatalf("%d %q", r.status, r.body)
		}
	}
	<-done
}

// upstreamCA is a CA with a TLS server certificate for upstream.internal issued by it.
type upstreamCA struct {
	pem  []byte
	leaf tls.Certificate
}

func newUpstreamCA(t *testing.T) upstreamCA {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "upstream.internal"},
		DNSNames: []string{"upstream.internal"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return upstreamCA{pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		leaf: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}}
}

// TestHTTPRoutes_HTTPSUpstream: an https upstream is verified with the settings of the target the
// connector chose: its CA bundle, server name and SPKI pin; any mismatch, a target without
// settings, or the host's trust store for a private CA is 502. ALPN brings HTTP/2.
func TestHTTPRoutes_HTTPSUpstream(t *testing.T) {
	ca := newUpstreamCA(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{ca.leaf},
		NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	up := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto) //nolint:gosec // G705: the test upstream answers with its protocol as plain text
	})}
	go func() { _ = up.Serve(ln) }()
	t.Cleanup(func() { _ = up.Close() })
	p := newPlaneWith(t, ln.Addr().String(), "none", "rt_tls")
	route := gateway.HTTPRoute{ID: "rt_tls", Upstream: "https", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	e := newHTTPEnvOn(t, p.sessions, route)
	pin := sha256.Sum256(ca.leaf.Leaf.RawSubjectPublicKeyInfo)
	other := newUpstreamCA(t)
	for _, tc := range []struct {
		name string
		tls  map[string]gateway.UpstreamTLS
		want int
	}{
		{"verified", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "upstream.internal", CAPEM: ca.pem}}, http.StatusOK},
		{"pinned", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "upstream.internal", CAPEM: ca.pem, SPKISHA256: pin[:]}}, http.StatusOK},
		{"another CA", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "upstream.internal", CAPEM: other.pem}}, http.StatusBadGateway},
		{"another name", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "other.internal", CAPEM: ca.pem}}, http.StatusBadGateway},
		{"another pin", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "upstream.internal", CAPEM: ca.pem,
			SPKISHA256: make([]byte, 32)}}, http.StatusBadGateway},
		{"the host's trust store", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "upstream.internal"}}, http.StatusBadGateway},
		{"another target's settings only", map[string]gateway.UpstreamTLS{"tg_other": {ServerName: "upstream.internal", CAPEM: ca.pem}},
			http.StatusBadGateway},
	} {
		route.TLS = tc.tls
		e.routes.Apply([]gateway.HTTPRoute{route})
		r := get(t, e.client(false), "https://app.example.com/", nil)
		if r.status != tc.want || tc.want == http.StatusOK && r.body != "HTTP/2.0" {
			t.Errorf("%s: %d %q, want %d", tc.name, r.status, r.body, tc.want)
		}
	}
}

// headerEcho answers with the request's Host, forwarding headers, two test headers and body size,
// and sets a Server header.
var headerEcho = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	n, err := io.Copy(io.Discard, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Server", "upstream/1.0")
	//nolint:gosec // G705: the test upstream echoes the request as plain text
	_, _ = fmt.Fprintf(w, "%s|%s|%s|%s|%s|%s|%s|%d", r.Host, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Proto"),
		r.Header.Get("X-Forwarded-Host"), strings.Join(r.Header.Values("Forwarded"), ", "), r.Header.Get("X-Env"),
		r.Header.Get("X-Debug"), n)
})

// TestHTTPRoutes_Forwarding: a client's forwarding headers are replaced unless it is a trusted
// proxy, whose chain is extended and whose protocol and host are kept.
func TestHTTPRoutes_Forwarding(t *testing.T) {
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	e := newHTTPEnv(t, headerEcho, route)
	spoofed := http.Header{"X-Forwarded-For": {"203.0.113.9"}, "X-Forwarded-Proto": {"http"}, "X-Forwarded-Host": {"evil.example"},
		"Forwarded": {"for=203.0.113.9"}}
	want := `app.example.com|127.0.0.1|https|app.example.com|for=127.0.0.1;host="app.example.com";proto=https|||0`
	if r := get(t, e.client(false), "https://app.example.com/", spoofed); r.body != want {
		t.Errorf("an untrusted client:\n got %s\nwant %s", r.body, want)
	}
	route.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	e.routes.Apply([]gateway.HTTPRoute{route})
	want = `app.example.com|203.0.113.9, 127.0.0.1|http|evil.example|for=203.0.113.9, for=127.0.0.1;host="app.example.com";proto=https|||0`
	if r := get(t, e.client(true), "https://app.example.com/", spoofed); r.body != want {
		t.Errorf("a trusted proxy:\n got %s\nwant %s", r.body, want)
	}
}

// TestHTTPRoutes_Headers: a route sets and removes request and response headers and may send its
// own Host upstream.
func TestHTTPRoutes_Headers(t *testing.T) {
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
		HostHeader:      "internal.local",
		RequestHeaders:  []gateway.HTTPHeader{{Name: "X-Debug"}, {Name: "X-Env", Value: "prod"}},
		ResponseHeaders: []gateway.HTTPHeader{{Name: "Server"}, {Name: "X-Frame-Options", Value: "DENY"}}}
	e := newHTTPEnv(t, headerEcho, route)
	r := get(t, e.client(false), "https://app.example.com/", http.Header{"X-Debug": {"1"}, "X-Env": {"dev"}})
	if !strings.HasPrefix(r.body, "internal.local|") || !strings.HasSuffix(r.body, "|prod||0") || r.header.Get("Server") != "" ||
		r.header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("%q %v", r.body, r.header)
	}
}

// TestHTTPRoutes_BodyLimit: a body at the route's limit passes; one byte more is 413, whether
// announced by Content-Length or streamed.
func TestHTTPRoutes_BodyLimit(t *testing.T) {
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}, MaxBody: 10}
	e := newHTTPEnv(t, headerEcho, route)
	post := func(body io.Reader, length int64) int {
		req, _ := http.NewRequest(http.MethodPost, "https://app.example.com/", body)
		req.ContentLength = length
		resp, err := e.client(false).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if got := post(strings.NewReader("0123456789"), 10); got != http.StatusOK {
		t.Errorf("at the limit: %d", got)
	}
	if got := post(strings.NewReader("0123456789x"), 11); got != http.StatusRequestEntityTooLarge {
		t.Errorf("announced above the limit: %d", got)
	}
	if got := post(io.MultiReader(strings.NewReader("0123456789x")), -1); got != http.StatusRequestEntityTooLarge {
		t.Errorf("streamed above the limit: %d", got)
	}
}

// serve80 serves e's port 80 on a loopback port and returns its address.
func (e *httpEnv) serve80(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = e.routes.Serve80(ln) }()
	return ln.Addr().String()
}

// plain sends a request to port 80 at addr for host and returns the reply without following
// redirects; err is set when the connection closed without one.
func plain(t *testing.T, addr, method, host, target string) (reply, error) {
	t.Helper()
	req, _ := http.NewRequest(method, "http://"+host+target, strings.NewReader("body"))
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}}
	resp, err := c.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return reply{status: resp.StatusCode, header: resp.Header, body: string(b)}, nil
}

// TestHTTPRoutes_Port80: plain HTTP redirects to HTTPS keeping path and query (301 for GET, 308
// otherwise), serves the route, or closes, as the route says; ACME challenges are answered for any
// name, even with port 80 off; a name without a route goes to the fallback, unknown ACME tokens
// included.
func TestHTTPRoutes_Port80(t *testing.T) {
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	p := newPlaneWith(t, service(t, func(c net.Conn, br *bufio.Reader, line string) {
		// A minimal HTTP/1.1 upstream: answer with the forwarded protocol, then close. It reads the
		// request's body first, as plain sends one: closing with unread data sends a reset, which
		// can overtake the answer and turn it into a 502.
		req, err := http.ReadRequest(bufio.NewReader(io.MultiReader(strings.NewReader(line), br)))
		if err != nil {
			_ = c.Close()
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		body := req.Header.Get("X-Forwarded-Proto")
		_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		_ = c.Close()
	}), "none", "rt_web")
	certs, pool := routeCert(t, "app.example.com")
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Sessions: p.sessions, Certificates: certs,
		Challenges: func(host, token string) (string, bool) { return token + ".thumbprint", token == "tok" && host != "" },
		Fallback80: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "fallback", http.StatusTeapot) })})
	t.Cleanup(h.Close)
	e := &httpEnv{routes: h, addr: httpFront(t, h), pool: pool}
	addr := e.serve80(t)
	h.Apply([]gateway.HTTPRoute{route})

	r, err := plain(t, addr, http.MethodGet, "app.example.com", "/a/b?c=d&e")
	if err != nil || r.status != http.StatusMovedPermanently || r.header.Get("Location") != "https://app.example.com/a/b?c=d&e" {
		t.Errorf("redirect: %v %v", r, err)
	}
	if r, err := plain(t, addr, http.MethodPost, "app.example.com:80", "/form"); err != nil || r.status != http.StatusPermanentRedirect ||
		r.header.Get("Location") != "https://app.example.com/form" {
		t.Errorf("redirect of a POST: %v %v", r, err)
	}
	if r, err := plain(t, addr, http.MethodGet, "other.example.com", "/"); err != nil || r.status != http.StatusTeapot {
		t.Errorf("a name without a route: %v %v", r, err)
	}

	route.Port80 = "serve"
	h.Apply([]gateway.HTTPRoute{route})
	if r, err := plain(t, addr, http.MethodGet, "app.example.com", "/"); err != nil || r.status != http.StatusOK || r.body != "http" {
		t.Errorf("serve: %v %v", r, err)
	}

	route.Port80 = "off"
	h.Apply([]gateway.HTTPRoute{route})
	if r, err := plain(t, addr, http.MethodGet, "app.example.com", "/"); err == nil {
		t.Errorf("off answered: %v", r)
	}
	if r, err := plain(t, addr, http.MethodGet, "app.example.com", "/.well-known/acme-challenge/tok"); err != nil ||
		r.status != http.StatusOK || r.body != "tok.thumbprint" {
		t.Errorf("an ACME challenge with port 80 off: %v %v", r, err)
	}
	if r, err := plain(t, addr, http.MethodGet, "app.example.com", "/.well-known/acme-challenge/unknown"); err != nil ||
		r.status != http.StatusNotFound {
		t.Errorf("an unknown ACME token: %v %v", r, err)
	}
	// all-in-one's controller answers the challenges of its own name, which no route serves.
	if r, err := plain(t, addr, http.MethodGet, "panel.example.com", "/.well-known/acme-challenge/unknown"); err != nil ||
		r.status != http.StatusTeapot {
		t.Errorf("an unknown ACME token for a name without a route: %v %v", r, err)
	}
}

// TestHTTPRoutes_HSTS: Strict-Transport-Security goes out over HTTPS only, the route's value
// replacing the upstream's, and not at all when the route sets none.
func TestHTTPRoutes_HSTS(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=1")
		_, _ = io.WriteString(w, "ok")
	})
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Port80: "serve", HSTS: 31536000,
		Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	e := newHTTPEnv(t, upstream, route)
	if r := get(t, e.client(true), "https://app.example.com/", nil); r.header.Values("Strict-Transport-Security")[0] != "max-age=31536000" ||
		len(r.header.Values("Strict-Transport-Security")) != 1 {
		t.Errorf("over HTTPS: %v", r.header.Values("Strict-Transport-Security"))
	}
	addr := e.serve80(t)
	if r, err := plain(t, addr, http.MethodGet, "app.example.com", "/"); err != nil || r.header.Get("Strict-Transport-Security") != "" {
		t.Errorf("over plain HTTP: %v %v", r, err)
	}
	route.HSTS = 0
	e.routes.Apply([]gateway.HTTPRoute{route})
	if r := get(t, e.client(false), "https://app.example.com/", nil); r.header.Get("Strict-Transport-Security") != "max-age=1" {
		t.Errorf("a route without HSTS passes the upstream's: %v", r.header.Values("Strict-Transport-Security"))
	}
}
