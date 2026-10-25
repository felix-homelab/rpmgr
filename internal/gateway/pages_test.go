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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// browser asks for a page as a browser does.
var browser = http.Header{"Accept": {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}}

// isPage reports whether a reply is one of the gateway's pages with the given heading.
func isPage(r reply, title string) bool {
	return strings.HasPrefix(r.header.Get("Content-Type"), "text/html") && strings.Contains(r.header.Get("Content-Security-Policy"), "default-src 'none'") &&
		strings.Contains(r.body, "<h1>"+title+"</h1>")
}

// TestPages_Errors: the errors the gateway makes itself, 503 without a ready connector (with
// Retry-After and the route's HSTS), 502 for a refused upstream and 504 for a silent one, are the
// service-unavailable page for a browser and text for other clients, decided by the client's own
// Host and Accept, not those the route sends upstream; the upstream's own errors pass through
// unchanged, and so does the 413 of the body limit, announced or streamed.
func TestPages_Errors(t *testing.T) {
	gateway.SetHTTPTimers(t, time.Second, 300*time.Millisecond)
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", HSTS: 600, MaxBody: 4, Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	idle := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: routeAssignment{"con_x"}})
	t.Cleanup(idle.Close)
	e := newHTTPEnvOn(t, idle, route)
	for _, h2 := range []bool{false, true} {
		r := get(t, e.client(h2), "https://app.example.com/", browser)
		if r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") != "5" || !isPage(r, "Service unavailable") ||
			r.header.Get("Strict-Transport-Security") != "max-age=600" || !strings.Contains(r.body, ">app.example.com</span>") {
			t.Errorf("no session, h2 %v: %d %v %s", h2, r.status, r.header, r.body)
		}
	}
	if r := get(t, e.client(false), "https://app.example.com/", http.Header{"Accept": {"application/json"}}); r.status != http.StatusServiceUnavailable ||
		r.body != "Service Unavailable\n" || r.header.Get("Retry-After") != "5" {
		t.Errorf("no session, not a browser: %d %q", r.status, r.body)
	}
	// A route that rewrites Host and Accept towards the upstream: the page names the client's host
	// and follows the client's Accept, never the internal name.
	rewriting := route
	rewriting.HostHeader = "nas.internal.lan:5000"
	rewriting.RequestHeaders = []gateway.HTTPHeader{{Name: "Accept", Value: "application/json"}}
	e = newHTTPEnvOn(t, idle, rewriting)
	if r := get(t, e.client(false), "https://app.example.com/", browser); !isPage(r, "Service unavailable") ||
		!strings.Contains(r.body, ">app.example.com</span>") || strings.Contains(r.body, "internal") {
		t.Errorf("a rewritten Host and Accept: %d %s", r.status, r.body)
	}
	rewriting.RequestHeaders = []gateway.HTTPHeader{{Name: "Accept", Value: "text/html"}}
	e = newHTTPEnvOn(t, idle, rewriting)
	if r := get(t, e.client(false), "https://app.example.com/", http.Header{"Accept": {"application/json"}}); r.body != "Service Unavailable\n" {
		t.Errorf("an Accept the route sets to text/html: %q", r.body)
	}

	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	refusedAddr := closed.Addr().String()
	_ = closed.Close()
	e = newHTTPEnvOn(t, newPlaneWith(t, refusedAddr, "none", "rt_web").sessions, route)
	if r := get(t, e.client(true), "https://app.example.com/", browser); r.status != http.StatusBadGateway || !isPage(r, "Service unavailable") ||
		!strings.Contains(r.body, "502 · Bad Gateway") || r.header.Get("Retry-After") != "" {
		t.Errorf("refused: %d %v", r.status, r.header)
	}
	if r := get(t, e.client(false), "https://app.example.com/", nil); r.status != http.StatusBadGateway || r.body != "Bad Gateway\n" {
		t.Errorf("refused, not a browser: %d %q", r.status, r.body)
	}

	silent := service(t, func(_ net.Conn, br *bufio.Reader, _ string) { _, _ = io.Copy(io.Discard, br) })
	e = newHTTPEnvOn(t, newPlaneWith(t, silent, "none", "rt_web").sessions, route)
	if r := get(t, e.client(false), "https://app.example.com/", browser); r.status != http.StatusGatewayTimeout || !isPage(r, "Service unavailable") {
		t.Errorf("silent upstream: %d %v", r.status, r.header)
	}

	// The upstream's own 503 and the body limit's 413 are not the gateway's page.
	e = newHTTPEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "<p>the upstream's own</p>")
	}), route)
	if r := get(t, e.client(false), "https://app.example.com/", browser); r.status != http.StatusServiceUnavailable ||
		r.body != "<p>the upstream's own</p>" || r.header.Get("Content-Security-Policy") != "" {
		t.Errorf("the upstream's 503: %d %q %v", r.status, r.body, r.header)
	}
	for _, body := range []io.Reader{strings.NewReader("too large"), io.MultiReader(strings.NewReader("too large"))} {
		req, _ := http.NewRequest(http.MethodPost, "https://app.example.com/", body)
		req.Header = browser.Clone()
		resp, err := e.client(false).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
			t.Errorf("413, %T body: %d %v", body, resp.StatusCode, resp.Header)
		}
	}
}

// TestPages_NoRoute443: a name or path no route serves, on a connection of its own name, is the
// site-not-available page for a browser, without the route's HSTS, and the text for others; on a
// connection of another name it is misdirected.
func TestPages_NoRoute443(t *testing.T) {
	e := newHTTPEnv(t, http.NotFoundHandler(), gateway.HTTPRoute{ID: "rt_web", Upstream: "http", HSTS: 600,
		Hosts: []gateway.HTTPHost{{Hostname: "app.example.com", PathPrefix: "/app"}}})
	for _, url := range []string{"https://other.example.com/", "https://app.example.com/elsewhere"} {
		r := get(t, e.client(true), url, browser)
		if r.status != http.StatusNotFound || !isPage(r, "Site not available") || r.header.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: %d %v %s", url, r.status, r.header, r.body)
		}
		if r := get(t, e.client(false), url, nil); r.status != http.StatusNotFound || r.body != "no route for this host and path\n" {
			t.Errorf("%s, not a browser: %d %q", url, r.status, r.body)
		}
	}
	dial := func() net.Conn {
		c, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: "app.example.com", RootCAs: e.pool, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	expectMisdirected(t, dial(), "other.example.com")
	if rep := roundTrip(t, dial(), "app.example.com:443"); rep.status != http.StatusNotFound || !isPage(rep, "Site not available") {
		t.Errorf("an unrouted path on its name's connection: %d", rep.status)
	}
}

// expectMisdirected sends a request for host on c and expects 421, after which the gateway closes
// the HTTP/1.1 connection, so that the client connects anew.
func expectMisdirected(t *testing.T, c net.Conn, host string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nAccept: text/html\r\n\r\n", host); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest || !resp.Close {
		t.Errorf("%s: %d, close %v; want 421 and a close", host, resp.StatusCode, resp.Close)
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Errorf("%s: %v after the 421, want the gateway to close", host, err)
	}
}

// selfSigned returns a certificate for names and IP addresses that the returned pool trusts.
func selfSigned(t *testing.T, names []string, ips ...netip.Addr) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "default"}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip.AsSlice())
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}, pool
}

// roundTrip sends one HTTP/1.1 request for host over c and returns the reply.
func roundTrip(t *testing.T, c net.Conn, host string) reply {
	t.Helper()
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nAccept: text/html\r\n\r\n", host); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return reply{status: resp.StatusCode, header: resp.Header, body: string(b)}
}

// TestPages_Unrouted: a name no route serves completes TLS with a certificate the gateway holds
// that covers it, or else with the default one, and every request on that connection gets the
// site-not-available page; a connection without a server name too. A request for a name a
// route serves, or for another name than the connection's, is misdirected, so that a browser
// asks again on a connection of its own: nothing on such a connection reaches a route.
func TestPages_Unrouted(t *testing.T) {
	certs, pool := routeCert(t, "app.example.com", "*.example.com")
	// The default certificate names unknown.test and 127.0.0.1, so that the test can verify it.
	loopback := netip.MustParseAddr("127.0.0.1")
	def, defPool := selfSigned(t, []string{"unknown.test"}, loopback)
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Certificates: certs, Default: &def})
	t.Cleanup(h.Close)
	h.Apply([]gateway.HTTPRoute{{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}})
	r := &gateway.Router{TrustDomain: td, GatewayID: "gw_01", Routes: fakeRoutes{http: map[string]bool{"app.example.com": true}},
		HTTP: h.Serve, HTTPTLS: h.TLSConfig(), Unrouted: h.ServeUnrouted, UnroutedTLS: h.UnroutedTLSConfig()}
	addr := serve(t, r)
	dial := func(serverName string, pool *x509.CertPool, alpn ...string) (*tls.Conn, error) {
		c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: serverName, RootCAs: pool, MinVersion: tls.VersionTLS12, NextProtos: alpn})
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
		}
		return c, err
	}

	// A covered name: the wildcard certificate and the page, twice on one connection; a request
	// for the routed name or for another covered name is misdirected.
	c, err := dial("foo.example.com", pool)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.ConnectionState().PeerCertificates[0]; !slices.Contains(got.DNSNames, "*.example.com") {
		t.Fatalf("foo.example.com got %v", got.DNSNames)
	}
	if rep := roundTrip(t, c, "foo.example.com"); rep.status != http.StatusNotFound || !isPage(rep, "Site not available") ||
		!strings.Contains(rep.body, ">foo.example.com</span>") {
		t.Errorf("foo.example.com: %d %v", rep.status, rep.header)
	}
	if rep := roundTrip(t, c, "FOO.example.com.:443"); rep.status != http.StatusNotFound {
		t.Errorf("foo.example.com again: %d", rep.status)
	}
	for _, host := range []string{"app.example.com", "bar.example.com", "app.example.com:443"} {
		c, err := dial("foo.example.com", pool)
		if err != nil {
			t.Fatal(err)
		}
		expectMisdirected(t, c, host)
	}
	h2 := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}
	h2.Protocols = new(http.Protocols)
	h2.Protocols.SetHTTP2(true)
	t.Cleanup(h2.CloseIdleConnections)
	if rep := get(t, &http.Client{Transport: h2, Timeout: 10 * time.Second}, "https://foo.example.com/", browser); rep.proto != 2 ||
		rep.status != http.StatusNotFound || !isPage(rep, "Site not available") {
		t.Errorf("HTTP/2: HTTP/%d %d %v", rep.proto, rep.status, rep.header)
	}

	// A name nothing covers gets the default certificate, which a client refuses for it, as a
	// browser warns; one the default certificate names, and a connection without a server name,
	// then get the page.
	if _, err := dial("a.b.example.com", defPool); !errors.As(err, new(x509.HostnameError)) {
		t.Errorf("a.b.example.com: %v, want the default certificate", err)
	}
	for _, name := range []string{"unknown.test", loopback.String()} {
		c, err := dial(name, defPool)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep := roundTrip(t, c, name); rep.status != http.StatusNotFound || !isPage(rep, "Site not available") {
			t.Errorf("%s: %d %v", name, rep.status, rep.header)
		}
		expectMisdirected(t, c, "app.example.com")
	}
}

// servesOf is the router's table of h's routes alone.
type servesOf struct{ h *gateway.HTTPRoutes }

func (s servesOf) Passthrough(string) (func(net.Conn), bool) { return nil, false }
func (s servesOf) HTTP(sni string) bool                      { return s.h.Serves(sni) }

// TestPages_RoutedAfterConnect: a connection made before a route served its name, with the
// certificate the gateway already held for it, serves the route once the route is applied, so
// that a client's keep-alive connection reaches it instead of an answer it would never redial on;
// over HTTP/1.1 and HTTP/2.
func TestPages_RoutedAfterConnect(t *testing.T) {
	up := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "app")
	})}
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = up.Serve(upLn) }()
	t.Cleanup(func() { _ = up.Close() })
	p := newPlaneWith(t, upLn.Addr().String(), "none", "rt_web")
	certs, pool := routeCert(t, "app.example.com")
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Sessions: p.sessions, Certificates: certs})
	t.Cleanup(h.Close)
	addr := serve(t, &gateway.Router{TrustDomain: td, GatewayID: "gw_01", Routes: servesOf{h}, HTTP: h.Serve, HTTPTLS: h.TLSConfig(),
		Unrouted: h.ServeUnrouted, UnroutedTLS: h.UnroutedTLSConfig()})
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	for _, h2 := range []bool{false, true} {
		h.Apply(nil)
		var dials atomic.Int32
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				dials.Add(1)
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}}
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetHTTP1(!h2)
		tr.Protocols.SetHTTP2(h2)
		client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
		if r := get(t, client, "https://app.example.com/", browser); r.status != http.StatusNotFound || !isPage(r, "Site not available") {
			t.Fatalf("h2 %v, before the route: %d %v", h2, r.status, r.header)
		}
		h.Apply([]gateway.HTTPRoute{route})
		if r := get(t, client, "https://app.example.com/", nil); r.status != http.StatusOK || r.body != "app" || r.proto != map[bool]int{false: 1, true: 2}[h2] {
			t.Errorf("h2 %v, after the route: HTTP/%d %d %q", h2, r.proto, r.status, r.body)
		}
		if n := dials.Load(); n != 1 {
			t.Errorf("h2 %v: %d connections, want the one kept alive", h2, n)
		}
		tr.CloseIdleConnections()
	}
}

// TestPages_UnroutedSlowBody: nothing reads the body of a request that gets the page, so the gateway
// answers and closes the connection rather than wait for a body the client stops sending.
func TestPages_UnroutedSlowBody(t *testing.T) {
	certs, pool := routeCert(t, "*.example.com")
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Certificates: certs})
	t.Cleanup(h.Close)
	addr := serve(t, &gateway.Router{TrustDomain: td, GatewayID: "gw_01", Routes: fakeRoutes{}, Unrouted: h.ServeUnrouted,
		UnroutedTLS: h.UnroutedTLSConfig()})
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "foo.example.com", RootCAs: pool, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "POST / HTTP/1.1\r\nHost: foo.example.com\r\nContent-Length: 100\r\n\r\nabc"); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("after %v: %v", time.Since(start), err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("after %v: %v, want the gateway to close", time.Since(start), err)
	}
}

// TestPages_Maintenance (D88): a route in maintenance answers every request its access rules admit
// with 503, Retry-After and the maintenance page with its message as text, keeps HSTS and its port
// 80 redirect, and sends nothing to the upstream; a denied client still gets 403 and one without
// credentials 401. Leaving maintenance serves the route again.
func TestPages_Maintenance(t *testing.T) {
	var hits atomic.Int32
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", HSTS: 600, Maintenance: true,
		MaintenanceMessage: "Back at 18:00.\n<b>Thanks</b> for waiting & sorry", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	e := newHTTPEnv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "up")
	}), route)
	for _, h2 := range []bool{false, true} {
		r := get(t, e.client(h2), "https://app.example.com/any/path", browser)
		if r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") != "300" || !isPage(r, "Down for maintenance") ||
			r.header.Get("Strict-Transport-Security") != "max-age=600" ||
			!strings.Contains(r.body, "<p class=\"note\">Back at 18:00.\n&lt;b&gt;Thanks&lt;/b&gt; for waiting &amp; sorry</p>") {
			t.Errorf("h2 %v: %d %v %s", h2, r.status, r.header, r.body)
		}
	}
	if r := get(t, e.client(false), "https://app.example.com/", nil); r.status != http.StatusServiceUnavailable ||
		r.body != "Service Unavailable: down for maintenance\n\nBack at 18:00.\n<b>Thanks</b> for waiting & sorry\n" ||
		!strings.HasPrefix(r.header.Get("Content-Type"), "text/plain") {
		t.Errorf("not a browser: %d %q", r.status, r.body)
	}
	// An upgrade gets the page too, not the upstream.
	if r := get(t, e.client(false), "https://app.example.com/", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}); r.status != http.StatusServiceUnavailable {
		t.Errorf("an upgrade: %d", r.status)
	}
	addr := e.serve80(t)
	if r, err := plain(t, addr, http.MethodGet, "app.example.com", "/x"); err != nil || r.status != http.StatusMovedPermanently {
		t.Errorf("port 80 redirect: %v %v", r, err)
	}

	// The access rules come first.
	denied := route
	denied.Access = access(t, deny("127.0.0.0/8"))
	e.routes.Apply([]gateway.HTTPRoute{denied})
	if r := get(t, e.client(false), "https://app.example.com/", browser); r.status != http.StatusForbidden {
		t.Errorf("a denied client: %d", r.status)
	}
	locked := route
	locked.BasicAuth = []gateway.BasicAuthRule{rule(t, "ap_1", "v1", "alice", "pw")}
	e.routes.Apply([]gateway.HTTPRoute{locked})
	if r := get(t, e.client(false), "https://app.example.com/", browser); r.status != http.StatusUnauthorized {
		t.Errorf("no credentials: %d", r.status)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	req.SetBasicAuth("alice", "pw")
	req.Header.Set("Accept", "text/html")
	resp, err := e.client(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("with credentials: %d", resp.StatusCode)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the upstream got %d requests in maintenance", n)
	}

	// Leaving maintenance.
	route.Maintenance = false
	e.routes.Apply([]gateway.HTTPRoute{route})
	if r := get(t, e.client(false), "https://app.example.com/", browser); r.status != http.StatusOK || r.body != "up" || hits.Load() != 1 {
		t.Errorf("after maintenance: %d %q", r.status, r.body)
	}
}

// TestPages_MaintenanceWithheldBody: a request to a route in maintenance that announces a body it
// does not send gets its 503 at once, and the connection closes rather than wait for the body.
func TestPages_MaintenanceWithheldBody(t *testing.T) {
	e := newHTTPEnv(t, http.NotFoundHandler(), gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Maintenance: true,
		Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}})
	c, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: "app.example.com", RootCAs: e.pool, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "POST / HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 100\r\n\r\nabc"); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !resp.Close {
		t.Errorf("%d, close %v; want 503 and a close", resp.StatusCode, resp.Close)
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Errorf("%v, want the gateway to close", err)
	}
}

// TestPages_CustomThroughRoutes: a group's own pages replace the built-in ones wherever the gateway
// makes a page: a path no route serves, HEAD, a name no route serves on port 443 and on port 80, the
// 502 of a refused upstream and a route in maintenance, each with the custom-page CSP and escaped
// values; clients that do not ask for HTML still get text.
func TestPages_CustomThroughRoutes(t *testing.T) {
	items := map[string]string{
		"gwp_1": "<p>nf {{status}} {{hostname}}</p>",
		"gwp_2": "<p>down {{status}}</p>",
		"gwp_3": "<p>maint {{status}} {{message}}</p>",
	}
	pages := gateway.NewPages(gateway.PagesOptions{Fetch: func(_ context.Context, id string, _ []byte) ([]byte, error) { return []byte(items[id]), nil }})
	var refs []gateway.PageRef
	for id, kind := range map[string]string{"gwp_1": "not-found", "gwp_2": "unavailable", "gwp_3": "maintenance"} {
		sum := sha256.Sum256([]byte(items[id]))
		refs = append(refs, gateway.PageRef{ID: id, Kind: kind, ContentSHA256: sum[:]})
	}
	if st := pages.Apply(context.Background(), refs); len(st) != 0 {
		t.Fatal(st)
	}
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	refused := closed.Addr().String()
	_ = closed.Close()
	p := newPlaneWith(t, refused, "none", "rt_web", "rt_maint")
	certs, pool := routeCert(t, "app.example.com", "*.example.com")
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Sessions: p.sessions, Certificates: certs, Pages: pages})
	t.Cleanup(h.Close)
	h.Apply([]gateway.HTTPRoute{
		{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com", PathPrefix: "/app"}}},
		{ID: "rt_maint", Upstream: "http", Maintenance: true, MaintenanceMessage: `<b>"back"</b> {{status}}`,
			Hosts: []gateway.HTTPHost{{Hostname: "maint.example.com"}}},
	})
	e := &httpEnv{routes: h, addr: httpFront(t, h), pool: pool}
	custom := func(name string, r reply, status int, body string) {
		t.Helper()
		if r.status != status || r.body != body || !strings.HasPrefix(r.header.Get("Content-Security-Policy"), "default-src 'none'; style-src 'unsafe-inline'; img-src data:") ||
			r.header.Get("Cache-Control") != "no-store" || r.header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: %d %q %v", name, r.status, r.body, r.header)
		}
	}
	c := e.client(false)
	custom("a path no route serves", get(t, c, "https://app.example.com/other", browser), http.StatusNotFound, "<p>nf 404 app.example.com</p>")
	if r := get(t, c, "https://app.example.com/other", nil); r.status != http.StatusNotFound || strings.Contains(r.body, "<p>") {
		t.Errorf("not a browser: %d %q", r.status, r.body)
	}
	custom("a refused upstream", get(t, e.client(true), "https://app.example.com/app/x", browser), http.StatusBadGateway, "<p>down 502</p>")
	custom("maintenance", get(t, c, "https://maint.example.com/", browser), http.StatusServiceUnavailable,
		"<p>maint 503 &lt;b&gt;&#34;back&#34;&lt;/b&gt; {{status}}</p>")
	req, _ := http.NewRequest(http.MethodHead, "https://app.example.com/other", nil)
	req.Header = browser.Clone()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || !strings.HasPrefix(resp.Header.Get("Content-Security-Policy"), "default-src 'none'; style-src 'unsafe-inline'") {
		t.Errorf("HEAD: %d %v", resp.StatusCode, resp.Header)
	}

	// Port 80: a name no route serves.
	addr80 := e.serve80(t)
	c80 := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr80)
	}}}
	custom("port 80", get(t, c80, "http://nothing.example.com/", browser), http.StatusNotFound, "<p>nf 404 nothing.example.com</p>")

	// Port 443: a name no route serves, on a connection of its own.
	addr := serve(t, &gateway.Router{TrustDomain: td, GatewayID: "gw_01", Routes: servesOf{h}, HTTP: h.Serve, HTTPTLS: h.TLSConfig(),
		Unrouted: h.ServeUnrouted, UnroutedTLS: h.UnroutedTLSConfig()})
	tc, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "foo.example.com", RootCAs: pool, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tc.Close() })
	custom("an unrouted name", roundTrip(t, tc, "foo.example.com"), http.StatusNotFound, "<p>nf 404 foo.example.com</p>")
}
