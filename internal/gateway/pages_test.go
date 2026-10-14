// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
// service-unavailable page for a browser and text for other clients; the upstream's own errors
// pass through unchanged, and so does the 413 of the body limit.
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
	e = newHTTPEnv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "<p>the upstream's own</p>")
	}), route)
	if r := get(t, e.client(false), "https://app.example.com/", browser); r.status != http.StatusServiceUnavailable ||
		r.body != "<p>the upstream's own</p>" || r.header.Get("Content-Security-Policy") != "" {
		t.Errorf("the upstream's 503: %d %q %v", r.status, r.body, r.header)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://app.example.com/", strings.NewReader("too large"))
	req.Header = browser.Clone()
	resp, err := e.client(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("413: %d %v", resp.StatusCode, resp.Header)
	}
}

// TestPages_NoRoute443: a name or path no route serves, on a connection of a routed name, is the
// site-not-available page for a browser, without the route's HSTS, and the text for others.
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

	// A covered name: the wildcard certificate, the page, a misdirected request for the routed
	// name and for another covered name, and the page again, all on one connection.
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
	for _, host := range []string{"app.example.com", "bar.example.com", "app.example.com:443"} {
		if rep := roundTrip(t, c, host); rep.status != http.StatusMisdirectedRequest {
			t.Errorf("%s on foo.example.com's connection: %d", host, rep.status)
		}
	}
	if rep := roundTrip(t, c, "FOO.example.com.:443"); rep.status != http.StatusNotFound {
		t.Errorf("foo.example.com again: %d", rep.status)
	}
	if c, err := dial("foo.example.com", pool, "h2"); err != nil || c.ConnectionState().NegotiatedProtocol != "h2" {
		t.Errorf("HTTP/2: %v", err)
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
		if rep := roundTrip(t, c, "app.example.com"); rep.status != http.StatusMisdirectedRequest {
			t.Errorf("app.example.com on %s's connection: %d", name, rep.status)
		}
	}
}
