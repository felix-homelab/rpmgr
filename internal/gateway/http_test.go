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
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/headermatch"
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

// TestHTTPRoutes_HeaderMatches (D135): among the routes of a hostname and prefix, one whose header
// matches all hold wins over one with fewer; the route with the smaller ID wins a tie; a request
// no route of its prefix takes goes to a shorter prefix, and else nowhere.
func TestHTTPRoutes_HeaderMatches(t *testing.T) {
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{})
	t.Cleanup(h.Close)
	host := func(prefix string) []gateway.HTTPHost {
		return []gateway.HTTPHost{{Hostname: "app.example.com", PathPrefix: prefix}}
	}
	h.Apply([]gateway.HTTPRoute{
		{ID: "rt_main", Hosts: host("")},
		{ID: "rt_api", Hosts: host("/api")},
		{ID: "rt_b", Hosts: host("/api"), HeaderMatches: []headermatch.Match{{Name: "X-Env", Value: "beta"}}},
		{ID: "rt_a", Hosts: host("/api"), HeaderMatches: []headermatch.Match{{Name: "X-Tenant", Present: true}}},
		{ID: "rt_both", Hosts: host("/api"), HeaderMatches: []headermatch.Match{{Name: "X-Env", Value: "beta"}, {Name: "X-Tenant", Present: true}}},
		{ID: "rt_only", Hosts: host("/admin"), HeaderMatches: []headermatch.Match{{Name: "X-Admin", Value: "1"}}},
	})
	for _, tc := range []struct {
		path   string
		header http.Header
		want   string
	}{
		{"/api/x", nil, "rt_api"},
		{"/api/x", http.Header{"X-Env": {"beta"}}, "rt_b"},
		{"/api/x", http.Header{"X-Env": {"Beta"}}, "rt_api"},                      // values compare exactly
		{"/api/x", http.Header{"X-Env": {"prod", "beta"}}, "rt_b"},                // any of several values
		{"/api/x", http.Header{"X-Tenant": {""}}, "rt_a"},                         // presence, an empty value too
		{"/api/x", http.Header{"X-Env": {"beta"}, "X-Tenant": {"t1"}}, "rt_both"}, // more matches win
		{"/admin", http.Header{"X-Admin": {"1"}}, "rt_only"},
		{"/admin", nil, "rt_main"}, // no route of /admin takes it: the next shorter prefix
		{"/", http.Header{"X-Env": {"beta"}}, "rt_main"},
	} {
		if got := gateway.RouteFor(h, "app.example.com", tc.path, tc.header); got != tc.want {
			t.Errorf("%s %v: %q, want %q", tc.path, tc.header, got, tc.want)
		}
	}
	// A tie of equally many matches that both hold: the route created first, with the smaller ID.
	h.Apply([]gateway.HTTPRoute{
		{ID: "rte_2", Hosts: host(""), HeaderMatches: []headermatch.Match{{Name: "X-Tenant", Present: true}}},
		{ID: "rte_1", Hosts: host(""), HeaderMatches: []headermatch.Match{{Name: "X-Env", Value: "beta"}}},
	})
	if got := gateway.RouteFor(h, "app.example.com", "/", http.Header{"X-Env": {"beta"}, "X-Tenant": {"t"}}); got != "rte_1" {
		t.Errorf("a tie: %q", got)
	}
	if got := gateway.RouteFor(h, "app.example.com", "/", nil); got != "" {
		t.Errorf("no match holds: %q", got)
	}
}

// TestGateway_ReservedPathNeverUpstream (security regression, docs/12): a request under /.rpmgr/
// on an http route hostname, in any case, with ";" parameters or percent-encoded, never reaches
// the upstream and gets the gateway's 404, on 443 and on port 80; the identity headers a client
// sends never reach the upstream on any route.
func TestGateway_ReservedPathNeverUpstream(t *testing.T) {
	var reached atomic.Int32
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		//nolint:gosec // G705: the test upstream echoes the request as plain text
		_, _ = fmt.Fprintf(w, "%s|%s|%s|%s", r.URL.Path, r.Header.Get("Rpmgr-User-Email"), r.Header.Get("Rpmgr-User-Subject"),
			r.Header.Get("Rpmgr-User-Groups"))
	})
	e := newHTTPEnv(t, upstream, gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Port80: "serve",
		Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}})
	addr80 := e.serve80(t)
	for _, path := range []string{"/.rpmgr/oidc", "/.rpmgr", "/.rpmgr/", "/.RPMGR/oidc", "/%2Erpmgr/oidc", "/.rpmgr;x/oidc",
		"/.rpmgr/tunnel", "/%2e%72pmgr/x"} {
		for _, h2 := range []bool{false, true} {
			if r := get(t, e.client(h2), "https://app.example.com"+path, nil); r.status != http.StatusNotFound {
				t.Errorf("%s (h2 %v): %d %q", path, h2, r.status, r.body)
			}
		}
		if r, err := plain(t, addr80, http.MethodGet, "app.example.com", path); err != nil || r.status != http.StatusNotFound {
			t.Errorf("%s on port 80: %v %v", path, r, err)
		}
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("%d requests under /.rpmgr/ reached the upstream", n)
	}
	// Neighbours of the reserved path are ordinary paths.
	for _, path := range []string{"/.rpmgrx", "/x/.rpmgr/y", "/rpmgr/"} {
		if r := get(t, e.client(false), "https://app.example.com"+path, nil); r.status != http.StatusOK || !strings.HasPrefix(r.body, path) {
			t.Errorf("%s: %d %q", path, r.status, r.body)
		}
	}
	spoofed := http.Header{"Rpmgr-User-Email": {"admin@example.com"}, "Rpmgr-User-Subject": {"admin"}, "rpmgr-user-groups": {"admins"}}
	for _, h2 := range []bool{false, true} {
		if r := get(t, e.client(h2), "https://app.example.com/x", spoofed); r.body != "/x|||" {
			t.Errorf("identity headers from the client reached the upstream (h2 %v): %q", h2, r.body)
		}
	}
}

// TestHTTPRoutes_RouteTimeouts (D94): a route's own upstream response-header timeout turns a slow
// upstream into 504 where the gateway's would wait, 0 keeps the gateway's, and a change applies
// to the next request; a route's own idle timeout closes an unused upstream connection sooner.
func TestHTTPRoutes_RouteTimeouts(t *testing.T) {
	gateway.SetHTTPTimers(t, time.Second, 5*time.Second)
	var conns atomic.Int32
	up := &http.Server{ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/slow" {
				time.Sleep(time.Second)
			}
			_, _ = io.WriteString(w, "ok")
		}),
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateNew {
				conns.Add(1)
			}
		}}
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = up.Serve(upLn) }()
	t.Cleanup(func() { _ = up.Close() })
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
		UpstreamHeaderTimeout: 300 * time.Millisecond}
	p := newPlaneWith(t, upLn.Addr().String(), "none", route.ID)
	e := newHTTPEnvOn(t, p.sessions, route)
	c := e.client(false)
	if r := get(t, c, "https://app.example.com/slow", nil); r.status != http.StatusGatewayTimeout {
		t.Errorf("the route's own timeout: %d %q", r.status, r.body)
	}
	route.UpstreamHeaderTimeout = 0
	e.routes.Apply([]gateway.HTTPRoute{route})
	if r := get(t, c, "https://app.example.com/slow", nil); r.status != http.StatusOK {
		t.Errorf("the gateway's timeout: %d %q", r.status, r.body)
	}
	// Idle: with the gateway's 120 s the pooled connection serves the next request; with the
	// route's own 1 s it is closed by then and a new one is opened.
	gets := func() int32 {
		before := conns.Load()
		for range 2 {
			if r := get(t, c, "https://app.example.com/", nil); r.status != http.StatusOK {
				t.Fatalf("%d %q", r.status, r.body)
			}
			time.Sleep(1500 * time.Millisecond)
		}
		return conns.Load() - before
	}
	_ = get(t, c, "https://app.example.com/", nil) // a pooled connection to start from
	if n := gets(); n != 0 {
		t.Errorf("the gateway's idle timeout opened %d new upstream connections, want 0", n)
	}
	route.UpstreamIdleTimeout = time.Second
	e.routes.Apply([]gateway.HTTPRoute{route})
	if n := gets(); n != 2 {
		t.Errorf("the route's idle timeout opened %d new upstream connections, want 2", n)
	}
}

// TestHTTPRoutes_ReplacedTransportClosesIdle: a transport that a change of the route's timeouts
// replaced while a request ran on it leaves no upstream connection open once a later snapshot
// finds it idle. Over HTTP/1.1 Go's transport closes a connection given back after
// CloseIdleConnections by itself; an h2c connection that was busy then stays open until the
// gateway closes the transport's idle connections when it drops it.
func TestHTTPRoutes_ReplacedTransportClosesIdle(t *testing.T) {
	for _, upstream := range []string{"http", "h2c"} {
		t.Run(upstream, func(t *testing.T) {
			var opened, closed atomic.Int32
			running, release := make(chan struct{}), make(chan struct{})
			up := &http.Server{ReadHeaderTimeout: 5 * time.Second,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/block" {
						close(running)
						<-release
					}
					_, _ = io.WriteString(w, "ok")
				}),
				ConnState: func(_ net.Conn, s http.ConnState) {
					switch s {
					case http.StateNew:
						opened.Add(1)
					case http.StateClosed:
						closed.Add(1)
					}
				}}
			if upstream == "h2c" {
				p := new(http.Protocols)
				p.SetUnencryptedHTTP2(true)
				up.Protocols = p
			}
			upLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = up.Serve(upLn) }()
			t.Cleanup(func() { _ = up.Close() })
			route := gateway.HTTPRoute{ID: "rt_web", Upstream: upstream, Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
			p := newPlaneWith(t, upLn.Addr().String(), "none", route.ID)
			e := newHTTPEnvOn(t, p.sessions, route)
			done := make(chan reply, 1)
			go func() { done <- get(t, e.client(false), "https://app.example.com/block", nil) }()
			<-running
			route.UpstreamIdleTimeout = time.Hour // a new transport; the request goes on on the old one
			e.routes.Apply([]gateway.HTTPRoute{route})
			close(release)
			if r := <-done; r.status != http.StatusOK {
				t.Fatalf("the request on the replaced transport: %d %q", r.status, r.body)
			}
			// The request leaves the old transport only once the gateway's handler returns, which may
			// be just after the client read the reply: a snapshot in between finds the transport
			// busy and keeps it, so later snapshots, as the gateway gets them, close it.
			deadline := time.Now().Add(5 * time.Second)
			for {
				e.routes.Apply([]gateway.HTTPRoute{route})
				if closed.Load() >= opened.Load() || time.Now().After(deadline) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if n := opened.Load() - closed.Load(); n != 0 {
				t.Fatalf("%d upstream connections of the replaced transport stay open", n)
			}
		})
	}
}

// TestGateway_IdentityHeadersAnySpelling (D135): every header and trailer a client sends whose
// name starts with Rpmgr-User-, in any case and with "_" for "-", which CGI-style servers read
// alike, is removed before the request goes upstream; other headers pass.
func TestGateway_IdentityHeadersAnySpelling(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // trailers arrive after the body
		// Trailers are compared by name: what reaches the upstream is the names the client declared.
		var got []string
		for i, h := range []http.Header{r.Header, r.Trailer} {
			for name, v := range h {
				if n := strings.ToLower(strings.ReplaceAll(name, "_", "-")); strings.HasPrefix(n, "rpmgr-user-") || n == "x-keep" || n == "x-late" {
					got = append(got, map[int]string{0: name + "=" + strings.Join(v, ","), 1: "trailer " + name}[i])
				}
			}
		}
		slices.Sort(got)
		_, _ = io.WriteString(w, strings.Join(got, " "))
	})
	e := newHTTPEnv(t, upstream, gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}})
	for _, h2 := range []bool{false, true} {
		req, _ := http.NewRequest(http.MethodPost, "https://app.example.com/x", io.NopCloser(strings.NewReader("body")))
		req.ContentLength = -1 // chunked on HTTP/1.1, so the trailers go
		req.Header["rpmgr_user_email"] = []string{"admin@example.com"}
		req.Header["Rpmgr-User-Role"] = []string{"admin"}
		req.Header["RPMGR-USER_ORG"] = []string{"org_1"}
		req.Header.Set("X-Keep", "1")
		req.Trailer = http.Header{"Rpmgr-User-Email": {"late@example.com"}, "rpmgr_user_x": {"t"}, "X-Late": {"t"}}
		resp, err := e.client(h2).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(b) != "X-Keep=1 trailer X-Late" {
			t.Errorf("h2 %v: the upstream got %q, want only X-Keep and the trailer X-Late", h2, b)
		}
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
// settings, or the host's trust store for a private CA is 502. A target marked unverified passes
// whatever its certificate, and still gets its server name; a pinned-key target passes with its
// key whatever its chain and name, and fails with another. A target's settings apply only to a
// stream its own connector answered: when another connector's target is named, or unverified or
// pinned-key settings name no connector, the stream is closed, whatever the mode (ADR-0017). ALPN
// brings HTTP/2.
func TestHTTPRoutes_HTTPSUpstream(t *testing.T) {
	ca := newUpstreamCA(t)
	var sni atomic.Value
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni.Store(hello.ServerName)
			return &ca.leaf, nil
		}})
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
		{"verified, of its connector", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "upstream.internal", CAPEM: ca.pem,
			Connector: p.connector}}, http.StatusOK},
		{"verified, of another connector", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "upstream.internal", CAPEM: ca.pem,
			Connector: "con_other"}}, http.StatusBadGateway},
		{"unverified on another target only", map[string]gateway.UpstreamTLS{"tg_other": {ServerName: "other.internal",
			Verify: gateway.VerifyNothing, Connector: p.connector}}, http.StatusBadGateway},
		{"unverified, of another connector", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "other.internal",
			Verify: gateway.VerifyNothing, Connector: "con_other"}}, http.StatusBadGateway},
		{"unverified, of no connector", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "other.internal",
			Verify: gateway.VerifyNothing}}, http.StatusBadGateway},
		{"its pinned key only", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "other.internal", SPKISHA256: pin[:],
			Verify: gateway.VerifyPinnedKey, Connector: p.connector}}, http.StatusOK},
		{"its pinned key, of another connector", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "other.internal",
			SPKISHA256: pin[:], Verify: gateway.VerifyPinnedKey, Connector: "con_other"}}, http.StatusBadGateway},
		{"its pinned key, of no connector", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "other.internal",
			SPKISHA256: pin[:], Verify: gateway.VerifyPinnedKey}}, http.StatusBadGateway},
		{"another pinned key", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "upstream.internal", SPKISHA256: make([]byte, 32),
			Verify: gateway.VerifyPinnedKey, Connector: p.connector}}, http.StatusBadGateway},
		{"a pinned key without a pin", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "upstream.internal",
			Verify: gateway.VerifyPinnedKey, Connector: p.connector}}, http.StatusBadGateway},
		{"unverified", map[string]gateway.UpstreamTLS{"tg_rt_tls": {ServerName: "other.internal", Verify: gateway.VerifyNothing,
			Connector: p.connector}}, http.StatusOK}, // last: the server name is checked below
	} {
		route.TLS = tc.tls
		e.routes.Apply([]gateway.HTTPRoute{route})
		r := get(t, e.client(false), "https://app.example.com/", nil)
		if r.status != tc.want || tc.want == http.StatusOK && r.body != "HTTP/2.0" {
			t.Errorf("%s: %d %q, want %d", tc.name, r.status, r.body, tc.want)
		}
	}
	if got := sni.Load(); got != "other.internal" {
		t.Errorf("the unverified target got the server name %v", got)
	}
}

// TestHTTPRoutes_StricterUpstreamTLS (#517): when a target's TLS settings change for ones that
// would not accept a connection the old ones checked, a response still streaming over it ends at
// once, also when the connection belongs to a transport an earlier change replaced; a change to
// unverified settings of the same connector, and a change of another target's settings, let it
// finish. The upstream connection speaks HTTP/1.1 or HTTP/2, the client either.
func TestHTTPRoutes_StricterUpstreamTLS(t *testing.T) {
	ca := newUpstreamCA(t)
	for _, alpn := range [][]string{{"http/1.1"}, {"h2", "http/1.1"}} {
		release := make(chan struct{})
		var proto atomic.Value
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: alpn, Certificates: []tls.Certificate{ca.leaf}})
		if err != nil {
			t.Fatal(err)
		}
		up := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proto.Store(r.Proto)
			_, _ = io.WriteString(w, "start\n")
			w.(http.Flusher).Flush()
			select {
			case <-release:
				_, _ = io.WriteString(w, "end\n")
			case <-r.Context().Done():
			}
		})}
		if len(alpn) == 1 {
			up.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){} // HTTP/1.1 only
		}
		go func() { _ = up.Serve(ln) }()
		t.Cleanup(func() { _ = up.Close() })
		p := newPlaneWith(t, ln.Addr().String(), "none", "rt_tls")
		unverified := gateway.UpstreamTLS{ServerName: "upstream.internal", Verify: gateway.VerifyNothing, Connector: p.connector}
		verified := gateway.UpstreamTLS{ServerName: "upstream.internal", CAPEM: ca.pem, Connector: p.connector}
		renamed := gateway.UpstreamTLS{ServerName: "other.internal", CAPEM: ca.pem, Connector: p.connector}
		elsewhere := gateway.UpstreamTLS{ServerName: "upstream.internal", Verify: gateway.VerifyNothing, Connector: "con_other"}
		route := func(a gateway.UpstreamTLS, b *gateway.UpstreamTLS) gateway.HTTPRoute {
			r := gateway.HTTPRoute{ID: "rt_tls", Upstream: "https", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
				TLS: map[string]gateway.UpstreamTLS{"tg_rt_tls": a}}
			if b != nil {
				r.TLS["tg_other"] = *b
			}
			return r
		}
		for _, tc := range []struct {
			name    string
			steps   []gateway.HTTPRoute // the first opens the response, the others follow while it streams
			wantEnd bool                // it finishes rather than breaking off
		}{
			{"unverified to verified", []gateway.HTTPRoute{route(unverified, nil), route(verified, nil)}, false},
			{"verified to another server name", []gateway.HTTPRoute{route(verified, nil), route(renamed, nil)}, false},
			{"verified to unverified", []gateway.HTTPRoute{route(verified, nil), route(unverified, nil)}, true},
			{"to unverified of another connector", []gateway.HTTPRoute{route(verified, nil), route(elsewhere, nil)}, false},
			{"another target's settings", []gateway.HTTPRoute{route(verified, &unverified), route(verified, &verified)}, true},
			{"stricter after another target's change", []gateway.HTTPRoute{route(unverified, &unverified), route(unverified, &verified),
				route(verified, &verified)}, false},
		} {
			t.Run(alpn[0]+"/"+tc.name, func(t *testing.T) {
				e := newHTTPEnvOn(t, p.sessions, tc.steps[0])
				for _, h2 := range []bool{false, true} {
					e.routes.Apply([]gateway.HTTPRoute{tc.steps[0]})
					res, err := e.client(h2).Get("https://app.example.com/stream")
					if err != nil {
						t.Fatal(err)
					}
					body := bufio.NewReader(res.Body)
					if line, err := body.ReadString('\n'); err != nil || line != "start\n" {
						t.Fatalf("h2 %v: first line %q %v", h2, line, err)
					}
					if want := map[bool]string{true: "HTTP/1.1", false: "HTTP/2.0"}[len(alpn) == 1]; proto.Load() != want {
						t.Fatalf("the upstream spoke %v, want %s", proto.Load(), want)
					}
					rest := make(chan string, 1)
					go func() {
						b, _ := io.ReadAll(body)
						rest <- string(b)
					}()
					for i, step := range tc.steps[1:] {
						e.routes.Apply([]gateway.HTTPRoute{step})
						if i < len(tc.steps)-2 {
							select {
							case got := <-rest:
								t.Fatalf("h2 %v: step %d ended the response early: %q", h2, i+1, got)
							case <-time.After(150 * time.Millisecond):
							}
						}
					}
					if tc.wantEnd {
						time.Sleep(200 * time.Millisecond)
						release <- struct{}{}
					}
					select {
					case got := <-rest:
						if (got == "end\n") != tc.wantEnd {
							t.Errorf("h2 %v: the rest %q, want it to finish %v", h2, got, tc.wantEnd)
						}
					case <-time.After(3 * time.Second):
						t.Errorf("h2 %v: the response stayed open", h2)
					}
					_ = res.Body.Close()
				}
			})
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
// name, even with port 80 off; a fallback name without a route goes to the fallback, unknown ACME
// tokens included, and any other name without a route gets the 404 page.
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
		Challenges:    func(host, token string) (string, bool) { return token + ".thumbprint", token == "tok" && host != "" },
		Fallback80:    http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "fallback", http.StatusTeapot) }),
		FallbackNames: []string{"Panel.example.com.", "2001:db8::1"}})
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
	for _, host := range []string{"panel.example.com", "PANEL.example.com:80", "panel.example.com.", "[2001:db8::1]", "[2001:db8::1]:80"} {
		if r, err := plain(t, addr, http.MethodGet, host, "/"); err != nil || r.status != http.StatusTeapot {
			t.Errorf("the fallback's name %s without a route: %v %v", host, r, err)
		}
	}
	if r, err := plain(t, addr, http.MethodGet, "other.example.com", "/"); err != nil || r.status != http.StatusNotFound ||
		r.body != "no route for this host and path\n" {
		t.Errorf("another name without a route: %v %v", r, err)
	}
	if r, err := plainAccept(t, addr, "other.example.com", "text/html"); err != nil || r.status != http.StatusNotFound ||
		!isPage(r, "Site not available") || !strings.Contains(r.body, ">other.example.com</span>") {
		t.Errorf("another name without a route, from a browser: %v %v", r, err)
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
	// all-in-one's controller answers the challenges of its own name, which no route serves; a
	// known token is answered for any name, an unknown one for another name is 404.
	if r, err := plain(t, addr, http.MethodGet, "panel.example.com", "/.well-known/acme-challenge/unknown"); err != nil ||
		r.status != http.StatusTeapot {
		t.Errorf("an unknown ACME token for the fallback's name: %v %v", r, err)
	}
	if r, err := plain(t, addr, http.MethodGet, "other.example.com", "/.well-known/acme-challenge/tok"); err != nil ||
		r.status != http.StatusOK || r.body != "tok.thumbprint" {
		t.Errorf("an ACME challenge for a name without a route: %v %v", r, err)
	}
	if r, err := plain(t, addr, http.MethodGet, "other.example.com", "/.well-known/acme-challenge/unknown"); err != nil ||
		r.status != http.StatusNotFound {
		t.Errorf("an unknown ACME token for another name without a route: %v %v", r, err)
	}
}

// plainAccept sends a GET to port 80 at addr for host with an Accept header.
func plainAccept(t *testing.T, addr, host, accept string) (reply, error) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return reply{}, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nAccept: %s\r\n\r\n", host, accept); err != nil {
		return reply{}, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return reply{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return reply{status: resp.StatusCode, header: resp.Header, body: string(b)}, nil
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

// A connection that has not sent a request yet is fresh, so that the drain of a hand-off waits for
// its request instead of closing it (#1008); a request or a close ends it.
func TestHTTPRoutes_Fresh(t *testing.T) {
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{})
	t.Cleanup(h.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = h.Serve80(ln) }()

	if n := h.Fresh(); n != 0 {
		t.Fatalf("fresh before any connection: %d", n)
	}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	waitFor(t, func() bool { return h.Fresh() == 1 }, "the silent connection to be fresh")

	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: nothing.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return h.Fresh() == 0 }, "the connection to leave the fresh state once it sent a request")

	silent, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return h.Fresh() == 1 }, "a second silent connection to be fresh")
	_ = silent.Close()
	waitFor(t, func() bool { return h.Fresh() == 0 }, "a closed connection not to be fresh")
}
