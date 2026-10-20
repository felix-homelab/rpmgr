// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// uncleanPaths are request paths with an empty, "." or ".." segment, written as a client sends
// them; each would reach /admin/x at a backend that merges slashes or resolves dot segments.
var uncleanPaths = []string{"//admin/x", "/./admin/x", "/x/../admin/x", "/%2e%2e/admin/x", "/%2E%2E/admin/x",
	"/x/%2e%2e/admin/x", "/x%2f..%2fadmin/x", "/admin/x/.", "/admin/x/..", "/admin//x", "/admin/x//",
	// dot segments with ";" parameters, which some servers resolve as dot segments
	"/..;/admin/x", "/x/..;/admin/x", "/.;/admin/x", "/x/..;jsessionid=1/admin/x",
	// segments that are empty once their ";" parameters are dropped
	"/;/admin/x", "/x/;/admin", "/;x/admin", "/x/;y;z/admin",
	// "\", which some servers read as "/", and control characters
	"/x%5c..%5cadmin/x", "/admin%5cx", "/admin%00x", "/admin%0ax", "/admin%7fx", "/admin%09x"}

// pathEnv is a host with an open route on / and a route on /admin that admits no client of the
// tests, and an upstream that records the request targets it gets.
type pathEnv struct {
	*httpEnv
	mu   sync.Mutex
	seen []string
}

func newPathEnv(t *testing.T, port80 string) (*pathEnv, gateway.HTTPRoute, gateway.HTTPRoute) {
	t.Helper()
	pe := &pathEnv{}
	up := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pe.mu.Lock()
		pe.seen = append(pe.seen, r.RequestURI)
		pe.mu.Unlock()
		_, _ = w.Write([]byte("upstream"))
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = up.Serve(ln) }()
	t.Cleanup(func() { _ = up.Close() })
	open := gateway.HTTPRoute{ID: "rt_pub", Upstream: "http", Port80: port80,
		Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}}}
	admin := gateway.HTTPRoute{ID: "rt_admin", Upstream: "http", Port80: port80,
		Hosts:  []gateway.HTTPHost{{Hostname: "app.example.com", PathPrefix: "/admin"}},
		Access: access(t, allow("10.0.0.0/8"))}
	p := newPlaneWith(t, ln.Addr().String(), "none", open.ID, admin.ID)
	pe.httpEnv = newHTTPEnvOn(t, p.sessions, open, admin)
	return pe, open, admin
}

func (pe *pathEnv) upstreamSaw() []string {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	return slices.Clone(pe.seen)
}

// TestGateway_UncleanPathRefused: a path with an empty, "." or ".." segment is refused with 400
// over HTTP/1.1, HTTP/2 and on port 80, before any route is chosen, so it never reaches an upstream
// through a broader route than the one its clean form belongs to (docs/03-connections.md, "HTTP
// routes"); paths that are clean, encoded letters and slashes included, are routed as before.
func TestGateway_UncleanPathRefused(t *testing.T) {
	e, _, _ := newPathEnv(t, "serve")
	addr80 := e.serve80(t)
	for _, h2 := range []bool{false, true} {
		for _, p := range uncleanPaths {
			if r := get(t, e.client(h2), "https://app.example.com"+p, nil); r.status != http.StatusBadRequest {
				t.Errorf("HTTP/2 %v, %s: %d %q, want 400", h2, p, r.status, r.body)
			}
		}
	}
	for _, p := range uncleanPaths {
		if r, err := plain(t, addr80, http.MethodGet, "app.example.com", p); err != nil || r.status != http.StatusBadRequest {
			t.Errorf("port 80, %s: %v %v, want 400", p, r, err)
		}
	}
	if seen := e.upstreamSaw(); len(seen) != 0 {
		t.Fatalf("unclean paths reached the upstream: %q", seen)
	}

	// Clean paths are routed as before: /admin and an encoded form of it by the admin route, whose
	// rules deny the client; /adminx, /pub/ and / by the open route.
	for p, want := range map[string]int{"/admin/x": http.StatusForbidden, "/admin%2fx": http.StatusForbidden,
		"/%61dmin/x": http.StatusForbidden, "/admin": http.StatusForbidden, "/adminx": http.StatusOK, "/pub/": http.StatusOK,
		"/": http.StatusOK, "/a.b/..c/...": http.StatusOK,
		// ";" parameters: routed by the longest prefix their path, with or without them, matches
		"/admin;/x": http.StatusForbidden, "/admin;jsessionid=1": http.StatusForbidden, "/admin;p/x": http.StatusForbidden,
		"/adminx;p": http.StatusOK, "/x;y/..z": http.StatusOK,
		// a last segment of parameters alone reads as a trailing "/"
		"/admin/;x": http.StatusForbidden, "/pub/;x": http.StatusOK, "/;x": http.StatusOK} {
		if r := get(t, e.client(false), "https://app.example.com"+p, nil); r.status != want {
			t.Errorf("%s: %d, want %d", p, r.status, want)
		}
	}
	if seen := e.upstreamSaw(); !slices.Equal(slices.Sorted(slices.Values(seen)),
		[]string{"/", "/;x", "/a.b/..c/...", "/adminx", "/adminx;p", "/pub/", "/pub/;x", "/x;y/..z"}) {
		t.Errorf("the upstream saw %q", seen)
	}
}

// TestHTTPRoutes_UncleanPathBeforeEverything: the refusal comes before a route's maintenance page
// and port-80 mode, while ACME challenges and domain tokens, whose paths are clean, are answered.
func TestHTTPRoutes_UncleanPathBeforeEverything(t *testing.T) {
	e, open, admin := newPathEnv(t, "off")
	admin.Maintenance = true
	e.routes.Apply([]gateway.HTTPRoute{open, admin})
	addr80 := e.serve80(t)
	if r := get(t, e.client(false), "https://app.example.com/./admin/x", nil); r.status != http.StatusBadRequest {
		t.Errorf("a route in maintenance: %d, want 400", r.status)
	}
	if r := get(t, e.client(false), "https://app.example.com/admin/x", nil); r.status != http.StatusForbidden {
		t.Errorf("a route in maintenance, clean path: %d, want 403 (its rules come first)", r.status)
	}
	if r, err := plain(t, addr80, http.MethodGet, "app.example.com", "//admin"); err != nil || r.status != http.StatusBadRequest {
		t.Errorf("port 80 off, unclean path: %v %v, want 400", r, err)
	}
	e.routes.SetDomainTokens(map[string]gateway.DomainToken{"dom_1": {FQDN: "app.example.com", Value: "token"}})
	if r, err := plain(t, addr80, http.MethodGet, "app.example.com", "/.well-known/rpmgr-challenge/dom_1"); err != nil ||
		r.status != http.StatusOK || r.body != "token" {
		t.Errorf("a domain token: %v %v", r, err)
	}
	if r, err := plain(t, addr80, http.MethodGet, "app.example.com", "/.well-known/rpmgr-challenge/../dom_1"); err != nil ||
		r.status != http.StatusBadRequest {
		t.Errorf("a domain token behind a dot segment: %v %v, want 400", r, err)
	}
	if seen := e.upstreamSaw(); len(seen) != 0 {
		t.Errorf("the upstream saw %q", seen)
	}
}

// TestHTTPRoutes_ConnectAndOptionsStar: CONNECT asks for a tunnel, not a path, and is refused with
// 501 on 443 and port 80; OPTIONS * is answered by the gateway itself; absolute-form targets are
// checked like others. None reaches a route.
func TestHTTPRoutes_ConnectAndOptionsStar(t *testing.T) {
	e, _, _ := newPathEnv(t, "serve")
	addr80 := e.serve80(t)
	raw := func(c net.Conn, req string) int {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%q: %v", strings.SplitN(req, "\r\n", 2)[0], err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	dialTLS := func() net.Conn {
		c, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: "app.example.com", RootCAs: e.pool, MinVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	dial80 := func() net.Conn {
		c, err := net.Dial("tcp", addr80)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	for name, c := range map[string]func() net.Conn{"443": dialTLS, "80": dial80} {
		for _, req := range []string{"CONNECT app.example.com:443 HTTP/1.1\r\nHost: app.example.com:443\r\n\r\n",
			"CONNECT /admin/x HTTP/1.1\r\nHost: app.example.com\r\n\r\n"} {
			if code := raw(c(), req); code != http.StatusNotImplemented {
				t.Errorf("port %s, %q: %d, want 501", name, strings.SplitN(req, "\r\n", 2)[0], code)
			}
		}
		if code := raw(c(), "OPTIONS * HTTP/1.1\r\nHost: app.example.com\r\n\r\n"); code != http.StatusOK {
			t.Errorf("port %s, OPTIONS *: %d, want 200 from the gateway", name, code)
		}
		// Absolute-form request targets: an empty path and a dot segment are refused, and so is a
		// literal "\" in the request line.
		for _, line := range []string{"GET http://app.example.com HTTP/1.1", "GET http://app.example.com/../admin/x HTTP/1.1",
			"GET https://app.example.com/x/../admin/x HTTP/1.1", "GET /x\\..\\admin/x HTTP/1.1"} {
			if code := raw(c(), line+"\r\nHost: app.example.com\r\n\r\n"); code != http.StatusBadRequest {
				t.Errorf("port %s, %q: %d, want 400", name, line, code)
			}
		}
	}
	if seen := e.upstreamSaw(); len(seen) != 0 {
		t.Errorf("the upstream saw %q", seen)
	}
}
