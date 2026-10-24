// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// The HTTP server's timing (docs/03-connections.md, "Timeouts, keepalive and backoff"); the
// variables change only in tests.
const (
	httpIdle              = 120 * time.Second // a keep-alive connection without a request
	httpRetryAfter        = 5                 // seconds, in a 503 without a ready connector
	maintenanceRetryAfter = 300               // seconds, in the 503 of a route in maintenance
	limitRetryAfter       = 1                 // seconds, in the 503 of a route over its connection limit
)

var (
	httpReadHeader     = 10 * time.Second // the TLS handshake and the request headers
	httpUpstreamHeader = 60 * time.Second // the upstream's response headers
)

// RouteTable answers the router for both kinds of routes on port 443 that it hands over: the
// TLS-passthrough routes and the http routes.
type RouteTable struct {
	pass *Passthrough
	http *HTTPRoutes
}

// NewRouteTable returns the router's table of pass's and h's routes.
func NewRouteTable(pass *Passthrough, h *HTTPRoutes) RouteTable {
	return RouteTable{pass: pass, http: h}
}

// Passthrough implements Routes.
func (t RouteTable) Passthrough(sni string) (func(net.Conn), bool) { return t.pass.Passthrough(sni) }

// HTTP implements Routes.
func (t RouteTable) HTTP(sni string) bool { return t.http.Serves(sni) }

// HTTPRoute is an http route as the gateway serves it, from its snapshot.
type HTTPRoute struct {
	ID    string
	Hosts []HTTPHost
	// Upstream is "http" (HTTP/1.1), "h2c" or "https".
	Upstream  string
	WebSocket bool
	// TLS verifies an "https" upstream, by route target ID.
	TLS map[string]UpstreamTLS
	// HostHeader is the Host sent upstream; "" keeps the client's.
	HostHeader string
	// RequestHeaders and ResponseHeaders are set on the way; an empty value removes a header.
	RequestHeaders, ResponseHeaders []HTTPHeader
	// MaxBody is the largest request body; 0 sets no limit.
	MaxBody int64
	// TrustedProxies are the clients whose forwarding headers the gateway keeps.
	TrustedProxies []netip.Prefix
	// Port80 is what plain HTTP does: "redirect" (also ""), "serve" or "off".
	Port80 string
	// HSTS is the max-age, in seconds, of Strict-Transport-Security over HTTPS; 0 sends none.
	HSTS int
	// Access is who may send requests: the client, or the client a trusted proxy names.
	Access Access
	// BasicAuth are the basic_auth rules a request the IP rules allow must pass, in order.
	BasicAuth []BasicAuthRule
	// RequireHeader are the require_header rules a request the IP rules allow must pass, before
	// basic auth; their headers never go upstream.
	RequireHeader []RequireHeaderRule
	// Maintenance answers every request the access rules admit with the maintenance page, which
	// shows MaintenanceMessage, and opens no stream.
	Maintenance        bool
	MaintenanceMessage string
	// Limit is the route's limit state; nil limits nothing.
	Limit *RouteLimit
}

// HTTPHeader is a header name, canonical, and its value; "" removes the header.
type HTTPHeader struct{ Name, Value string }

// apply sets or removes each header in hs.
func apply(h http.Header, hs []HTTPHeader) {
	for _, x := range hs {
		if x.Value == "" {
			h.Del(x.Name)
		} else {
			h.Set(x.Name, x.Value)
		}
	}
}

// HTTPHost is a hostname, or "*.name" for every name one label below, with a path prefix; ""
// is every path.
type HTTPHost struct{ Hostname, PathPrefix string }

// HTTPOptions configure HTTPRoutes.
type HTTPOptions struct {
	Sessions     *Sessions
	Certificates *Certificates
	// Default is presented for a name without a valid certificate, so a browser shows a
	// certificate error rather than a reset.
	Default  *tls.Certificate
	Revision func() *agentv1.Revision
	// Challenges answers ACME HTTP-01 challenges on port 80 with the key authorization of a
	// token for a host; nil answers none.
	Challenges func(host, token string) (keyAuthorization string, ok bool)
	// Fallback80 takes port-80 requests for FallbackNames when no route serves them: all-in-one's
	// controller, which answers ACME HTTP-01 for its own name and redirects the rest. Other names
	// no route serves get the gateway's 404 page.
	Fallback80    http.Handler
	FallbackNames []string
	// Pages are the custom pages of the gateway's group; nil serves the built-in pages.
	Pages  *Pages
	Logger *slog.Logger
}

// HTTPRoutes serves the http routes (docs/03-connections.md, "HTTP routes"): it terminates TLS
// with the route certificate for the server name, routes each request by host and the longest
// path prefix, and proxies it over a tunnel stream to a connector of the route.
type HTTPRoutes struct {
	o        HTTPOptions
	basic    *BasicAuth
	server   *http.Server
	server80 *http.Server
	unrouted *http.Server // the connections of names no route serves
	ln       *connListener
	lnNone   *connListener
	table    atomic.Pointer[httpTable]
	tokens   atomic.Pointer[map[string]DomainToken] // by claim ID
	active   atomic.Int64                           // requests being served

	mu         sync.Mutex
	transports map[string]*routeTransport   // by route ID
	replaced   map[string][]*routeTransport // by route ID: transports a change replaced, while requests run on them
	upstream   map[string]*upstreamConns    // by route ID, kept while their connections are open
}

type httpTable struct {
	byHost map[string][]httpEntry // longest prefix first
}

type httpEntry struct {
	prefix string
	route  *routeTransport
}

// routeTransport is one route's proxy, whose transport pools the route's tunnel streams. route
// changes with snapshots while requests read it; a change of the upstream protocol or its TLS
// settings makes a new routeTransport, so no pooled connection outlives its verification.
type routeTransport struct {
	route atomic.Pointer[HTTPRoute]
	tr    *http.Transport
	proxy *httputil.ReverseProxy
	tls   map[string]upstreamTLS // by route target ID

	mu            sync.Mutex
	access        Access              // the route's IP rules in force, which enforce sets
	requireHeader []RequireHeaderRule // and its require_header rules
	active        map[*activeRequest]struct{}
	upstream      *upstreamConns // the route's TLS connections to its targets, of every transport

	best      func() (uint32, bool)     // the route's best priority with a ready session (Sessions.BestPriority)
	entry     func(string, uint32) bool // whether a connector at a priority is still an entry of the route
	closeIdle func()                    // the transport's CloseIdleConnections
	poolMu    sync.Mutex
	pooled    map[net.Conn]*pooledConn // the upstream connections open now that a priority was chosen for
}

// pooledConn is an upstream connection's entry, the route's best ready priority when it was
// dialled, and its requests in progress.
type pooledConn struct {
	connector  string
	priority   uint32
	bestAtDial uint32
	active     int
}

// RoundTrip implements http.RoundTripper: the route's transport, failing back to a better priority
// (D90). An upstream connection is closed as soon as it has no request in progress, checked before
// a request and when one ends, once the route has a ready session at a better priority than when
// it was dialled, or once its entry left the route; a new connection then goes to the better
// priority. While the best priority's target merely fails, its connector still ready, the
// connections of the fallback stay. An HTTP/2 upstream connection with requests always in progress
// stays too.
func (rt *routeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.failBack()
	var got net.Conn
	trace := &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) {
			if got != nil {
				rt.use(got, -1) // the transport retries on another connection
			}
			got = i.Conn
			rt.use(got, 1)
		},
		PutIdleConn: func(err error) {
			if err == nil {
				rt.failBack()
			}
		},
	}
	resp, err := rt.tr.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	if got == nil {
		return resp, err
	}
	var once sync.Once
	done := func() {
		once.Do(func() {
			rt.use(got, -1)
			rt.failBack()
		})
	}
	switch {
	case err != nil:
		done()
	case resp.StatusCode == http.StatusSwitchingProtocols:
		if rwc, ok := resp.Body.(io.ReadWriteCloser); ok {
			resp.Body = &doneRWC{ReadWriteCloser: rwc, done: done}
		}
	default:
		resp.Body = &doneBody{ReadCloser: resp.Body, done: done}
	}
	return resp, err
}

// doneBody calls done when the response body is closed.
type doneBody struct {
	io.ReadCloser
	done func()
}

func (b *doneBody) Close() error {
	defer b.done()
	return b.ReadCloser.Close()
}

// doneRWC is doneBody for the body of an upgraded connection, which the proxy also writes to.
type doneRWC struct {
	io.ReadWriteCloser
	done func()
}

func (b *doneRWC) Close() error {
	defer b.done()
	return b.ReadWriteCloser.Close()
}

// use counts a request in progress on upstream connection c, or its end.
func (rt *routeTransport) use(c net.Conn, delta int) {
	rt.poolMu.Lock()
	defer rt.poolMu.Unlock()
	if pc := rt.pooled[c]; pc != nil {
		pc.active += delta
	}
}

// failBack closes the idle upstream connections if one without a request in progress lost its
// entry, or was dialled while the route's best ready priority was worse than it is now.
func (rt *routeTransport) failBack() {
	rt.poolMu.Lock()
	var idle []pooledConn
	for _, pc := range rt.pooled {
		if pc.active == 0 {
			idle = append(idle, *pc)
		}
	}
	rt.poolMu.Unlock()
	best, known := uint32(0), false
	for _, pc := range idle {
		if !rt.entry(pc.connector, pc.priority) {
			rt.closeIdle()
			return
		}
		if pc.bestAtDial == 0 {
			continue // no priority is better
		}
		if !known {
			b, ok := rt.best()
			if !ok {
				return
			}
			best, known = b, true
		}
		if best < pc.bestAtDial {
			rt.closeIdle()
			return
		}
	}
}

// pool records the priority an upstream connection c, over the stream of sc, was opened at, until
// the stream closes.
func (rt *routeTransport) pool(c net.Conn, sc *streamConn, err error) (net.Conn, error) {
	if err != nil {
		return nil, err
	}
	if p, ranked := streamPriority(sc.Stream); ranked {
		best, ok := rt.best()
		if !ok {
			best = p
		}
		rt.poolMu.Lock()
		rt.pooled[c] = &pooledConn{connector: StreamConnector(sc.Stream), priority: p, bestAtDial: best}
		rt.poolMu.Unlock()
		sc.onClose = func() {
			rt.poolMu.Lock()
			defer rt.poolMu.Unlock()
			delete(rt.pooled, c)
		}
	}
	return c, nil
}

// upstreamConns are the open TLS connections of an http route to its targets, from every
// transport the route had, each with the settings it was checked with (#517). Every change of
// the route's settings ends those the new settings would not accept, and a connection whose
// dial ends after a change is checked against the settings then.
type upstreamConns struct {
	mu    sync.Mutex
	now   map[string]UpstreamTLS // the route's settings, by route target ID
	conns map[*upstreamConn]struct{}
}

// upstreamConn is the tunnel stream under a TLS connection to a target; closing it ends the TLS
// connection and what runs on it, upgraded connections and HTTP/2 streams included.
type upstreamConn struct {
	net.Conn
	target  string
	checked UpstreamTLS
	of      *upstreamConns
	once    sync.Once
}

func (c *upstreamConn) Close() error {
	c.once.Do(func() {
		c.of.mu.Lock()
		defer c.of.mu.Unlock()
		delete(c.of.conns, c)
	})
	return c.Conn.Close()
}

// accepts reports whether the settings now still accept a connection to target that checked
// settings: the same ones, or unverified ones of the same connector. A target the route no longer
// has keeps its connections, which finish as a removed route's do.
func accepts(now map[string]UpstreamTLS, target string, checked UpstreamTLS) bool {
	n, ok := now[target]
	return !ok || reflect.DeepEqual(n, checked) || n.Verify == VerifyNothing && n.Connector == checked.Connector
}

// set makes now the route's settings and ends at once the connections they do not accept.
func (u *upstreamConns) set(now map[string]UpstreamTLS) {
	var doomed []*upstreamConn
	u.mu.Lock()
	u.now = now
	for c := range u.conns {
		if !accepts(now, c.target, c.checked) {
			doomed = append(doomed, c)
		}
	}
	u.mu.Unlock()
	for _, c := range doomed {
		_ = c.Close()
	}
}

// track records c, a stream to target that is to be checked with checked, until it closes; a
// change of the settings since the dial began refuses it.
func (u *upstreamConns) track(target string, checked UpstreamTLS, c net.Conn) (net.Conn, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !accepts(u.now, target, checked) {
		return nil, fmt.Errorf("the TLS settings of target %s changed during the dial", target)
	}
	uc := &upstreamConn{Conn: c, target: target, checked: checked, of: u}
	u.conns[uc] = struct{}{}
	return uc, nil
}

// activeRequest is a request being proxied, which a tightened access policy cancels.
type activeRequest struct {
	client netip.Addr
	header http.Header // the client's request header, which the proxy never changes
	cancel context.CancelFunc
}

// enforce cancels the requests, upgraded connections included, that the route's new access rules
// no longer allow: by their client's address, or by the headers the require_header rules ask for.
func (rt *routeTransport) enforce(r *HTTPRoute) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.access, rt.requireHeader = r.Access, r.RequireHeader
	for ar := range rt.active {
		if !rt.allows(ar) {
			ar.cancel()
		}
	}
}

// allows reports whether the rules in force admit a request; rt.mu is held.
func (rt *routeTransport) allows(ar *activeRequest) bool {
	return rt.access.Allows(ar.client) && requireHeaderPasses(rt.requireHeader, ar.header)
}

// idle reports whether no request runs on the transport.
func (rt *routeTransport) idle() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.active) == 0
}

// NewHTTPRoutes returns the http routes' server; Close stops it.
func NewHTTPRoutes(o HTTPOptions) *HTTPRoutes {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	h := &HTTPRoutes{o: o, ln: newConnListener(), lnNone: newConnListener(), transports: map[string]*routeTransport{},
		replaced: map[string][]*routeTransport{}, upstream: map[string]*upstreamConns{}, basic: NewBasicAuth(nil)}
	h.table.Store(&httpTable{byHost: map[string][]httpEntry{}})
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	h.server = &http.Server{Handler: h, ReadHeaderTimeout: httpReadHeader, IdleTimeout: httpIdle, Protocols: protocols,
		ErrorLog: slog.NewLogLogger(o.Logger.Handler(), slog.LevelDebug)}
	go func() { _ = h.server.Serve(h.ln) }()
	h.server80 = &http.Server{Handler: http.HandlerFunc(h.serve80), ReadHeaderTimeout: httpReadHeader, IdleTimeout: httpIdle,
		ErrorLog: slog.NewLogLogger(o.Logger.Handler(), slog.LevelDebug)}
	h.unrouted = &http.Server{Handler: http.HandlerFunc(h.serveUnrouted), ReadHeaderTimeout: httpReadHeader, IdleTimeout: httpIdle,
		Protocols: protocols, ErrorLog: slog.NewLogLogger(o.Logger.Handler(), slog.LevelDebug)}
	go func() { _ = h.unrouted.Serve(h.lnNone) }()
	return h
}

// Serve80 serves plain HTTP on port 80 from ln until Drain or Close.
func (h *HTTPRoutes) Serve80(ln net.Listener) error {
	if err := h.server80.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// acmePath is where ACME HTTP-01 challenges are answered (RFC 8555, section 8.3).
const acmePath = "/.well-known/acme-challenge/"

// tokenPath is where the HTTP tokens of domain claims are answered (R17).
const tokenPath = "/.well-known/rpmgr-challenge/" //nolint:gosec // G101: a URL path, not a credential

// DomainToken is the HTTP token of a pending domain claim of the gateway's org.
type DomainToken struct {
	FQDN, Value string
}

// SetDomainTokens makes tokens, by claim ID, the HTTP tokens the gateway answers on port 80.
func (h *HTTPRoutes) SetDomainTokens(tokens map[string]DomainToken) { h.tokens.Store(&tokens) }

// domainToken answers the token of a claim, only for the claimed name.
func (h *HTTPRoutes) domainToken(w http.ResponseWriter, r *http.Request, host, id string) {
	if tokens := h.tokens.Load(); tokens != nil {
		if t, ok := (*tokens)[id]; ok && strings.EqualFold(host, t.FQDN) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, t.Value)
			return
		}
	}
	http.NotFound(w, r)
}

// serve80 answers plain HTTP (docs/03-connections.md, "HTTP routes"): the HTTP tokens of the org's
// pending domain claims and ACME HTTP-01 challenges for any name, always; then, by the route of
// the host and path, a redirect to HTTPS that keeps the path and query, the route itself, or a
// closed connection; without a route, all-in-one's controller for its own names, or the 404 page.
func (h *HTTPRoutes) serve80(w http.ResponseWriter, r *http.Request) {
	h.active.Add(1)
	defer h.active.Add(-1)
	if refuseUnclean(w, r) {
		return
	}
	host := hostOnly(r.Host)
	if id, ok := strings.CutPrefix(r.URL.Path, tokenPath); ok {
		h.domainToken(w, r, host, id)
		return
	}
	rt := h.routeFor(r.Host, r.URL.Path)
	if token, ok := strings.CutPrefix(r.URL.Path, acmePath); ok {
		if h.o.Challenges != nil {
			if ka, ok := h.o.Challenges(strings.ToLower(host), token); ok {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, ka)
				return
			}
		}
		// all-in-one's controller answers for its own name, which no route serves.
		if rt == nil && h.fallback(host) {
			h.o.Fallback80.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	if rt == nil {
		if h.fallback(host) {
			h.o.Fallback80.ServeHTTP(w, r)
			return
		}
		h.o.Pages.writePage(w, r, http.StatusNotFound, pageNotFound, noRouteText)
		return
	}
	switch rt.route.Load().Port80 {
	case "serve":
		h.proxy(w, r, rt)
	case "off":
		if c, _, err := http.NewResponseController(w).Hijack(); err == nil {
			_ = c.Close()
		}
	default:
		code := http.StatusPermanentRedirect // keeps the method and body
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			code = http.StatusMovedPermanently
		}
		// The host is one a route of this gateway serves, so the redirect stays on the route.
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), code) //nolint:gosec // G710: see above
	}
}

// fallback reports whether port 80 hands a host no route serves to Fallback80.
func (h *HTTPRoutes) fallback(host string) bool {
	host = strings.TrimSuffix(host, ".")
	return h.o.Fallback80 != nil && slices.ContainsFunc(h.o.FallbackNames, func(n string) bool {
		return strings.EqualFold(strings.TrimSuffix(n, "."), host)
	})
}

// httpCipherSuites are the TLS 1.2 suites of public TLS: ECDHE with AES-GCM or ChaCha20-Poly1305
// (docs/04-security.md, "Controller certificates"); TLS 1.3's are not configurable.
var httpCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// TLSConfig is the configuration the router terminates http routes' TLS with: TLS 1.3, or TLS
// 1.2 with forward secrecy and AEAD only, for public clients (docs/04-security.md, "Controller
// certificates"); HTTP/2 or HTTP/1.1; and the route certificate for the server name.
func (h *HTTPRoutes) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: httpCipherSuites,
		NextProtos:   []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if h.o.Certificates != nil {
				if c := h.o.Certificates.ForName(hello.ServerName); c != nil {
					return c, nil
				}
			}
			if h.o.Default != nil {
				return h.o.Default, nil
			}
			return nil, fmt.Errorf("no certificate for %q", hello.ServerName)
		},
	}
}

// UnroutedTLSConfig is the configuration of the connections of names no route serves, or of none:
// that of the routes, with a certificate the gateway holds that covers the name, such as a route's
// wildcard one, or else the default one, which no client trusts.
func (h *HTTPRoutes) UnroutedTLSConfig() *tls.Config {
	cfg := h.TLSConfig()
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.o.Certificates != nil {
			if c := h.o.Certificates.Covering(hello.ServerName); c != nil {
				return c, nil
			}
		}
		if h.o.Default != nil {
			return h.o.Default, nil
		}
		return nil, fmt.Errorf("no certificate for %q", hello.ServerName)
	}
	return cfg
}

// Serve takes one connection the router chose for an http route.
func (h *HTTPRoutes) Serve(c *tls.Conn) {
	if !h.ln.put(c) {
		_ = c.Close()
	}
}

// ServeUnrouted takes one connection of a name no route serves, or of none, which only ever gets
// the 404 page.
func (h *HTTPRoutes) ServeUnrouted(c *tls.Conn) {
	if !h.lnNone.put(c) {
		_ = c.Close()
	}
}

// serveUnrouted answers the requests of such a connection with the 404 page for their name. A
// route that serves the connection's own name by now, added by a snapshot after the client
// connected, is served as on a connection of its own: the certificate the connection got is the
// one the name gets. A request for another name than the connection's, or for a name a route
// serves on a connection without a name, is misdirected (RFC 9110, section 15.5.20): a client that
// reused the connection for a name its certificate covers asks again on a connection of its own.
func (h *HTTPRoutes) serveUnrouted(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSuffix(hostOnly(r.Host), ".")
	sni := ""
	if r.TLS != nil {
		sni = strings.TrimSuffix(r.TLS.ServerName, ".")
	}
	own := sni != "" && strings.EqualFold(sni, host)
	switch {
	case own && h.Serves(host):
		h.ServeHTTP(w, r)
	case !own && (sni != "" || h.Serves(host)):
		misdirected(w, r)
	default:
		h.active.Add(1)
		defer h.active.Add(-1)
		if r.ContentLength != 0 {
			closeUnread(w, r)
		}
		h.o.Pages.writePage(w, r, http.StatusNotFound, pageNotFound, noRouteText)
	}
}

// misdirected answers 421 and closes an HTTP/1.1 connection, on which a client would otherwise send
// the name again rather than connect anew.
func misdirected(w http.ResponseWriter, r *http.Request) {
	closeUnread(w, r)
	http.Error(w, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
}

// closeUnread closes an HTTP/1.1 connection after the answer, without reading the rest of a request
// body that nothing reads: the server would wait for it, as long as a client cared to hold it.
func closeUnread(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 1 {
		return
	}
	w.Header().Set("Connection", "close")
	if r.ContentLength != 0 {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	}
}

// Serves reports whether an http route serves the name, exactly or by its wildcard hostname.
func (h *HTTPRoutes) Serves(name string) bool {
	_, ok := h.table.Load().lookup(name)
	return ok
}

// Apply makes routes the served ones. A route whose upstream protocol stays keeps its pooled
// streams; the idle streams of the others are closed.
func (h *HTTPRoutes) Apply(routes []HTTPRoute) {
	h.mu.Lock()
	defer h.mu.Unlock()
	next := map[string]*routeTransport{}
	t := &httpTable{byHost: map[string][]httpEntry{}}
	for _, r := range routes {
		rt := h.transports[r.ID]
		if rt == nil || rt.route.Load().Upstream != r.Upstream || !reflect.DeepEqual(rt.route.Load().TLS, r.TLS) {
			if rt != nil {
				// Its requests finish on the old transport, unless h.upstream ends them, under the
				// route's rules of this and every later snapshot (#523).
				h.replaced[r.ID] = append(h.replaced[r.ID], rt)
			}
			rt = h.newTransport(r)
		} else if old := rt.route.Swap(&r); !old.Access.Same(r.Access) || !sameRequireHeader(old.RequireHeader, r.RequireHeader) {
			rt.enforce(&r)
		}
		h.replaced[r.ID] = slices.DeleteFunc(h.replaced[r.ID], func(old *routeTransport) bool {
			old.enforce(&r)
			return old.idle()
		})
		next[r.ID] = rt
		h.upstreamOf(r.ID).set(r.TLS)
		for _, host := range r.Hosts {
			t.byHost[host.Hostname] = append(t.byHost[host.Hostname], httpEntry{prefix: host.PathPrefix, route: rt})
		}
	}
	for _, entries := range t.byHost {
		slices.SortFunc(entries, func(a, b httpEntry) int { return len(b.prefix) - len(a.prefix) })
	}
	h.table.Store(t)
	var rules []BasicAuthRule
	for _, r := range routes {
		rules = append(rules, r.BasicAuth...)
	}
	h.basic.Retain(rules)
	for id, rt := range h.transports {
		if next[id] != rt {
			rt.tr.CloseIdleConnections()
		}
	}
	h.transports = next
	for id := range h.replaced {
		if next[id] == nil {
			delete(h.replaced, id) // a removed route's requests finish
		}
	}
	for id, u := range h.upstream {
		if next[id] == nil {
			u.set(nil) // a removed route's connections finish
			u.mu.Lock()
			if len(u.conns) == 0 {
				delete(h.upstream, id)
			}
			u.mu.Unlock()
		}
	}
}

// upstreamOf returns the record of a route's TLS connections. Under h.mu.
func (h *HTTPRoutes) upstreamOf(route string) *upstreamConns {
	u := h.upstream[route]
	if u == nil {
		u = &upstreamConns{conns: map[*upstreamConn]struct{}{}}
		h.upstream[route] = u
	}
	return u
}

// newTransport returns the proxy of a route; its transport dials tunnel streams to the route.
func (h *HTTPRoutes) newTransport(r HTTPRoute) *routeTransport {
	rt := &routeTransport{access: r.Access, requireHeader: r.RequireHeader, active: map[*activeRequest]struct{}{}, upstream: h.upstreamOf(r.ID),
		pooled: map[net.Conn]*pooledConn{}, best: func() (uint32, bool) { return h.o.Sessions.BestPriority(r.ID) },
		entry: func(con string, p uint32) bool { return h.o.Sessions.HasEntry(r.ID, con, p) }}
	rt.route.Store(&r)
	rt.tr = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := h.dial(ctx, r.ID)
			if err != nil {
				return nil, err
			}
			return rt.pool(rt.route.Load().Limit.UpstreamConn(c), c, nil)
		},
		ResponseHeaderTimeout: httpUpstreamHeader,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       httpIdle,
	}
	target := &url.URL{Scheme: "http", Host: r.ID + ".route.invalid"}
	switch r.Upstream {
	case "h2c":
		p := new(http.Protocols)
		p.SetUnencryptedHTTP2(true)
		rt.tr.Protocols = p
	case "https":
		target.Scheme = "https"
		p := new(http.Protocols)
		p.SetHTTP1(true)
		p.SetHTTP2(true)
		rt.tr.Protocols = p
		rt.tls = map[string]upstreamTLS{}
		for id, u := range r.TLS {
			if cfg, err := u.config(); err == nil {
				rt.tls[id] = upstreamTLS{cfg: cfg, connector: u.Connector, verify: u.Verify}
			}
		}
		rt.tr.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return rt.pool(h.dialTLS(ctx, rt)) }
	}
	rt.closeIdle = rt.tr.CloseIdleConnections
	rt.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			route := rt.route.Load()
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			if route.HostHeader != "" {
				pr.Out.Host = route.HostHeader
			}
			forward(pr, route.TrustedProxies)
			// The upstream continues the trace: the gateway's span, or the client's without one.
			otel.GetTextMapPropagator().Inject(pr.Out.Context(), propagation.HeaderCarrier(pr.Out.Header))
			if len(route.BasicAuth) > 0 {
				pr.Out.Header.Del("Authorization") // the gateway's credentials, not the upstream's
			}
			for _, rh := range route.RequireHeader {
				pr.Out.Header.Del(rh.Name) // a shared secret between the client and the gateway
			}
			apply(pr.Out.Header, route.RequestHeaders)
		},
		Transport:     rt,
		FlushInterval: -1, // stream responses as they come, for server-sent events and gRPC
		ModifyResponse: func(res *http.Response) error {
			route := rt.route.Load()
			if route.HSTS > 0 {
				res.Header.Del("Strict-Transport-Security") // the gateway's, set before, applies
			}
			apply(res.Header, route.ResponseHeaders)
			return grpcTrailersOnly(res)
		},
		ErrorHandler: h.proxyError,
		ErrorLog:     slog.NewLogLogger(h.o.Logger.Handler(), slog.LevelDebug),
	}
	return rt
}

// clientOf returns the address of a request's client: the TCP peer, or, when the peer is a trusted
// proxy, the last address in X-Forwarded-For that is not a trusted proxy.
func clientOf(r *http.Request, trusted []netip.Prefix) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	isTrusted := func(ip netip.Addr) bool {
		return slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(ip) })
	}
	ip := ap.Addr().Unmap()
	if !isTrusted(ip) {
		return ip
	}
	var chain []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		chain = append(chain, strings.Split(v, ",")...)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil {
			return ip // a chain that does not parse names no one: the proxy is the client
		}
		if hop = hop.Unmap(); !isTrusted(hop) {
			return hop
		}
		ip = hop
	}
	return ip
}

// forward sets the forwarding headers of a proxied request (docs/03-connections.md, "HTTP
// routes"): X-Forwarded-For, -Proto and -Host and Forwarded. The client's own are dropped unless
// the client is a trusted proxy, whose chain the gateway extends and whose protocol and host it
// keeps.
func forward(pr *httputil.ProxyRequest, trusted []netip.Prefix) {
	client, err := netip.ParseAddrPort(pr.In.RemoteAddr)
	if err != nil {
		return
	}
	ip := client.Addr().Unmap()
	scheme := "https"
	if pr.In.TLS == nil {
		scheme = "http"
	}
	proto, host := scheme, pr.In.Host
	var chain, prior []string
	if slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(ip) }) {
		chain = pr.In.Header.Values("X-Forwarded-For")
		prior = pr.In.Header.Values("Forwarded")
		if p := pr.In.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
			proto = p
		}
		if hh := pr.In.Header.Get("X-Forwarded-Host"); hh != "" {
			host = hh
		}
	}
	pr.Out.Header.Del("Forwarded") // Rewrite already drops X-Forwarded-*, not Forwarded
	pr.Out.Header.Set("X-Forwarded-For", strings.Join(append(chain, ip.String()), ", "))
	pr.Out.Header.Set("X-Forwarded-Proto", proto)
	pr.Out.Header.Set("X-Forwarded-Host", host)
	node := ip.String()
	if ip.Is6() {
		node = `"[` + node + `]"`
	}
	pr.Out.Header.Set("Forwarded", strings.Join(append(prior, fmt.Sprintf("for=%s;host=%q;proto=%s", node, pr.In.Host, scheme)), ", "))
}

// grpcTrailersOnly turns a gRPC "Trailers-Only" response, whose status comes in its only HEADERS
// frame, into headers followed by trailers: the proxy flushes the headers of every streamed
// response at once, so that frame can no longer end the stream, and a gRPC client wants the
// status in trailers then.
func grpcTrailersOnly(res *http.Response) error {
	if !strings.HasPrefix(res.Header.Get("Content-Type"), "application/grpc") || res.Header.Get("Grpc-Status") == "" ||
		len(res.Trailer) > 0 {
		return nil
	}
	res.Trailer = http.Header{}
	for _, k := range []string{"Grpc-Status", "Grpc-Message", "Grpc-Status-Details-Bin"} {
		if v, ok := res.Header[k]; ok {
			res.Trailer[k] = v
			delete(res.Header, k)
		}
	}
	return nil
}

// openError is a stream that could not be opened, with its result code.
type openError struct {
	route string
	code  tunnelv1.ResultCode
}

func (e *openError) Error() string { return fmt.Sprintf("route %s: %s", e.route, e.code) }

// dial opens a tunnel stream for the route.
func (h *HTTPRoutes) dial(ctx context.Context, route string) (*streamConn, error) {
	c, _, _, err := h.open(ctx, route)
	return c, err
}

// open opens a tunnel stream for the route and returns it with the target the connector chose
// and that connector, as its certificate names it.
func (h *HTTPRoutes) open(ctx context.Context, route string) (*streamConn, string, string, error) {
	open := &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_TCP, RouteId: route}
	if h.o.Revision != nil {
		open.SnapshotRev = h.o.Revision()
	}
	st, res, err := h.o.Sessions.OpenStreamResult(ctx, open)
	if err != nil {
		return nil, "", "", err
	}
	if st == nil {
		return nil, "", "", &openError{route: route, code: res.GetCode()}
	}
	return &streamConn{Stream: st}, res.GetTargetId(), StreamConnector(st), nil
}

// upstreamTLS is the TLS configuration of a route target, for the streams of its connector.
type upstreamTLS struct {
	cfg       *tls.Config
	connector string // "" from a controller that names none
	verify    UpstreamVerify
}

// dialTLS opens a tunnel stream for an https route and completes TLS over it, verified with the
// settings of the target the connector chose. A target without settings fails closed, and so does
// one of another connector: a connector cannot have the gateway apply another target's settings,
// such as an unverified one's, to its stream (ADR-0017). Settings that name no connector, from an
// older controller, apply only when they verify the chain.
func (h *HTTPRoutes) dialTLS(ctx context.Context, rt *routeTransport) (net.Conn, *streamConn, error) {
	route := rt.route.Load().ID
	c, target, connector, err := h.open(ctx, route)
	if err != nil {
		return nil, nil, err
	}
	u, ok := rt.tls[target]
	switch {
	case !ok:
		_ = c.Close()
		return nil, nil, fmt.Errorf("route %s: no TLS settings for target %q", route, target)
	case u.verify != VerifyChain && u.connector == "":
		_ = c.Close()
		return nil, nil, fmt.Errorf("route %s: target %s is not verified and names no connector", route, target)
	case u.connector != "" && u.connector != connector:
		_ = c.Close()
		return nil, nil, fmt.Errorf("route %s: connector %s answered for target %s, which is not its own", route, connector, target)
	}
	// The stream is tracked under the TLS connection, which the transport needs as a *tls.Conn to
	// learn the protocol ALPN chose.
	tracked, err := rt.upstream.track(target, rt.route.Load().TLS[target], c)
	if err != nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("route %s: %w", route, err)
	}
	tc := tls.Client(rt.route.Load().Limit.UpstreamConn(tracked), u.cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = tc.Close()
		return nil, nil, fmt.Errorf("route %s: TLS to target %s: %w", route, target, err)
	}
	return tc, c, nil
}

// proxyError answers a request the proxy could not complete: 503 with Retry-After when no
// connector is ready, 504 when the upstream does not answer in time, 502 otherwise, each with the
// service-unavailable page; a body above the route's limit is 413.
func (h *HTTPRoutes) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		oe *openError
		ne net.Error
		me *http.MaxBytesError
	)
	status := http.StatusBadGateway
	switch {
	case errors.As(err, &me):
		status = http.StatusRequestEntityTooLarge
	case errors.Is(err, ErrNoSession), errors.Is(err, ErrDraining):
		status = http.StatusServiceUnavailable
	case errors.As(err, &oe) && (oe.code == tunnelv1.ResultCode_RESULT_CODE_ROUTE_UNKNOWN ||
		oe.code == tunnelv1.ResultCode_RESULT_CODE_DRAINING || oe.code == tunnelv1.ResultCode_RESULT_CODE_OVERLOADED):
		status = http.StatusServiceUnavailable
	case errors.As(err, &oe) && oe.code == tunnelv1.ResultCode_RESULT_CODE_UPSTREAM_TIMEOUT,
		errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		status = http.StatusGatewayTimeout
	case errors.Is(err, context.Canceled) && r.Context().Err() != nil:
		return // the client went away
	}
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", strconv.Itoa(httpRetryAfter))
	}
	h.o.Logger.Debug("proxy error", "host", r.Host, "status", status, "error", err)
	if status == http.StatusRequestEntityTooLarge {
		http.Error(w, http.StatusText(status), status)
		return
	}
	h.o.Pages.writePage(w, r, status, pageUnavailable, http.StatusText(status))
}

// ServeHTTP routes a request by its host and the longest matching path prefix.
func (h *HTTPRoutes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.active.Add(1)
	defer h.active.Add(-1)
	if refuseUnclean(w, r) {
		return
	}
	rt := h.routeFor(r.Host, r.URL.Path)
	if rt == nil {
		// A name this gateway does not route, on a connection of another name: a client that
		// reused the connection, such as an HTTP/2 one under a wildcard certificate, asks again
		// on a connection of its own, which reaches the name's own handler (RFC 9110, section
		// 15.5.20).
		if host := strings.TrimSuffix(hostOnly(r.Host), "."); r.TLS != nil && r.TLS.ServerName != "" &&
			!strings.EqualFold(strings.TrimSuffix(r.TLS.ServerName, "."), host) && !h.Serves(host) {
			misdirected(w, r)
			return
		}
		h.o.Pages.writePage(w, r, http.StatusNotFound, pageNotFound, noRouteText)
		return
	}
	if age := rt.route.Load().HSTS; age > 0 && r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age="+strconv.Itoa(age))
	}
	h.proxy(w, r, rt)
}

// refuseUnclean answers a request no route may get and reports whether it did: CONNECT, which
// asks for a tunnel rather than a path (501), and a path that is not clean (400). Routes are chosen
// by the path's prefix and the path goes upstream as it came, so a path with an empty, "." or ".."
// segment, such as //admin, /./admin or /x/../admin, would be routed by a broader route than the
// one a backend that merges slashes or resolves dot segments serves it as (docs/03-connections.md,
// "HTTP routes").
func refuseUnclean(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.Method == http.MethodConnect:
		http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
	case !cleanPath(r.URL.Path):
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	default:
		return false
	}
	return true
}

// cleanPath reports whether p, a request's decoded path, starts with "/" and has no empty, "." or
// ".." segment, also not once ";" parameters are dropped (".;x" and "..;x", which some servers
// resolve as dot segments, or ";x" alone), no "\\", which some servers read as "/", and no control
// character; a trailing "/" is allowed.
func cleanPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.ContainsRune(p, '\\') {
		return false
	}
	if strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return false
	}
	for seg := range strings.SplitSeq(p[1:], "/") {
		if name, _, _ := strings.Cut(seg, ";"); name == "." || name == ".." {
			return false
		}
	}
	// A server that drops ";" parameters must read a clean path too: "/;/admin" is "//admin" there,
	// and "/;x/admin" too. A last segment of parameters alone ("/admin/;x") is "/admin/", which a
	// trailing "/" allows.
	if bare := withoutParams(p); bare != p {
		return cleanPath(bare)
	}
	return true
}

// withoutParams returns p without the ";" parameters of its segments ("/admin;x/y" is "/admin/y"),
// as servers that read path parameters see it.
func withoutParams(p string) string {
	if !strings.Contains(p, ";") {
		return p
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		segs[i], _, _ = strings.Cut(seg, ";")
	}
	return strings.Join(segs, "/")
}

// proxy sends a request over the route, within its access rules and its WebSocket and body
// settings.
func (h *HTTPRoutes) proxy(rw http.ResponseWriter, r *http.Request, rt *routeTransport) {
	route := rt.route.Load()
	w := &statusWriter{ResponseWriter: rw}
	tctx, span := otel.Tracer(tracerName).Start(otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header)),
		"rpmgr.gateway.http", trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attribute.String("rpmgr.route", route.ID)))
	r = r.WithContext(tctx)
	defer func() {
		code := cmp.Or(w.code, http.StatusOK)
		h.o.Sessions.metrics().request(route.ID, code)
		span.SetAttributes(attribute.Int("http.response.status_code", code))
		if code >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(code))
		}
		span.End()
	}()
	client := clientOf(r, route.TrustedProxies)
	if !route.Access.Allows(client) || !requireHeaderPasses(route.RequireHeader, r.Header) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	// The rates come before basic auth, so that a flood never reaches its password checks.
	if ok, wait, _ := route.Limit.Admit(client, false); !ok {
		if r.ContentLength != 0 {
			closeUnread(w, r)
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter(wait)))
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	if len(route.BasicAuth) > 0 {
		user, password, given := r.BasicAuth()
		ok := false
		var err error
		if given {
			ok, err = h.basic.Check(r.Context(), client, route.BasicAuth, user, password)
		}
		switch {
		case errors.Is(err, ErrRateLimited):
			w.Header().Set("Retry-After", strconv.Itoa(int(basicAuthRefill.Seconds())))
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		case err != nil:
			return // the client went away
		case !ok:
			w.Header().Set("WWW-Authenticate", `Basic realm="rpmgr", charset="UTF-8"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
	}
	ctx, cancel := context.WithCancel(withPageRequest(r.Context(), r))
	defer cancel()
	ar := &activeRequest{client: client, header: r.Header, cancel: cancel}
	rt.mu.Lock()
	rt.active[ar] = struct{}{}
	// The rules may have changed while the request was checked, basic auth taking a while; under
	// rt.mu, either enforce sees the request, or this check sees the rules it set (#523).
	allowed := rt.allows(ar)
	rt.mu.Unlock()
	defer func() {
		rt.mu.Lock()
		delete(rt.active, ar)
		rt.mu.Unlock()
	}()
	if !allowed {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	r = r.WithContext(ctx)
	if route.Maintenance {
		if r.ContentLength != 0 {
			closeUnread(w, r) // nothing reads the body
		}
		w.Header().Set("Retry-After", strconv.Itoa(maintenanceRetryAfter))
		h.o.Pages.writeMaintenance(w, r, route.MaintenanceMessage)
		return
	}
	if !route.WebSocket && r.Header.Get("Upgrade") != "" {
		http.Error(w, "upgrades are off for this route", http.StatusForbidden)
		return
	}
	if route.MaxBody > 0 {
		if r.ContentLength > route.MaxBody {
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, route.MaxBody)
	}
	// A request in flight, an upgraded one until it ends, holds one of the route's connection slots,
	// released however the request ends.
	release, ok := route.Limit.Acquire()
	if !ok {
		if r.ContentLength != 0 {
			closeUnread(w, r)
		}
		w.Header().Set("Retry-After", strconv.Itoa(limitRetryAfter))
		h.o.Pages.writePage(w, r, http.StatusServiceUnavailable, pageUnavailable, http.StatusText(http.StatusServiceUnavailable))
		return
	}
	defer release()
	rt.proxy.ServeHTTP(w, r)
}

// routeFor returns the route for a request's host, with or without a port, and path, or nil.
func (h *HTTPRoutes) routeFor(host, path string) *routeTransport {
	entries, _ := h.table.Load().lookup(hostOnly(host))
	// A path with ";" parameters goes to the longest prefix that either it or its form without them
	// matches, so a backend that drops the parameters never gets a path that a narrower route
	// serves through a broader one.
	bare := withoutParams(path)
	for _, e := range entries {
		if matchPrefix(path, e.prefix) || matchPrefix(bare, e.prefix) {
			return e.route
		}
	}
	return nil
}

// lookup returns the entries for a host: its own, or else those of the wildcard hostname one
// label up.
func (t *httpTable) lookup(host string) ([]httpEntry, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if e, ok := t.byHost[host]; ok {
		return e, true
	}
	if _, parent, ok := strings.Cut(host, "."); ok {
		e, ok := t.byHost["*."+parent]
		return e, ok
	}
	return nil, false
}

// matchPrefix reports whether a path falls under a prefix, at a segment boundary: "/docs"
// matches "/docs", "/docs/x" and "/docs;x", not "/docsx".
func matchPrefix(path, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/' || path[len(prefix)] == ';'
}

// Active returns the number of requests being served.
func (h *HTTPRoutes) Active() int64 { return h.active.Load() }

// Drain stops taking connections and keep-alives; requests in flight go on.
func (h *HTTPRoutes) Drain() {
	h.server.SetKeepAlivesEnabled(false)
	h.server80.SetKeepAlivesEnabled(false)
	h.unrouted.SetKeepAlivesEnabled(false)
	h.ln.close()
	h.lnNone.close()
}

// Close stops the server and every connection.
func (h *HTTPRoutes) Close() {
	h.ln.close()
	h.lnNone.close()
	_ = h.server.Close()
	_ = h.server80.Close()
	_ = h.unrouted.Close()
	h.mu.Lock()
	for _, rt := range h.transports {
		rt.tr.CloseIdleConnections()
	}
	h.mu.Unlock()
}

// connListener hands the router's connections to the HTTP server.
type connListener struct {
	ch     chan net.Conn
	done   chan struct{}
	once   sync.Once
	closed atomic.Bool
}

func newConnListener() *connListener {
	return &connListener{ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *connListener) put(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) close() { l.once.Do(func() { l.closed.Store(true); close(l.done) }) }

func (l *connListener) Close() error { l.close(); return nil }

func (l *connListener) Addr() net.Addr { return &net.TCPAddr{} }

// streamConn is a tunnel stream as the net.Conn the HTTP transport dials. The transport sets no
// deadlines on it (no WriteByteTimeout), so they are not supported.
type streamConn struct {
	tunnel.Stream
	onClose func() // set before the transport has the connection
}

func (c *streamConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return c.Stream.Close()
}

func (c *streamConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *streamConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *streamConn) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (c *streamConn) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (c *streamConn) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }
func (c *streamConn) CloseWrite() error                { return c.Stream.CloseWrite() }
