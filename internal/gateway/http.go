// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// The HTTP server's timing (docs/03-connections.md, "Timeouts, keepalive and backoff"); the
// variables change only in tests.
const (
	httpIdle       = 120 * time.Second // a keep-alive connection without a request
	httpRetryAfter = 5                 // seconds, in a 503 without a ready connector
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
}

// UpstreamTLS is how the gateway verifies the HTTPS upstream of one route target.
type UpstreamTLS struct {
	ServerName string
	// CAPEM verifies the upstream's chain; empty is the host's trust store.
	CAPEM []byte
	// SPKISHA256, if set, must be the SHA-256 of the leaf's SubjectPublicKeyInfo.
	SPKISHA256 []byte
}

// config returns the TLS configuration of a connection to the upstream: TLS 1.2 or later, the
// server name, the CA bundle or the host's trust store, the pin, and ALPN for HTTP/2.
func (u UpstreamTLS) config() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.ServerName, NextProtos: []string{"h2", "http/1.1"}}
	if len(u.CAPEM) > 0 {
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(u.CAPEM) {
			return nil, errors.New("the CA bundle holds no certificate")
		}
	}
	if pin := u.SPKISHA256; len(pin) > 0 {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if !bytes.Equal(sum[:], pin) {
				return errors.New("the upstream's key does not match its pin")
			}
			return nil
		}
	}
	return cfg, nil
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
	Logger   *slog.Logger
}

// HTTPRoutes serves the http routes (docs/03-connections.md, "HTTP routes"): it terminates TLS
// with the route certificate for the server name, routes each request by host and the longest
// path prefix, and proxies it over a tunnel stream to a connector of the route.
type HTTPRoutes struct {
	o      HTTPOptions
	server *http.Server
	ln     *connListener
	table  atomic.Pointer[httpTable]
	active atomic.Int64 // requests being served

	mu         sync.Mutex
	transports map[string]*routeTransport // by route ID
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
	tls   map[string]*tls.Config // by route target ID
}

// NewHTTPRoutes returns the http routes' server; Close stops it.
func NewHTTPRoutes(o HTTPOptions) *HTTPRoutes {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	h := &HTTPRoutes{o: o, ln: newConnListener(), transports: map[string]*routeTransport{}}
	h.table.Store(&httpTable{byHost: map[string][]httpEntry{}})
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	h.server = &http.Server{Handler: h, ReadHeaderTimeout: httpReadHeader, IdleTimeout: httpIdle, Protocols: protocols,
		ErrorLog: slog.NewLogLogger(o.Logger.Handler(), slog.LevelDebug)}
	go func() { _ = h.server.Serve(h.ln) }()
	return h
}

// TLSConfig is the configuration the router terminates http routes' TLS with: TLS 1.3, or TLS
// 1.2 with forward secrecy and AEAD only, for public clients (docs/04-security.md, "Controller
// certificates"); HTTP/2 or HTTP/1.1; and the route certificate for the server name.
func (h *HTTPRoutes) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{ // TLS 1.2 only; TLS 1.3's are not configurable
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		NextProtos: []string{"h2", "http/1.1"},
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

// Serve takes one connection the router chose for an http route.
func (h *HTTPRoutes) Serve(c *tls.Conn) {
	if !h.ln.put(c) {
		_ = c.Close()
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
			rt = h.newTransport(r)
		} else {
			rt.route.Store(&r)
		}
		next[r.ID] = rt
		for _, host := range r.Hosts {
			t.byHost[host.Hostname] = append(t.byHost[host.Hostname], httpEntry{prefix: host.PathPrefix, route: rt})
		}
	}
	for _, entries := range t.byHost {
		slices.SortFunc(entries, func(a, b httpEntry) int { return len(b.prefix) - len(a.prefix) })
	}
	h.table.Store(t)
	for id, rt := range h.transports {
		if next[id] != rt {
			rt.tr.CloseIdleConnections()
		}
	}
	h.transports = next
}

// newTransport returns the proxy of a route; its transport dials tunnel streams to the route.
func (h *HTTPRoutes) newTransport(r HTTPRoute) *routeTransport {
	rt := &routeTransport{}
	rt.route.Store(&r)
	rt.tr = &http.Transport{
		DialContext:           func(ctx context.Context, _, _ string) (net.Conn, error) { return h.dial(ctx, r.ID) },
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
		rt.tls = map[string]*tls.Config{}
		for id, u := range r.TLS {
			if cfg, err := u.config(); err == nil {
				rt.tls[id] = cfg
			}
		}
		rt.tr.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return h.dialTLS(ctx, rt) }
	}
	rt.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		Transport:      rt.tr,
		FlushInterval:  -1, // stream responses as they come, for server-sent events and gRPC
		ModifyResponse: grpcTrailersOnly,
		ErrorHandler:   h.proxyError,
		ErrorLog:       slog.NewLogLogger(h.o.Logger.Handler(), slog.LevelDebug),
	}
	return rt
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
func (h *HTTPRoutes) dial(ctx context.Context, route string) (net.Conn, error) {
	c, _, err := h.open(ctx, route)
	return c, err
}

// open opens a tunnel stream for the route and returns it with the target the connector chose.
func (h *HTTPRoutes) open(ctx context.Context, route string) (net.Conn, string, error) {
	open := &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_TCP, RouteId: route}
	if h.o.Revision != nil {
		open.SnapshotRev = h.o.Revision()
	}
	st, res, err := h.o.Sessions.OpenStreamResult(ctx, open)
	if err != nil {
		return nil, "", err
	}
	if st == nil {
		return nil, "", &openError{route: route, code: res.GetCode()}
	}
	return &streamConn{Stream: st}, res.GetTargetId(), nil
}

// dialTLS opens a tunnel stream for an https route and completes TLS over it, verified with the
// settings of the target the connector chose; a target without them fails closed.
func (h *HTTPRoutes) dialTLS(ctx context.Context, rt *routeTransport) (net.Conn, error) {
	route := rt.route.Load().ID
	c, target, err := h.open(ctx, route)
	if err != nil {
		return nil, err
	}
	cfg := rt.tls[target]
	if cfg == nil {
		_ = c.Close()
		return nil, fmt.Errorf("route %s: no TLS settings for target %q", route, target)
	}
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("route %s: TLS to target %s: %w", route, target, err)
	}
	return tc, nil
}

// proxyError answers a request the proxy could not complete: 503 with Retry-After when no
// connector is ready, 504 when the upstream does not answer in time, 502 otherwise.
func (h *HTTPRoutes) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		oe *openError
		ne net.Error
	)
	status := http.StatusBadGateway
	switch {
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
	http.Error(w, http.StatusText(status), status)
}

// ServeHTTP routes a request by its host and the longest matching path prefix.
func (h *HTTPRoutes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.active.Add(1)
	defer h.active.Add(-1)
	rt := h.routeFor(r.Host, r.URL.Path)
	if rt == nil {
		http.Error(w, "no route for this host and path", http.StatusNotFound)
		return
	}
	if !rt.route.Load().WebSocket && r.Header.Get("Upgrade") != "" {
		http.Error(w, "upgrades are off for this route", http.StatusForbidden)
		return
	}
	rt.proxy.ServeHTTP(w, r)
}

// routeFor returns the route for a request's host, with or without a port, and path, or nil.
func (h *HTTPRoutes) routeFor(host, path string) *routeTransport {
	if hp, _, err := net.SplitHostPort(host); err == nil {
		host = hp
	}
	entries, _ := h.table.Load().lookup(host)
	for _, e := range entries {
		if matchPrefix(path, e.prefix) {
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
// matches "/docs" and "/docs/x", not "/docsx".
func matchPrefix(path, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/'
}

// Active returns the number of requests being served.
func (h *HTTPRoutes) Active() int64 { return h.active.Load() }

// Drain stops taking connections and keep-alives; requests in flight go on.
func (h *HTTPRoutes) Drain() {
	h.server.SetKeepAlivesEnabled(false)
	h.ln.close()
}

// Close stops the server and every connection.
func (h *HTTPRoutes) Close() {
	h.ln.close()
	_ = h.server.Close()
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
type streamConn struct{ tunnel.Stream }

func (c *streamConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *streamConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *streamConn) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (c *streamConn) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (c *streamConn) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }
func (c *streamConn) CloseWrite() error                { return c.Stream.CloseWrite() }
