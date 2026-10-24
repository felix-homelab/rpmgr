// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

// ConnectMode is how a CONNECT listener checks proxy credentials (docs/03-connections.md, "HTTP
// CONNECT routes", D130).
type ConnectMode string

// The modes of a CONNECT listener.
const (
	ConnectNone       ConnectMode = "none"        // plain CONNECT, IP rules only
	ConnectTLSBasic   ConnectMode = "tls_basic"   // a TLS listener with basic auth
	ConnectPlainBasic ConnectMode = "plain_basic" // plain CONNECT with basic auth in the clear
)

// Connect is a tcp route's place on a CONNECT listener: the port is shared by the routes of one
// org, each named by its authorities, and every route of the port has the same Mode and Hostname.
type Connect struct {
	// Org owns the listener: every route of a port has the same.
	Org string
	// Authorities are the lower-case host names that choose the route; a CONNECT's port is ignored.
	Authorities []string
	Mode        ConnectMode
	// Hostname is the TLS listener's name, whose certificate it presents (ConnectTLSBasic).
	Hostname string
	// BasicAuth are the rules a client of a basic mode must pass; none admits nobody.
	BasicAuth []BasicAuthRule
}

// connectTable is a CONNECT listener's routes by authority.
type connectTable struct {
	org      string
	mode     ConnectMode
	hostname string
	routes   map[string]*TCPRoute
}

func newConnectTable(routes []TCPRoute) *connectTable {
	t := &connectTable{org: routes[0].Connect.Org, mode: routes[0].Connect.Mode, hostname: routes[0].Connect.Hostname, routes: map[string]*TCPRoute{}}
	for i := range routes {
		for _, a := range routes[i].Connect.Authorities {
			t.routes[a] = &routes[i]
		}
	}
	return t
}

// byID returns the route with the ID, or nil.
func (t *connectTable) byID(id string) *TCPRoute {
	for _, r := range t.routes {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// keeps reports whether a tunnel of route id, admitted under old, may stay open under t: the
// listener's org, mode and name are the same, the route is still there with the same credentials,
// and its access rules still admit the client.
func (t *connectTable) keeps(old *connectTable, id string, client net.Addr) bool {
	if t.org != old.org || t.mode != old.mode || t.hostname != old.hostname {
		return false
	}
	r, was := t.byID(id), old.byID(id)
	return r != nil && was != nil && sameRules(r.Connect.BasicAuth, was.Connect.BasicAuth) && r.Access.AllowsAddr(client)
}

// admits reports whether the access rules of a route of t admit the client: a peer no route
// admits is dropped before its TLS handshake and its request.
func (t *connectTable) admits(client net.Addr) bool {
	for _, r := range t.routes {
		if r.Access.AllowsAddr(client) {
			return true
		}
	}
	return false
}

func sameRules(a, b []BasicAuthRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].PolicyID != b[i].PolicyID || a[i].CredentialVersion != b[i].CredentialVersion {
			return false
		}
	}
	return true
}

// connectHeadMax bounds a CONNECT request's head; a longer one is refused.
const connectHeadMax = 16 << 10

// authorityRe is an authority-form request target: a host name, or a bracketed IPv6 address, and
// a port.
var authorityRe = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+):[0-9]{1,5}$`)

// connectRefusal is an answer to a CONNECT that opens no tunnel.
type connectRefusal struct {
	status int
	header string // extra header lines, each ending in CRLF
}

// handleConnect serves one connection of a CONNECT listener (docs/03-connections.md, "HTTP
// CONNECT routes"): a TLS handshake for ConnectTLSBasic, then one CONNECT request in authority
// form, which chooses a route of the listener by its host, is checked against the route's
// credentials in a basic mode and its access rules, and is answered 200 once a stream to a
// connector is open; then the connection is relayed over the stream, with any bytes the client
// sent along with the head first. Anything else is answered and closed. The head, with the
// handshake, is read within the HTTP server's header timeout and up to connectHeadMax; a request
// with a body or a Host other than the authority is refused, so no second request can hide
// behind the first.
func (t *TCPRoutes) handleConnect(c net.Conn, pl *portListener, table *connectTable) {
	deadline := time.Now().Add(httpReadHeader)
	_ = c.SetDeadline(deadline)
	ctx, cancel := context.WithDeadline(t.ctx, deadline) // no wait outlives the head's deadline
	defer cancel()
	conn := c
	if table.mode == ConnectTLSBasic {
		tc := tls.Server(c, t.connectTLS(table.hostname))
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = c.Close()
			return
		}
		conn = tc
	}
	br := bufio.NewReader(&io.LimitedReader{R: conn, N: connectHeadMax})
	req, err := readConnectHead(br)
	if err != nil {
		refuseConnect(conn, connectRefusal{status: http.StatusBadRequest})
		return
	}
	r, refusal := t.admit(ctx, req, clientAddr(c), table)
	if r == nil {
		refuseConnect(conn, refusal)
		return
	}
	// Recorded under pl.mu, which enforce takes after Apply swapped the port's routes in: either
	// enforce sees the connection with its route, or the port's routes changed while the request
	// was read and it is answered as if no connector were ready, so the client asks again (#523).
	pl.mu.Lock()
	if pl.connect.Load() != table {
		pl.mu.Unlock()
		refuseConnect(conn, connectRefusal{status: http.StatusServiceUnavailable, header: "Retry-After: 1\r\n"})
		return
	}
	pl.conns[c] = r.ID
	pl.mu.Unlock()
	st, err := openStream(ctx, t.o.Sessions, t.o.Revision, c, r.ID, "")
	if err != nil {
		t.o.Logger.Debug("no stream for a CONNECT", "route", r.ID, "error", err)
		refuseConnect(conn, connectRefusal{status: http.StatusServiceUnavailable, header: "Retry-After: " + strconv.Itoa(httpRetryAfter) + "\r\n"})
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		st.Abort()
		abort(c)
		return
	}
	_ = c.SetDeadline(time.Time{})
	early, _ := br.Peek(br.Buffered()) // sent with the head, before the answer: the tunnel's first bytes
	relayConn(st, &earlyConn{Conn: conn, early: early}, r.IdleTimeout)
}

// earlyConn reads the bytes a client sent along with its CONNECT head first, then its connection.
type earlyConn struct {
	net.Conn
	early []byte
}

func (c *earlyConn) Read(p []byte) (int, error) {
	if len(c.early) > 0 {
		n := copy(p, c.early)
		c.early = c.early[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// CloseWrite half-closes the connection, as Relay needs.
func (c *earlyConn) CloseWrite() error {
	if hc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return nil
}

// SetLinger lets Relay reset the connection.
func (c *earlyConn) SetLinger(sec int) error {
	if l, ok := c.Conn.(lingerer); ok {
		return l.SetLinger(sec)
	}
	return nil
}

// connectHead is the head of a request to a CONNECT listener.
type connectHead struct {
	method, target, proto string
	header                http.Header
}

// connectHeadFields bounds the header fields of a CONNECT head.
const connectHeadFields = 100

// readConnectHead reads a request's line and header fields as they came, strictly: lines end in
// CRLF, a field is a token, a colon and a value without control characters, and no line is folded.
// net/http's ReadRequest would drop the Host field, which must match the authority, and accepts
// lines that other parsers read otherwise.
func readConnectHead(br *bufio.Reader) (*connectHead, error) {
	line := func() (string, error) {
		l, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		l, ok := strings.CutSuffix(l, "\r\n")
		if !ok || strings.ContainsAny(l, "\r\n") {
			return "", errors.New("gateway: a line that does not end in CRLF")
		}
		return l, nil
	}
	first, err := line()
	if err != nil {
		return nil, err
	}
	parts := strings.Split(first, " ")
	if len(parts) != 3 {
		return nil, errors.New("gateway: not a request line")
	}
	h := http.Header{}
	for range connectHeadFields + 1 {
		l, err := line()
		if err != nil {
			return nil, err
		}
		if l == "" {
			return &connectHead{method: parts[0], target: parts[1], proto: parts[2], header: h}, nil
		}
		name, value, ok := strings.Cut(l, ":")
		value = strings.Trim(value, " \t")
		if !ok || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return nil, errors.New("gateway: not a header field") // a folded line starts with a blank, which no name has
		}
		h.Add(name, value)
	}
	return nil, errors.New("gateway: too many header fields")
}

// admit checks a CONNECT request and returns its route, or the refusal. The method compares
// with case, as RFC 9110 has it: "connect" is no CONNECT. In a basic mode the credentials are
// checked first, against an unknown authority too, so that a client without them learns nothing
// of the listener's routes; then, as in the mode none, an unknown authority and one whose access
// rules refuse the client get the same 403.
func (t *TCPRoutes) admit(ctx context.Context, req *connectHead, client netip.Addr, table *connectTable) (*TCPRoute, connectRefusal) {
	target := req.target
	host, _, err := net.SplitHostPort(target)
	hosts := req.header.Values("Host")
	switch {
	case req.method != http.MethodConnect:
		return nil, connectRefusal{status: http.StatusMethodNotAllowed, header: "Allow: CONNECT\r\n"}
	case req.proto != "HTTP/1.1" && req.proto != "HTTP/1.0", !authorityRe.MatchString(target), err != nil, host == "":
		return nil, connectRefusal{status: http.StatusBadRequest}
	case len(req.header.Values("Content-Length")) > 0 || len(req.header.Values("Transfer-Encoding")) > 0:
		// A body could be read as a second request.
		return nil, connectRefusal{status: http.StatusBadRequest}
	case len(hosts) > 1 || len(hosts) == 1 && !strings.EqualFold(hosts[0], target):
		return nil, connectRefusal{status: http.StatusBadRequest}
	}
	r := table.routes[strings.TrimSuffix(strings.ToLower(host), ".")]
	if table.mode == ConnectTLSBasic || table.mode == ConnectPlainBasic {
		user, password, given := proxyBasicAuth(req.header.Get("Proxy-Authorization"))
		rules := unknownUser
		if r != nil && len(r.Connect.BasicAuth) > 0 {
			rules = r.Connect.BasicAuth
		}
		ok := false
		if given {
			ok, err = t.basic.Check(ctx, client, rules, user, password)
		}
		switch {
		case errors.Is(err, ErrRateLimited):
			return nil, connectRefusal{status: http.StatusTooManyRequests, header: "Retry-After: " + strconv.Itoa(int(basicAuthRefill.Seconds())) + "\r\n"}
		case err != nil || !ok || r == nil || len(r.Connect.BasicAuth) == 0:
			return nil, connectRefusal{status: http.StatusProxyAuthRequired, header: "Proxy-Authenticate: Basic realm=\"rpmgr\", charset=\"UTF-8\"\r\n"}
		}
	}
	if r == nil || !r.Access.Allows(client) {
		return nil, connectRefusal{status: http.StatusForbidden}
	}
	return r, connectRefusal{}
}

// unknownUser is a rule no user passes, checked for an authority the listener does not know, so
// that it costs the same as a wrong password.
var unknownUser = []BasicAuthRule{{PolicyID: "-", CredentialVersion: "-", Users: map[string]PHC{}}}

// proxyBasicAuth parses a Proxy-Authorization header of the Basic scheme.
func proxyBasicAuth(h string) (user, password string, ok bool) {
	scheme, cred, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return "", "", false
	}
	return strings.Cut(string(b), ":")
}

// refuseConnect answers a CONNECT without a tunnel and closes the connection.
func refuseConnect(c net.Conn, r connectRefusal) {
	_ = c.SetWriteDeadline(time.Now().Add(httpReadHeader))
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n", r.status, http.StatusText(r.status), r.header)
	_ = c.Close()
}

// connectTLS is a TLS listener's configuration: that of http routes, with the certificate the
// gateway holds for the listener's name, or else its default one, which no client trusts.
func (t *TCPRoutes) connectTLS(hostname string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: httpCipherSuites,
		NextProtos:   []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if t.o.Certificates != nil {
				if c := t.o.Certificates.ForName(hostname); c != nil {
					return c, nil
				}
			}
			if t.o.Default != nil {
				return t.o.Default, nil
			}
			return nil, fmt.Errorf("no certificate for %q", hostname)
		},
	}
}

// clientAddr returns a connection's peer address, unmapped.
func clientAddr(c net.Conn) netip.Addr {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}
