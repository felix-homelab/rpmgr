// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	mode     ConnectMode
	hostname string
	routes   map[string]*TCPRoute
}

func newConnectTable(routes []TCPRoute) *connectTable {
	t := &connectTable{mode: routes[0].Connect.Mode, hostname: routes[0].Connect.Hostname, routes: map[string]*TCPRoute{}}
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

// same reports whether u serves the clients of t as t does: the same mode, name and routes, so a
// connection admitted under t is admitted under u. Access rules are checked by enforce.
func (t *connectTable) same(u *connectTable) bool {
	if t.mode != u.mode || t.hostname != u.hostname || len(t.routes) != len(u.routes) {
		return false
	}
	for a, r := range t.routes {
		if v, ok := u.routes[a]; !ok || v.ID != r.ID || !sameRules(v.Connect.BasicAuth, r.Connect.BasicAuth) {
			return false
		}
	}
	return true
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
// form, which chooses a route of the listener by its host, is checked against the route's access
// rules and, in a basic mode, its credentials, and is answered 200 once a stream to a connector
// is open; then the connection is relayed over the stream. Anything else is answered and closed:
// the head is read within the HTTP server's header timeout and up to connectHeadMax, and a
// request with a body, data sent after the head before the answer, or a Host other than the
// authority is refused, so no second request can hide behind the first.
func (t *TCPRoutes) handleConnect(c net.Conn, pl *portListener, table *connectTable) {
	_ = c.SetDeadline(time.Now().Add(httpReadHeader))
	conn := c
	if table.mode == ConnectTLSBasic {
		tc := tls.Server(c, t.connectTLS(table.hostname))
		if err := tc.HandshakeContext(t.ctx); err != nil {
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
	r, refusal := t.admit(req, br, clientAddr(c), table)
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
	st, err := openStream(t.ctx, t.o.Sessions, t.o.Revision, c, r.ID, "")
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
	relayConn(st, conn, r.IdleTimeout)
}

// connectHead is the head of a request to a CONNECT listener.
type connectHead struct {
	method, target, proto string
	header                textproto.MIMEHeader
}

// readConnectHead reads a request's line and header fields as they came; net/http's ReadRequest
// would drop the Host field, which must match the authority.
func readConnectHead(br *bufio.Reader) (*connectHead, error) {
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return nil, errors.New("gateway: not a request line")
	}
	h, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	return &connectHead{method: parts[0], target: parts[1], proto: parts[2], header: h}, nil
}

// admit checks a CONNECT request and returns its route, or the refusal.
func (t *TCPRoutes) admit(req *connectHead, br *bufio.Reader, client netip.Addr, table *connectTable) (*TCPRoute, connectRefusal) {
	target := req.target
	host, _, err := net.SplitHostPort(target)
	hosts := req.header.Values("Host")
	switch {
	case req.method != http.MethodConnect:
		return nil, connectRefusal{status: http.StatusMethodNotAllowed, header: "Allow: CONNECT\r\n"}
	case req.proto != "HTTP/1.1" && req.proto != "HTTP/1.0", !authorityRe.MatchString(target), err != nil, host == "":
		return nil, connectRefusal{status: http.StatusBadRequest}
	case len(req.header.Values("Content-Length")) > 0 || len(req.header.Values("Transfer-Encoding")) > 0 || br.Buffered() > 0:
		// A body, or bytes sent before the answer, could be read as a second request.
		return nil, connectRefusal{status: http.StatusBadRequest}
	case len(hosts) > 1 || len(hosts) == 1 && !strings.EqualFold(hosts[0], target):
		return nil, connectRefusal{status: http.StatusBadRequest}
	}
	r := table.routes[strings.TrimSuffix(strings.ToLower(host), ".")]
	if r == nil || !r.Access.Allows(client) {
		// The same answer for an authority the listener does not know and one whose rules refuse
		// the client, so a client learns nothing of the listener's other routes.
		return nil, connectRefusal{status: http.StatusForbidden}
	}
	if table.mode == ConnectTLSBasic || table.mode == ConnectPlainBasic {
		user, password, given := proxyBasicAuth(req.header.Get("Proxy-Authorization"))
		ok := false
		if given && len(r.Connect.BasicAuth) > 0 {
			ok, err = t.basic.Check(t.ctx, client, r.Connect.BasicAuth, user, password)
		}
		switch {
		case errors.Is(err, ErrRateLimited):
			return nil, connectRefusal{status: http.StatusTooManyRequests, header: "Retry-After: " + strconv.Itoa(int(basicAuthRefill.Seconds())) + "\r\n"}
		case err != nil || !ok:
			return nil, connectRefusal{status: http.StatusProxyAuthRequired, header: "Proxy-Authenticate: Basic realm=\"rpmgr\", charset=\"UTF-8\"\r\n"}
		}
	}
	return r, connectRefusal{}
}

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
