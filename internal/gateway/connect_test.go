// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// rawEcho is a service that echoes what it gets, with nothing in front.
func rawEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// connectRoute is a route of org_a's CONNECT listener on port.
func connectRoute(id string, port uint16, mode gateway.ConnectMode, authorities ...string) gateway.TCPRoute {
	return gateway.TCPRoute{ID: id, Port: port, Connect: &gateway.Connect{Org: "org_a", Authorities: authorities, Mode: mode}}
}

// connectHead sends head on c and returns the status line and headers of the answer, with what
// the answer leaves of the connection to read.
func connectHead(t *testing.T, c net.Conn, head string) (answer, *bufio.Reader) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, head); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("no answer to %q: %v", head, err)
	}
	_ = resp.Body.Close() // empty: a refusal has none, and a tunnel's bytes are read from br
	return answer{StatusCode: resp.StatusCode, Header: resp.Header}, br
}

// answer is the status and header of an answer to a CONNECT.
type answer struct {
	StatusCode int
	Header     http.Header
}

// tunnelEcho checks that a tunnel carries bytes both ways and that nothing of the CONNECT head
// reached the service, which echoes what it gets.
func tunnelEcho(t *testing.T, c net.Conn, br *bufio.Reader) {
	t.Helper()
	if _, err := io.WriteString(c, "ping"); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(br, b); err != nil || string(b) != "ping" {
		t.Fatalf("the tunnel echoed %q, %v", b, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _ := br.Read(make([]byte, 64)); n != 0 {
		t.Fatal("the service got more than the tunnel's data")
	}
	_ = c.SetReadDeadline(time.Time{})
}

func basicHeader(user, password string) string {
	return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)) + "\r\n"
}

// TestHTTPConnect_OnlyOwnAuthorities (security regression, docs/12): a CONNECT listener routes
// only to the authorities of its own org's routes, whatever the CONNECT's port and case; another
// org's authority, of a listener on the same gateway, and an unknown one are refused alike, and a
// request that is no CONNECT too; nothing of the CONNECT head, Proxy-Authorization included,
// reaches a target; a TLS listener refuses a plain CONNECT.
func TestHTTPConnect_OnlyOwnAuthorities(t *testing.T) {
	p := newPlaneWith(t, rawEcho(t), "none", "rt_a", "rt_b", "rt_c")
	own, other := freePort(t), freePort(t)
	c := connectRoute("rt_c", other, gateway.ConnectNone, "c.internal")
	c.Connect.Org = "org_b"
	if st := p.routes.Apply([]gateway.TCPRoute{connectRoute("rt_a", own, gateway.ConnectNone, "a.internal", "db.internal"),
		connectRoute("rt_b", own, gateway.ConnectNone, "b.internal"), c}); len(st) != 0 {
		t.Fatal(st)
	}
	for _, authority := range []string{"a.internal:22", "DB.Internal:5432", "b.internal:1", "a.internal.:443"} {
		c := dialPort(t, own)
		resp, br := connectHead(t, c, "CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n"+basicHeader("ada", "secret")+"\r\n")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", authority, resp.StatusCode)
		}
		tunnelEcho(t, c, br)
	}
	for _, tc := range []struct{ name, head string }{
		{"another org's authority", "CONNECT c.internal:22 HTTP/1.1\r\n\r\n"},
		{"an unknown authority", "CONNECT nowhere.internal:22 HTTP/1.1\r\n\r\n"},
		{"an IP address", "CONNECT 127.0.0.1:22 HTTP/1.1\r\n\r\n"},
		{"an IPv6 address", "CONNECT [::1]:22 HTTP/1.1\r\n\r\n"},
	} {
		if resp, _ := connectHead(t, dialPort(t, own), tc.head); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", tc.name, resp.StatusCode)
		}
	}
	for _, method := range []string{"GET", "connect"} { // methods compare with case
		if resp, _ := connectHead(t, dialPort(t, own), method+" a.internal:22 HTTP/1.1\r\n\r\n"); resp.StatusCode != http.StatusMethodNotAllowed ||
			resp.Header.Get("Allow") != "CONNECT" {
			t.Errorf("%s: %d %v", method, resp.StatusCode, resp.Header)
		}
	}
	// A TLS listener answers no plain CONNECT.
	tlsPort := freePort(t)
	r := connectRoute("rt_a", tlsPort, gateway.ConnectTLSBasic, "a.internal")
	r.Connect.Hostname = "proxy.example.com"
	p.routes.Apply([]gateway.TCPRoute{r})
	tc := dialPort(t, tlsPort)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(tc, "CONNECT a.internal:22 HTTP/1.1\r\n\r\n")
	if b, _ := io.ReadAll(tc); strings.HasPrefix(string(b), "HTTP/1.1 200") {
		t.Fatalf("a plain CONNECT on a TLS listener: %q", b)
	}
}

// TestHTTPConnect_RefusesSmuggling: a CONNECT head that is not one strict request in authority
// form without a body is refused, so no second request can hide behind the first.
func TestHTTPConnect_RefusesSmuggling(t *testing.T) {
	p := newPlaneWith(t, rawEcho(t), "none", "rt_a")
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{connectRoute("rt_a", port, gateway.ConnectNone, "a.internal")})
	for _, tc := range []struct{ name, head string }{
		{"absolute form", "CONNECT http://a.internal:22/ HTTP/1.1\r\n\r\n"},
		{"a path", "CONNECT /a.internal:22 HTTP/1.1\r\n\r\n"},
		{"no port", "CONNECT a.internal HTTP/1.1\r\n\r\n"},
		{"userinfo", "CONNECT x@a.internal:22 HTTP/1.1\r\n\r\n"},
		{"another Host", "CONNECT a.internal:22 HTTP/1.1\r\nHost: b.internal:22\r\n\r\n"},
		{"a body", "CONNECT a.internal:22 HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"},
		{"a chunked body", "CONNECT a.internal:22 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
		{"two Host headers", "CONNECT a.internal:22 HTTP/1.1\r\nHost: a.internal:22\r\nHost: a.internal:22\r\n\r\n"},
		{"HTTP/2.0", "CONNECT a.internal:22 HTTP/2.0\r\n\r\n"},
		{"a bare LF", "CONNECT a.internal:22 HTTP/1.1\nHost: a.internal:22\r\n\r\n"},
		{"a folded line", "CONNECT a.internal:22 HTTP/1.1\r\nX-A: 1\r\n 2\r\n\r\n"},
		{"a NUL", "CONNECT a.internal:22 HTTP/1.1\r\nX-A: 1\x002\r\n\r\n"},
		{"a space before the colon", "CONNECT a.internal:22 HTTP/1.1\r\nHost : b.internal:22\r\n\r\n"},
		{"too many fields", "CONNECT a.internal:22 HTTP/1.1\r\n" + strings.Repeat("X-A: 1\r\n", 101) + "\r\n"},
		{"a head too long", "CONNECT a.internal:22 HTTP/1.1\r\n" + strings.Repeat("X-Pad: "+strings.Repeat("a", 1000)+"\r\n", 20) + "\r\n"},
	} {
		c := dialPort(t, port)
		resp, _ := connectHead(t, c, tc.head)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", tc.name, resp.StatusCode)
		}
	}
}

// TestHTTPConnect_SlowHead: a client that does not finish its CONNECT head within the HTTP header
// timeout is cut off.
func TestHTTPConnect_SlowHead(t *testing.T) {
	gateway.SetHTTPTimers(t, 300*time.Millisecond, time.Second)
	p := newPlaneWith(t, rawEcho(t), "none", "rt_a")
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{connectRoute("rt_a", port, gateway.ConnectNone, "a.internal")})
	c := dialPort(t, port)
	_, _ = io.WriteString(c, "CONNECT a.internal:22 HTTP/1.1\r\nX-Slow: ")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, _ = io.ReadAll(c)
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("a slow head held the connection for %v", waited)
	}
}

// TestHTTPConnect_BasicAuth: in a basic mode a CONNECT without credentials, with wrong ones, or
// to a route without users is 407 with Proxy-Authenticate; the right ones open the tunnel; in the
// mode none credentials are neither needed nor checked.
func TestHTTPConnect_BasicAuth(t *testing.T) {
	p := newPlaneWith(t, rawEcho(t), "none", "rt_a", "rt_b")
	port := freePort(t)
	a := connectRoute("rt_a", port, gateway.ConnectPlainBasic, "a.internal")
	a.Connect.BasicAuth = []gateway.BasicAuthRule{rule(t, "pol_1", "1", "ada", "correct horse")}
	b := connectRoute("rt_b", port, gateway.ConnectPlainBasic, "b.internal") // no users: nobody passes
	p.routes.Apply([]gateway.TCPRoute{a, b})
	for _, tc := range []struct {
		name, head string
		want       int
	}{
		{"no credentials", "CONNECT a.internal:22 HTTP/1.1\r\n\r\n", http.StatusProxyAuthRequired},
		{"a wrong password", "CONNECT a.internal:22 HTTP/1.1\r\n" + basicHeader("ada", "wrong") + "\r\n", http.StatusProxyAuthRequired},
		{"an unknown user", "CONNECT a.internal:22 HTTP/1.1\r\n" + basicHeader("bob", "correct horse") + "\r\n", http.StatusProxyAuthRequired},
		{"another scheme", "CONNECT a.internal:22 HTTP/1.1\r\nProxy-Authorization: Bearer x\r\n\r\n", http.StatusProxyAuthRequired},
		{"a route without users", "CONNECT b.internal:22 HTTP/1.1\r\n" + basicHeader("ada", "correct horse") + "\r\n", http.StatusProxyAuthRequired},
	} {
		resp, _ := connectHead(t, dialPort(t, port), tc.head)
		if resp.StatusCode != tc.want || !strings.HasPrefix(resp.Header.Get("Proxy-Authenticate"), "Basic") {
			t.Errorf("%s: %d %v", tc.name, resp.StatusCode, resp.Header)
		}
	}
	c := dialPort(t, port)
	resp, br := connectHead(t, c, "CONNECT a.internal:22 HTTP/1.1\r\n"+basicHeader("ada", "correct horse")+"\r\n")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the right credentials: %d", resp.StatusCode)
	}
	tunnelEcho(t, c, br)
}

// TestHTTPConnect_TLSListener: a TLS listener presents the certificate of its hostname and opens
// the tunnel inside TLS for the right credentials.
func TestHTTPConnect_TLSListener(t *testing.T) {
	p := newPlaneWith(t, rawEcho(t), "none", "rt_a")
	certs, pool := routeCert(t, "proxy.example.com")
	routes := gateway.NewTCPRoutes(gateway.TCPOptions{Host: "127.0.0.1", Sessions: p.sessions, Certificates: certs,
		Revision: func() *agentv1.Revision { return &agentv1.Revision{Seq: 7} }})
	t.Cleanup(routes.Close)
	port := freePort(t)
	r := connectRoute("rt_a", port, gateway.ConnectTLSBasic, "a.internal")
	r.Connect.Hostname, r.Connect.BasicAuth = "proxy.example.com", []gateway.BasicAuthRule{rule(t, "pol_1", "1", "ada", "correct horse")}
	if st := routes.Apply([]gateway.TCPRoute{r}); len(st) != 0 {
		t.Fatal(st)
	}
	c, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))),
		&tls.Config{RootCAs: pool, ServerName: "proxy.example.com", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if resp, _ := connectHead(t, c, "CONNECT a.internal:22 HTTP/1.1\r\n\r\n"); resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("no credentials over TLS: %d", resp.StatusCode)
	}
	c, err = tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))),
		&tls.Config{RootCAs: pool, ServerName: "proxy.example.com", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	resp, br := connectHead(t, c, "CONNECT a.internal:22 HTTP/1.1\r\n"+basicHeader("ada", "correct horse")+"\r\n")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the right credentials over TLS: %d", resp.StatusCode)
	}
	tunnelEcho(t, c, br)
}

// TestHTTPConnect_AccessAndChanges: a route's IP rules refuse a client with 403 before any
// stream; a tightened rule resets an open tunnel of the route, and a removed route's tunnel ends,
// while another route's tunnel on the listener stays open; a listener of another org on the port
// ends every tunnel.
func TestHTTPConnect_AccessAndChanges(t *testing.T) {
	p := newPlaneWith(t, rawEcho(t), "none", "rt_a", "rt_b")
	port := freePort(t)
	deny, err := gateway.AccessOf(&agentv1.RouteAccess{IpRules: []*agentv1.IPRule{{Cidrs: []string{"127.0.0.0/8"}}}})
	if err != nil {
		t.Fatal(err)
	}
	a, b := connectRoute("rt_a", port, gateway.ConnectNone, "a.internal"), connectRoute("rt_b", port, gateway.ConnectNone, "b.internal")
	denied := a
	denied.Access = deny
	p.routes.Apply([]gateway.TCPRoute{denied, b})
	if resp, _ := connectHead(t, dialPort(t, port), "CONNECT a.internal:22 HTTP/1.1\r\n\r\n"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a denied client: %d", resp.StatusCode)
	}
	p.routes.Apply([]gateway.TCPRoute{a, b})
	open := func(authority string) (net.Conn, *bufio.Reader) {
		c := dialPort(t, port)
		resp, br := connectHead(t, c, "CONNECT "+authority+" HTTP/1.1\r\n\r\n")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", authority, resp.StatusCode)
		}
		_ = c.SetDeadline(time.Time{})
		return c, br
	}
	ca, bra := open("a.internal:22")
	cb, brb := open("b.internal:22")
	tunnelEcho(t, ca, bra)
	p.routes.Apply([]gateway.TCPRoute{denied, b})
	_ = ca.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := bra.ReadByte(); err == nil {
		t.Fatal("a tunnel the tightened rule refuses stayed open")
	}
	tunnelEcho(t, cb, brb)
	p.routes.Apply([]gateway.TCPRoute{a, b})
	ca, bra = open("a.internal:22")
	p.routes.Apply([]gateway.TCPRoute{b}) // rt_a goes
	_ = ca.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := bra.ReadByte(); err == nil {
		t.Fatal("the tunnel of a removed route stayed open")
	}
	tunnelEcho(t, cb, brb)
	other := b
	other.Connect = &gateway.Connect{Org: "org_b", Authorities: b.Connect.Authorities, Mode: b.Connect.Mode}
	p.routes.Apply([]gateway.TCPRoute{other})
	_ = cb.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := brb.ReadByte(); err == nil {
		t.Fatal("a tunnel stayed open after its listener became another org's")
	}
}

// TestApplier_ValidateConnect: CONNECT routes share a port only with the same mode and hostname
// and other authorities, never with a plain tcp route; their authorities are lower-case host
// names; a TLS listener names a hostname and only it; basic auth needs a basic mode.
func TestApplier_ValidateConnect(t *testing.T) {
	a, _ := gateway.NewApplier()
	route := func(id string, port uint32, auth agentv1.ConnectAuth, hostname string, authorities ...string) *agentv1.Resource {
		return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_GatewayTcpRoute{GatewayTcpRoute: &agentv1.GatewayTCPRoute{Port: port,
			HttpConnect: &agentv1.HTTPConnect{Auth: auth, Hostname: hostname, Authorities: authorities, OrgId: "org_a"}}}}
	}
	withUsers := func(res *agentv1.Resource) *agentv1.Resource {
		res.GetGatewayTcpRoute().Access = &agentv1.RouteAccess{BasicAuth: []*agentv1.BasicAuthRule{{PolicyId: "pol_1", CredentialVersion: "1",
			Users: []*rpmgrv1.BasicAuthUser{{Name: "ada", PasswordHash: phc(t, "x", 8, 1)}}}}}
		return res
	}
	none, tlsBasic, plainBasic := agentv1.ConnectAuth_CONNECT_AUTH_NONE, agentv1.ConnectAuth_CONNECT_AUTH_TLS_BASIC, agentv1.ConnectAuth_CONNECT_AUTH_PLAIN_BASIC
	ok := gatewaySnapshot(1, route("rt_1", 7000, none, "", "a.internal", "b.internal"), route("rt_2", 7000, agentv1.ConnectAuth_CONNECT_AUTH_UNSPECIFIED, "", "c.internal"),
		withUsers(route("rt_3", 7001, tlsBasic, "proxy.example.com", "a.internal")), withUsers(route("rt_4", 7002, plainBasic, "", "a.internal")))
	if errs := a.Validate(ok); len(errs) != 0 {
		t.Fatal(errs)
	}
	for _, tc := range []struct {
		name string
		snap *agentv1.Snapshot
		want string
	}{
		{"another mode on the port", gatewaySnapshot(1, route("rt_1", 7000, none, "", "a.internal"), route("rt_2", 7000, plainBasic, "", "b.internal")),
			"another mode or hostname"},
		{"another hostname on the port", gatewaySnapshot(1, route("rt_1", 7000, tlsBasic, "p.example.com", "a.internal"),
			route("rt_2", 7000, tlsBasic, "q.example.com", "b.internal")), "another mode or hostname"},
		{"an authority twice on a port", gatewaySnapshot(1, route("rt_1", 7000, none, "", "a.internal"), route("rt_2", 7000, none, "", "a.internal")),
			"also a route of rt_1"},
		{"a plain route on the port", gatewaySnapshot(1, route("rt_1", 7000, none, "", "a.internal"), tcpResource("rt_2", 7000)), "also the port of rt_1"},
		{"no authorities", gatewaySnapshot(1, route("rt_1", 7000, none, "")), "without authorities"},
		{"an upper-case authority", gatewaySnapshot(1, route("rt_1", 7000, none, "", "A.internal")), "not a lower-case host name"},
		{"an authority with a port", gatewaySnapshot(1, route("rt_1", 7000, none, "", "a.internal:22")), "not a lower-case host name"},
		{"TLS without a hostname", gatewaySnapshot(1, route("rt_1", 7000, tlsBasic, "", "a.internal")), "not normalised"},
		{"a hostname without TLS", gatewaySnapshot(1, route("rt_1", 7000, plainBasic, "p.example.com", "a.internal")), "hostname without TLS"},
		{"an unknown mode", gatewaySnapshot(1, route("rt_1", 7000, agentv1.ConnectAuth(9), "", "a.internal")), "authentication mode"},
		{"basic auth without a basic mode", gatewaySnapshot(1, withUsers(route("rt_1", 7000, none, "", "a.internal"))), "basic auth on a route"},
		{"two orgs on the port", gatewaySnapshot(1, route("rt_1", 7000, none, "", "a.internal"), func() *agentv1.Resource {
			r := route("rt_2", 7000, none, "", "b.internal")
			r.GetGatewayTcpRoute().GetHttpConnect().OrgId = "org_b"
			return r
		}()), "of another org"},
		{"no org", gatewaySnapshot(1, func() *agentv1.Resource {
			r := route("rt_1", 7000, none, "", "a.internal")
			r.GetGatewayTcpRoute().GetHttpConnect().OrgId = ""
			return r
		}()), "without an org"},
	} {
		errs := a.Validate(tc.snap)
		if len(errs) == 0 || !strings.Contains(errs[0].GetMessage(), tc.want) {
			t.Errorf("%s: %v, want an error about %q", tc.name, errs, tc.want)
		}
	}
}

// TestHTTPConnect_EarlyData: bytes a client sends along with its CONNECT head, before the answer,
// are the tunnel's first bytes, after the 200, never a second request; so is a second CONNECT.
func TestHTTPConnect_EarlyData(t *testing.T) {
	p := newPlaneWith(t, rawEcho(t), "none", "rt_a")
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{connectRoute("rt_a", port, gateway.ConnectNone, "a.internal")})
	for _, early := range []string{"SSH-2.0-early\r\n", "CONNECT b.internal:22 HTTP/1.1\r\n\r\n"} {
		c := dialPort(t, port)
		resp, br := connectHead(t, c, "CONNECT a.internal:22 HTTP/1.1\r\n\r\n"+early)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%q: %d", early, resp.StatusCode)
		}
		b := make([]byte, len(early))
		if _, err := io.ReadFull(br, b); err != nil || string(b) != early {
			t.Fatalf("the service got %q, %v; want %q", b, err, early)
		}
	}
}

// TestHTTPConnect_Answers: credentials of one route do not open another's; too many failed
// verifications from an address are 429; a route no connector serves is 503 with Retry-After; a
// CONNECT whose listener changed while its head was read is 503 too; a peer that no route of the
// listener admits is dropped without an answer; an unknown authority in a basic mode is 407 like
// a wrong password, and only right credentials meet the route's IP rules (403).
func TestHTTPConnect_Answers(t *testing.T) {
	p := newPlaneWith(t, rawEcho(t), "none", "rt_a", "rt_b")
	port := freePort(t)
	a := connectRoute("rt_a", port, gateway.ConnectPlainBasic, "a.internal")
	a.Connect.BasicAuth = []gateway.BasicAuthRule{rule(t, "pol_a", "1", "ada", "pw-a")}
	b := connectRoute("rt_b", port, gateway.ConnectPlainBasic, "b.internal")
	b.Connect.BasicAuth = []gateway.BasicAuthRule{rule(t, "pol_b", "1", "bob", "pw-b")}
	x := connectRoute("rt_x", port, gateway.ConnectPlainBasic, "x.internal") // the connector has no target for it
	x.Connect.BasicAuth = a.Connect.BasicAuth
	deny, err := gateway.AccessOf(&agentv1.RouteAccess{IpRules: []*agentv1.IPRule{{Cidrs: []string{"127.0.0.0/8"}}}})
	if err != nil {
		t.Fatal(err)
	}
	d := connectRoute("rt_d", port, gateway.ConnectPlainBasic, "d.internal")
	d.Connect.BasicAuth, d.Access = a.Connect.BasicAuth, deny
	p.routes.Apply([]gateway.TCPRoute{a, b, x, d})
	status := func(head string) answer {
		got, _ := connectHead(t, dialPort(t, port), head)
		return got
	}
	for _, tc := range []struct {
		name, head string
		want       int
	}{
		{"route A's credentials for route B", "CONNECT b.internal:22 HTTP/1.1\r\n" + basicHeader("ada", "pw-a") + "\r\n", http.StatusProxyAuthRequired},
		{"an unknown authority without credentials", "CONNECT nowhere.internal:22 HTTP/1.1\r\n\r\n", http.StatusProxyAuthRequired},
		{"an unknown authority with credentials", "CONNECT nowhere.internal:22 HTTP/1.1\r\n" + basicHeader("ada", "pw-a") + "\r\n", http.StatusProxyAuthRequired},
		{"an IP-denied route without credentials", "CONNECT d.internal:22 HTTP/1.1\r\n\r\n", http.StatusProxyAuthRequired},
		{"an IP-denied route with credentials", "CONNECT d.internal:22 HTTP/1.1\r\n" + basicHeader("ada", "pw-a") + "\r\n", http.StatusForbidden},
		{"no connector", "CONNECT x.internal:22 HTTP/1.1\r\n" + basicHeader("ada", "pw-a") + "\r\n", http.StatusServiceUnavailable},
	} {
		if got := status(tc.head); got.StatusCode != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got.StatusCode, tc.want)
		}
	}
	if got := status("CONNECT x.internal:22 HTTP/1.1\r\n" + basicHeader("ada", "pw-a") + "\r\n"); got.Header.Get("Retry-After") == "" {
		t.Error("503 without Retry-After")
	}
	// The listener changes while a head is read: the CONNECT is answered 503 and asked again.
	c := dialPort(t, port)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(c, "CONNECT a.internal:22 HTTP/1.1\r\n"+basicHeader("ada", "pw-a"))
	time.Sleep(100 * time.Millisecond)
	p.routes.Apply([]gateway.TCPRoute{a, b, x, d})
	if got, _ := connectHead(t, c, "\r\n"); got.StatusCode != http.StatusServiceUnavailable || got.Header.Get("Retry-After") != "1" {
		t.Errorf("a listener changed mid-head: %d %v", got.StatusCode, got.Header)
	}
	// Wrong passwords from one address run into the rate limit.
	limited := false
	for range 40 {
		if status("CONNECT a.internal:22 HTTP/1.1\r\n"+basicHeader("ada", "wrong")+"\r\n").StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("no 429 after 40 wrong passwords")
	}
	// A listener none of whose routes admits the peer drops it before reading anything.
	only := connectRoute("rt_a", port, gateway.ConnectNone, "a.internal")
	only.Access = deny
	p.routes.Apply([]gateway.TCPRoute{only})
	// The reset may already reach the dial.
	if dropped, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))); err == nil {
		t.Cleanup(func() { _ = dropped.Close() })
		_ = dropped.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.WriteString(dropped, "CONNECT a.internal:22 HTTP/1.1\r\n\r\n")
		if got, _ := io.ReadAll(dropped); len(got) != 0 {
			t.Errorf("a peer no route admits got an answer: %q", got)
		}
	}
}
