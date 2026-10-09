// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/ids"
)

func access(t *testing.T, rules ...*agentv1.IPRule) gateway.Access {
	t.Helper()
	a, err := gateway.AccessOf(&agentv1.RouteAccess{IpRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func allow(cidrs ...string) *agentv1.IPRule { return &agentv1.IPRule{Allow: true, Cidrs: cidrs} }
func deny(cidrs ...string) *agentv1.IPRule  { return &agentv1.IPRule{Cidrs: cidrs} }

// TestAccess: the first matching rule decides; without a match a client is allowed only when no
// rule allows; IPv4-mapped addresses and CIDRs count as IPv4.
func TestAccess(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []*agentv1.IPRule
		ip    string
		want  bool
	}{
		{"no rules", nil, "203.0.113.7", true},
		{"deny list, listed", []*agentv1.IPRule{deny("203.0.113.0/24")}, "203.0.113.7", false},
		{"deny list, not listed", []*agentv1.IPRule{deny("203.0.113.0/24")}, "198.51.100.1", true},
		{"allow list, listed", []*agentv1.IPRule{allow("10.0.0.0/8")}, "10.1.2.3", true},
		{"allow list, not listed", []*agentv1.IPRule{allow("10.0.0.0/8")}, "198.51.100.1", false},
		{"deny before allow", []*agentv1.IPRule{deny("10.0.0.5/32"), allow("10.0.0.0/8")}, "10.0.0.5", false},
		{"allow before deny", []*agentv1.IPRule{allow("10.0.0.0/8"), deny("10.0.0.5/32")}, "10.0.0.5", true},
		{"deny then allow, other", []*agentv1.IPRule{deny("10.0.0.5/32"), allow("10.0.0.0/8")}, "192.0.2.1", false},
		{"IPv6", []*agentv1.IPRule{allow("2001:db8::/32")}, "2001:db8::1", true},
		{"IPv6 outside", []*agentv1.IPRule{allow("2001:db8::/32")}, "2001:db9::1", false},
		{"mapped client, IPv4 rule", []*agentv1.IPRule{deny("192.0.2.0/24")}, "::ffff:192.0.2.9", false},
		{"IPv4 client, mapped rule", []*agentv1.IPRule{deny("::ffff:192.0.2.0/120")}, "192.0.2.9", false},
		{"IPv4 rule never matches IPv6", []*agentv1.IPRule{deny("0.0.0.0/0")}, "2001:db8::1", true},
		{"several CIDRs in one rule", []*agentv1.IPRule{allow("192.0.2.0/24", "2001:db8::/32")}, "2001:db8::5", true},
	} {
		if got := access(t, tc.rules...).Allows(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	for name, rules := range map[string][]*agentv1.IPRule{
		"no CIDR":      {deny()},
		"not a CIDR":   {deny("10.0.0.1")},
		"garbage CIDR": {allow("10.0.0.0/33")},
	} {
		if _, err := gateway.AccessOf(&agentv1.RouteAccess{IpRules: rules}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a, b := access(t, deny("10.0.0.0/8")), access(t, deny("10.0.0.0/8"))
	if !a.Same(b) || a.Same(access(t, allow("10.0.0.0/8"))) || a.Same(access(t)) {
		t.Error("Same")
	}
}

// TestTCPRoutes_Access: a client the route's access rules deny is reset at once; tightening the
// rules resets the open connections they no longer allow, loosening them keeps every one.
func TestTCPRoutes_Access(t *testing.T) {
	p := newPlane(t, service(t, echoService), "rt_1")
	port := freePort(t)
	loopback := deny("127.0.0.0/8")
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port, Access: access(t, allow("10.0.0.0/8"))}})
	// The reset may come before the dial returns.
	if c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))); err == nil {
		defer func() { _ = c.Close() }()
		if ping(c, "denied") == nil {
			t.Fatal("a client outside the allow list was served")
		}
	} else if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatal(err)
	}
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port, Access: access(t, deny("192.0.2.0/24"))}})
	c := dialPort(t, port)
	if err := ping(c, "allowed"); err != nil {
		t.Fatal(err)
	}
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port, Access: access(t, deny("192.0.2.0/24", "198.51.100.0/24"))}})
	if err := ping(c, "a tightening that does not concern the client"); err != nil {
		t.Fatal(err)
	}
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port, Access: access(t, loopback)}})
	if err := ping(c, "after tightening"); err == nil {
		t.Fatal("a connection the tightened rules deny went on")
	}
}

// TestPassthrough_Access: a passthrough client the rules deny is reset; tightening resets the
// open connections they no longer allow.
func TestPassthrough_Access(t *testing.T) {
	addr, pool := backend(t, "db.example.com")
	p := newPlaneWith(t, addr, "none", "rt_db")
	pass := gateway.NewPassthrough(p.sessions, nil, nil)
	t.Cleanup(pass.Close)
	def, err := gateway.DefaultTLS()
	if err != nil {
		t.Fatal(err)
	}
	front := serve(t, &gateway.Router{TrustDomain: td, GatewayID: "gw_01", Routes: pass, DefaultTLS: def})
	route := gateway.PassthroughRoute{ID: "rt_db", Hostnames: []string{"db.example.com"}, Access: access(t, deny("127.0.0.0/8"))}
	pass.Apply([]gateway.PassthroughRoute{route})
	dial := func() (*tls.Conn, error) {
		return tls.Dial("tcp", front, &tls.Config{ServerName: "db.example.com", RootCAs: pool, MinVersion: tls.VersionTLS13})
	}
	if c, err := dial(); err == nil {
		_ = c.Close()
		t.Fatal("a denied client was passed through")
	}
	route.Access = access(t)
	pass.Apply([]gateway.PassthroughRoute{route})
	var c *tls.Conn
	eventually(t, "no passthrough", func() bool {
		var err error
		c, err = dial()
		return err == nil
	})
	defer func() { _ = c.Close() }()
	route.Access = access(t, allow("10.0.0.0/8"))
	pass.Apply([]gateway.PassthroughRoute{route})
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Write([]byte("x"))
	if err == nil {
		_, err = io.ReadFull(c, make([]byte, 1))
	}
	if err == nil {
		t.Fatal("a connection the tightened rules deny went on")
	}
}

// TestUDPRoutes_Access: a client the rules deny opens no flow, counted as a policy drop;
// tightening ends the flows they no longer allow.
func TestUDPRoutes_Access(t *testing.T) {
	route := ids.New("rt")
	m := newSessions(&assignment{known: map[string]bool{cid("udp-acl"): true}, routes: map[string][]string{route: {cid("udp-acl")}}}, nil)
	t.Cleanup(m.Close)
	start(t, m, connectorID("udp-acl"), hello(route))
	u, addr, reg := udpGateway(t, m, route, time.Minute)
	port := uint16(addr.Port) //nolint:gosec // G115: a port
	u.Apply([]gateway.UDPRoute{{ID: route, Port: port, FlowIdle: time.Minute, Access: access(t, deny("127.0.0.0/8"))}})
	c := client(t)
	if _, err := c.WriteToUDP([]byte("x"), addr); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the denied datagram was not counted", func() bool {
		return counter(t, reg, "rpmgr_udp_datagrams_dropped_total", map[string]string{"route": route, "reason": "policy"}) == 1
	})
	if u.Flows() != 0 {
		t.Fatalf("%d flows for a denied client", u.Flows())
	}
	u.Apply([]gateway.UDPRoute{{ID: route, Port: port, FlowIdle: time.Minute}})
	exchange(t, c, addr, []byte("allowed"))
	u.Apply([]gateway.UDPRoute{{ID: route, Port: port, FlowIdle: time.Minute, Access: access(t, allow("10.0.0.0/8"))}})
	if u.Flows() != 0 {
		t.Fatalf("%d flows after tightening", u.Flows())
	}
}

// TestHTTPRoutes_Access: a client the rules deny gets 403; behind a trusted proxy the client is the
// last untrusted address of X-Forwarded-For; tightening cancels the requests it no longer allows,
// an upgraded connection included.
func TestHTTPRoutes_Access(t *testing.T) {
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", WebSocket: true, Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
		Access: access(t, deny("127.0.0.0/8"))}
	e := newHTTPEnv(t, websocketEcho, route)
	if r := get(t, e.client(false), "https://app.example.com/", nil); r.status != http.StatusForbidden {
		t.Fatalf("a denied client: %d", r.status)
	}
	route.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	route.Access = access(t, allow("203.0.113.0/24"))
	e.routes.Apply([]gateway.HTTPRoute{route})
	for xff, want := range map[string]int{
		"203.0.113.9":             http.StatusBadRequest, // allowed: the upstream answers a plain GET with 400
		"198.51.100.1":            http.StatusForbidden,
		"203.0.113.9, 127.0.0.2":  http.StatusBadRequest, // a trusted hop is skipped
		"203.0.113.9, 192.0.2.66": http.StatusForbidden,  // the last untrusted hop decides
		"not an address":          http.StatusForbidden,
	} {
		if r := get(t, e.client(false), "https://app.example.com/", http.Header{"X-Forwarded-For": {xff}}); r.status != want {
			t.Errorf("X-Forwarded-For %q: %d, want %d", xff, r.status, want)
		}
	}
	route.TrustedProxies, route.Access = nil, access(t)
	e.routes.Apply([]gateway.HTTPRoute{route})
	c, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: "app.example.com", RootCAs: e.pool, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = c.Write([]byte("GET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v", resp.Status)
	}
	route.Access = access(t, deny("127.0.0.0/8"))
	e.routes.Apply([]gateway.HTTPRoute{route})
	// Apply closes the connection soon, not before it returns: bytes already on their way may still
	// arrive, but the connection must end within the deadline.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("x"))
	_, err = io.Copy(io.Discard, br)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("an upgraded connection the tightened rules deny went on")
	}
}
