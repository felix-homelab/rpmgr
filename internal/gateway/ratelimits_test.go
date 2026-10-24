// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/ids"
)

// TestRouteLimit_Rates (docs/03-connections.md, "Route limits", "Access policies"): the route's
// total rate and each per-client rule refuse what comes over them, with the time to wait and which
// one refused; a client is an IPv4 address or an IPv6 /64; a rule that stays keeps its clients'
// buckets across snapshots, and a changed one starts anew.
func TestRouteLimit_Rates(t *testing.T) {
	var ls gateway.Limits
	lim := ls.Set("rt_1", gateway.RouteLimits{RequestsPerSecond: 2})
	a := netip.MustParseAddr("198.51.100.1")
	for i := range 2 {
		if ok, _, _ := lim.Admit(a); !ok {
			t.Fatalf("request %d of the route's burst refused", i+1)
		}
	}
	if ok, wait, perClient := lim.Admit(netip.MustParseAddr("198.51.100.2")); ok || perClient || wait <= 0 || wait > 500*time.Millisecond {
		t.Fatalf("over the route's rate: %t, wait %s, per client %t", ok, wait, perClient)
	}

	rule := gateway.ClientRate{Policy: "pol_1", PerSecond: 1, Burst: 2}
	ls.Set("rt_1", gateway.RouteLimits{Clients: []gateway.ClientRate{rule}})
	for i := range 2 {
		if ok, _, _ := lim.Admit(a); !ok {
			t.Fatalf("request %d of the client's burst refused", i+1)
		}
	}
	if ok, wait, perClient := lim.Admit(a); ok || !perClient || wait <= 0 || wait > time.Second {
		t.Fatalf("over the client's rate: %t, wait %s, per client %t", ok, wait, perClient)
	}
	if ok, _, _ := lim.Admit(netip.MustParseAddr("::ffff:198.51.100.1")); ok {
		t.Fatal("the IPv4-mapped form of the address escaped the rule")
	}
	if ok, _, _ := lim.Admit(netip.MustParseAddr("198.51.100.3")); !ok {
		t.Fatal("another client shares the bucket")
	}
	v6 := []netip.Addr{netip.MustParseAddr("2001:db8:1:2::1"), netip.MustParseAddr("2001:db8:1:2::2"), netip.MustParseAddr("2001:db8:1:2:ffff::3")}
	for i, ip := range v6 {
		if ok, _, _ := lim.Admit(ip); ok != (i < 2) {
			t.Fatalf("address %d of one /64: admitted %t", i+1, ok)
		}
	}
	if ok, _, _ := lim.Admit(netip.MustParseAddr("2001:db8:1:3::1")); !ok {
		t.Fatal("another /64 shares the bucket")
	}

	ls.Set("rt_1", gateway.RouteLimits{MaxConnections: 5, Clients: []gateway.ClientRate{rule}})
	if ok, _, _ := lim.Admit(a); ok {
		t.Fatal("a snapshot that kept the rule refilled the client's bucket")
	}
	ls.Set("rt_1", gateway.RouteLimits{Clients: []gateway.ClientRate{{Policy: "pol_1", PerSecond: 1, Burst: 3}}})
	if ok, _, _ := lim.Admit(a); !ok {
		t.Fatal("a changed rule kept the old buckets")
	}
	var none *gateway.RouteLimit
	if ok, _, _ := none.Admit(a); !ok {
		t.Fatal("no state refused a request")
	}
}

// TestRateLimit_ClientAddressNotSpoofable: a per-client rate limit keys on the TCP peer, so a
// client cannot escape it with its own X-Forwarded-For, and on the forwarded address only from a
// trusted proxy; a request over it is 429 with Retry-After. A full key table refuses new addresses
// and keeps limiting the ones it holds (docs/03-connections.md, "Access policies").
func TestRateLimit_ClientAddressNotSpoofable(t *testing.T) {
	gateway.SetClientKeys(t, 2)
	var ls gateway.Limits
	limits := gateway.RouteLimits{Clients: []gateway.ClientRate{{Policy: "pol_1", PerSecond: 1, Burst: 1}}}
	route := gateway.HTTPRoute{ID: "rt_rate", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
		Limit: ls.Set("rt_rate", limits)}
	e := newHTTPEnv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), route)
	from := func(addr string) reply {
		return get(t, e.client(false), "https://app.example.com/", http.Header{"X-Forwarded-For": {addr}})
	}
	if r := from("203.0.113.1"); r.status != http.StatusOK {
		t.Fatalf("the first request: %d", r.status)
	}
	r := from("203.0.113.2")
	if r.status != http.StatusTooManyRequests || r.header.Get("Retry-After") != "1" {
		t.Fatalf("a spoofed X-Forwarded-For: %d, Retry-After %q", r.status, r.header.Get("Retry-After"))
	}

	route.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	route.Limit = ls.Set("rt_rate", gateway.RouteLimits{Clients: []gateway.ClientRate{{Policy: "pol_2", PerSecond: 1, Burst: 1}}})
	e.routes.Apply([]gateway.HTTPRoute{route})
	for _, c := range []string{"203.0.113.1", "203.0.113.2"} {
		if r := from(c); r.status != http.StatusOK {
			t.Fatalf("%s through a trusted proxy: %d", c, r.status)
		}
	}
	if r := from("203.0.113.1"); r.status != http.StatusTooManyRequests {
		t.Fatalf("the same client again through a trusted proxy: %d", r.status)
	}
	if r := from("203.0.113.3"); r.status != http.StatusTooManyRequests {
		t.Fatalf("a new address with the key table full: %d", r.status)
	}
	if r := from("203.0.113.2"); r.status != http.StatusTooManyRequests {
		t.Fatalf("a held address after the table filled: %d", r.status)
	}
}

// TestHTTPRoutes_RequestRate: requests over the route's total rate are 429 with Retry-After.
func TestHTTPRoutes_RequestRate(t *testing.T) {
	var ls gateway.Limits
	route := gateway.HTTPRoute{ID: "rt_rps", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
		Limit: ls.Set("rt_rps", gateway.RouteLimits{RequestsPerSecond: 2})}
	e := newHTTPEnv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), route)
	c := e.client(true)
	codes := map[int]int{}
	var retry string
	for range 5 {
		r := get(t, c, "https://app.example.com/", nil)
		codes[r.status]++
		if r.status == http.StatusTooManyRequests {
			retry = r.header.Get("Retry-After")
		}
	}
	if codes[http.StatusOK] < 2 || codes[http.StatusTooManyRequests] == 0 || retry != "1" {
		t.Fatalf("5 requests at 2 per second: %v, Retry-After %q", codes, retry)
	}
}

// TestTCPRoutes_RequestRate: a connection over the route's rate of new connections is reset.
func TestTCPRoutes_RequestRate(t *testing.T) {
	p := newPlane(t, service(t, echoService), "rt_1")
	var ls gateway.Limits
	port := freePort(t)
	p.routes.Apply([]gateway.TCPRoute{{ID: "rt_1", Port: port, Limit: ls.Set("rt_1", gateway.RouteLimits{RequestsPerSecond: 1})}})
	if err := ping(dialPort(t, port), "first"); err != nil {
		t.Fatal(err)
	}
	if err := reset(port); err != nil {
		t.Fatalf("a connection over the rate: %v", err)
	}
}

// TestUDPRoutes_RequestRate: a new flow over a client's rate is dropped and counted as
// "rate_limit", one over the route's rate as "limit"; flows already open go on.
func TestUDPRoutes_RequestRate(t *testing.T) {
	route := ids.New("rt")
	m := newSessions(&assignment{known: map[string]bool{cid("udp-rate"): true}, routes: map[string][]string{route: {cid("udp-rate")}}}, nil)
	t.Cleanup(m.Close)
	start(t, m, connectorID("udp-rate"), hello(route))
	u, addr, reg := udpGateway(t, m, route, time.Minute)
	var ls gateway.Limits
	lim := ls.Set(route, gateway.RouteLimits{Clients: []gateway.ClientRate{{Policy: "pol_1", PerSecond: 1, Burst: 1}}})
	port := uint16(addr.Port) //nolint:gosec // G115: a port
	u.Apply([]gateway.UDPRoute{{ID: route, Port: port, FlowIdle: time.Minute, Limit: lim}})
	dropped := func(reason string) float64 {
		return counter(t, reg, "rpmgr_udp_datagrams_dropped_total", map[string]string{"route": route, "reason": reason})
	}
	a, b := client(t), client(t) // one client address, 127.0.0.1, on two ports
	exchange(t, a, addr, []byte("a"))
	if _, err := b.WriteToUDP([]byte("b"), addr); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a second flow of the client was not dropped", func() bool { return dropped("rate_limit") == 1 })
	exchange(t, a, addr, []byte("a again"))

	ls.Set(route, gateway.RouteLimits{RequestsPerSecond: 1})
	time.Sleep(time.Second) // the route's bucket starts full; let one second pass for b
	exchange(t, b, addr, []byte("b"))
	if _, err := client(t).WriteToUDP([]byte("c"), addr); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a flow over the route's rate was not dropped", func() bool { return dropped("limit") == 1 })
}

// TestApplier_RateLimitRules: a rate_limit rule that allows no request is refused, and the rules of
// a route's access reach its limit state.
func TestApplier_RateLimitRules(t *testing.T) {
	a, _ := gateway.NewApplier()
	res := tcpResource("rt_1", 5432, "con_1")
	res.GetGatewayTcpRoute().Access = &agentv1.RouteAccess{RateLimits: []*agentv1.RateLimitRule{{PolicyId: "pol_1", PerSecond: 0, Burst: 1}}}
	if errs := a.Validate(gatewaySnapshot(1, res)); len(errs) != 1 {
		t.Fatalf("a rule of 0 per second: %v", errs)
	}
	res.GetGatewayTcpRoute().Access.RateLimits[0].PerSecond = 1
	if errs := a.Validate(gatewaySnapshot(1, res)); len(errs) != 0 {
		t.Fatal(errs)
	}
	a.Apply(t.Context(), gatewaySnapshot(1, res), agent.Changes{})
	lim := gateway.LimitOf(a, "rt_1")
	client := netip.MustParseAddr("192.0.2.1")
	if ok, _, _ := lim.Admit(client); !ok {
		t.Fatal("the first connection was refused")
	}
	if ok, _, perClient := lim.Admit(client); ok || !perClient {
		t.Fatal("the rule of the snapshot was not set: " + strconv.FormatBool(ok))
	}
}

// TestRouteLimit_ClientTables (docs/03-connections.md, "Timeouts, keepalive and backoff"): the
// routes whose policies carry a rate_limit rule share its client table; a table holds at most its
// bound of clients and refuses new ones while those are limited; clients whose bucket is full
// again are dropped when the table is full, and every minute; a table no route uses goes.
func TestRouteLimit_ClientTables(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	ls := gateway.Limits{Now: func() time.Time { return now }}
	rule := gateway.ClientRate{Policy: "pol_1", PerSecond: 1, Burst: 1}
	a := ls.Set("rt_a", gateway.RouteLimits{Clients: []gateway.ClientRate{rule}})
	b := ls.Set("rt_b", gateway.RouteLimits{Clients: []gateway.ClientRate{rule}})
	c := ls.Set("rt_c", gateway.RouteLimits{Clients: []gateway.ClientRate{{Policy: "pol_2", PerSecond: 1, Burst: 1}}})
	client := netip.MustParseAddr("192.0.2.1")
	if ok, _, _ := a.Admit(client); !ok {
		t.Fatal("the first request was refused")
	}
	if ok, _, perClient := b.Admit(client); ok || !perClient {
		t.Fatal("a route sharing the rule has a bucket of its own for the client")
	}
	if ok, _, _ := c.Admit(client); !ok {
		t.Fatal("another rule shares the client's bucket")
	}

	// The bound: the default table holds 65 536 clients and refuses the next.
	for i := range 65_535 {
		if ok, _, _ := a.Admit(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})); !ok {
			t.Fatalf("client %d refused", i)
		}
	}
	newcomer := netip.MustParseAddr("198.51.100.1")
	if ok, wait, perClient := b.Admit(newcomer); ok || !perClient || wait != time.Second {
		t.Fatalf("a client beyond the bound: %t %s %t", ok, wait, perClient)
	}
	if got := gateway.ClientTables(&ls); !slices.Contains(got, 65_536) {
		t.Fatalf("tables %v", got)
	}
	// Held clients stay limited; once their buckets are full again, the full table drops them.
	if ok, _, _ := a.Admit(client); ok {
		t.Fatal("a held client was forgotten")
	}
	now = now.Add(2 * time.Second)
	if ok, _, _ := b.Admit(newcomer); !ok {
		t.Fatal("a client was refused after the others' buckets refilled")
	}
	if got := gateway.ClientTables(&ls); slices.Contains(got, 65_536) {
		t.Fatalf("the full table kept idle clients: %v", got)
	}

	// Every minute, idle clients go even from a table that is not full.
	ls.Set("rt_c", gateway.RouteLimits{Clients: []gateway.ClientRate{{Policy: "pol_2", PerSecond: 1, Burst: 1}}})
	now = now.Add(time.Minute)
	if ok, _, _ := c.Admit(netip.MustParseAddr("203.0.113.9")); !ok {
		t.Fatal("refused")
	}
	if got := gateway.ClientTables(&ls); !slices.Contains(got, 1) {
		t.Fatalf("idle clients stayed: %v", got)
	}

	ls.Retain(map[string]bool{"rt_a": true})
	if got := gateway.ClientTables(&ls); len(got) != 1 {
		t.Fatalf("tables of rules no route uses stayed: %v", got)
	}
}

// TestRouteLimit_AdmitOrder: a request a client rule refuses gives the route's total back, and one
// the total refuses takes nothing from the client's bucket.
func TestRouteLimit_AdmitOrder(t *testing.T) {
	var ls gateway.Limits
	lim := ls.Set("rt_1", gateway.RouteLimits{RequestsPerSecond: 3, Clients: []gateway.ClientRate{{Policy: "pol_1", PerSecond: 1, Burst: 1}}})
	a := netip.MustParseAddr("192.0.2.1")
	if ok, _, _ := lim.Admit(a); !ok {
		t.Fatal("the first request was refused")
	}
	for range 5 {
		if ok, _, perClient := lim.Admit(a); ok || !perClient {
			t.Fatal("a client over its rate was admitted")
		}
	}
	for i := range 2 {
		if ok, _, _ := lim.Admit(netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)})); !ok {
			t.Fatalf("client %d: the refused requests used up the route's total", i)
		}
	}
	other := netip.MustParseAddr("198.51.100.7")
	if ok, _, perClient := lim.Admit(other); ok || perClient {
		t.Fatal("over the route's total")
	}
	lim = ls.Set("rt_1", gateway.RouteLimits{RequestsPerSecond: 1000, Clients: []gateway.ClientRate{{Policy: "pol_1", PerSecond: 1, Burst: 1}}})
	if ok, _, _ := lim.Admit(other); !ok {
		t.Fatal("a refusal of the total used up the client's bucket")
	}
}
