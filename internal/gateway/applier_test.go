// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/gateway"
)

func tcpResource(id string, port uint32, connectors ...string) *agentv1.Resource {
	return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_GatewayTcpRoute{GatewayTcpRoute: &agentv1.GatewayTCPRoute{
		Port: port, IdleTimeoutSeconds: 3600, Connectors: connectors}}}
}

func udpResource(id string, port uint32, connectors ...string) *agentv1.Resource {
	return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_GatewayUdpRoute{GatewayUdpRoute: &agentv1.GatewayUDPRoute{
		Port: port, FlowIdleTimeoutSeconds: 60, Connectors: connectors}}}
}

func gatewaySnapshot(seq uint64, rs ...*agentv1.Resource) *agentv1.Snapshot {
	return &agentv1.Snapshot{Revision: &agentv1.Revision{Seq: seq}, Resources: rs}
}

// TestApplier_Validate: a gateway snapshot holds only gateway routes, on valid ports distinct per
// protocol, with connector IDs.
// tokenResource is the HTTP token of a domain claim.
func tokenResource(id, fqdn, value string) *agentv1.Resource {
	return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_GatewayDomainChallenge{
		GatewayDomainChallenge: &agentv1.GatewayDomainChallenge{Fqdn: fqdn, Value: value}}}
}

func TestApplier_Validate(t *testing.T) {
	a, _ := gateway.NewApplier()
	if errs := a.Validate(gatewaySnapshot(1, tcpResource("rt_1", 5432, "con_1"), tcpResource("rt_2", 6379, "con_1", "con_2"),
		udpResource("rt_3", 5432, "con_1"), udpResource("rt_4", 53, "con_2"), tokenResource("dom_1", "app.example.com", "c2wkd5yx"))); len(errs) != 0 {
		t.Fatalf("a valid snapshot: %v", errs)
	}
	for _, tc := range []struct {
		name string
		snap *agentv1.Snapshot
		want string
	}{
		{"a connector's resource", gatewaySnapshot(1, &agentv1.Resource{Id: "rt_1", Kind: &agentv1.Resource_ConnectorRoute{ConnectorRoute: &agentv1.ConnectorRoute{}}}), "does not run"},
		{"no kind", gatewaySnapshot(1, &agentv1.Resource{Id: "rt_1"}), "does not run"},
		{"port 0", gatewaySnapshot(1, tcpResource("rt_1", 0)), "not a TCP port"},
		{"port 65536", gatewaySnapshot(1, tcpResource("rt_1", 65536)), "not a TCP port"},
		{"a port twice", gatewaySnapshot(1, tcpResource("rt_1", 5432), tcpResource("rt_2", 5432)), "also the port of rt_1"},
		{"an empty connector", gatewaySnapshot(1, tcpResource("rt_1", 5432, "con_1", "")), "empty connector"},
		{"udp port 0", gatewaySnapshot(1, udpResource("rt_1", 0)), "not a UDP port"},
		{"udp port 65536", gatewaySnapshot(1, udpResource("rt_1", 65536)), "not a UDP port"},
		{"a udp port twice", gatewaySnapshot(1, udpResource("rt_1", 53), udpResource("rt_2", 53)), "UDP port 53 is also the port of rt_1"},
		{"an empty udp connector", gatewaySnapshot(1, udpResource("rt_1", 53, "")), "empty connector"},
		{"a token for an unnormalised name", gatewaySnapshot(1, tokenResource("dom_1", "App.Example.com", "abc234")), "not normalised"},
		{"a token for no name", gatewaySnapshot(1, tokenResource("dom_1", "", "abc234")), "not normalised"},
		{"an empty token", gatewaySnapshot(1, tokenResource("dom_1", "app.example.com", "")), "not lower-case base32"},
		{"a token with a line break", gatewaySnapshot(1, tokenResource("dom_1", "app.example.com", "abc\n")), "not lower-case base32"},
		{"an over-long token", gatewaySnapshot(1, tokenResource("dom_1", "app.example.com", strings.Repeat("a", 65))), "not lower-case base32"},
	} {
		errs := a.Validate(tc.snap)
		if len(errs) == 0 || !strings.Contains(errs[0].GetMessage(), tc.want) {
			t.Errorf("%s: %v, want an error about %q", tc.name, errs, tc.want)
		}
	}
}

// rankedTCP is a tcp route whose connectors come ranked: one entry per connector and priority.
func rankedTCP(id string, port uint32, ranked ...*agentv1.RouteConnector) *agentv1.Resource {
	res := tcpResource(id, port)
	r := res.GetGatewayTcpRoute()
	for _, rc := range ranked {
		if !slices.Contains(r.Connectors, rc.GetConnectorId()) {
			r.Connectors = append(r.Connectors, rc.GetConnectorId())
		}
	}
	r.RankedConnectors = ranked
	return res
}

func rank(id string, priority, weight uint32) *agentv1.RouteConnector {
	return &agentv1.RouteConnector{ConnectorId: id, Priority: priority, Weight: weight}
}

// TestApplier_Ranks: a route's ranked entries are one per connector and priority, of exactly the
// route's connectors, with a bounded weight; the assignment carries them for every route kind, and
// a route without them ranks every connector alike, at priority 0 and weight 1, unranked (D90).
func TestApplier_Ranks(t *testing.T) {
	a, assign := gateway.NewApplier()
	ranks := []*agentv1.RouteConnector{rank("con_1", 0, 3), rank("con_1", 5, 2), rank("con_2", 10, 1)}
	udp := udpResource("rt_3", 53, "con_1")
	udp.GetGatewayUdpRoute().RankedConnectors = []*agentv1.RouteConnector{rank("con_1", 4, 7)}
	both := &agentv1.Resource{Id: "rt_4", Kind: &agentv1.Resource_GatewayTcpUdpRoute{GatewayTcpUdpRoute: &agentv1.GatewayTCPUDPRoute{
		Port: 5353, FlowIdleTimeoutSeconds: 60, Connectors: []string{"con_2"}, RankedConnectors: []*agentv1.RouteConnector{rank("con_2", 6, 8)}}}}
	pass := &agentv1.Resource{Id: "rt_5", Kind: &agentv1.Resource_GatewayPassthroughRoute{GatewayPassthroughRoute: &agentv1.GatewayPassthroughRoute{
		Hostnames: []string{"db.example.com"}, Connectors: []string{"con_1"}, RankedConnectors: []*agentv1.RouteConnector{rank("con_1", 2, 9)}}}}
	web := &agentv1.Resource{Id: "rt_6", Kind: &agentv1.Resource_GatewayHttpRoute{GatewayHttpRoute: &agentv1.GatewayHTTPRoute{
		Hosts: []*agentv1.HTTPHost{{Hostname: "app.example.com"}}, UpstreamProtocol: "http", Connectors: []string{"con_2"},
		RankedConnectors: []*agentv1.RouteConnector{rank("con_2", 3, 4)}}}}
	valid := gatewaySnapshot(1, rankedTCP("rt_1", 5432, ranks...), tcpResource("rt_2", 6379, "con_1", "con_2"), udp, both, pass, web)
	if errs := a.Validate(valid); len(errs) != 0 {
		t.Fatalf("a valid snapshot: %v", errs)
	}
	other := rankedTCP("rt_1", 5432, rank("con_1", 0, 1))
	other.GetGatewayTcpRoute().RankedConnectors = []*agentv1.RouteConnector{rank("con_9", 0, 1)}
	short := rankedTCP("rt_1", 5432, rank("con_1", 0, 1), rank("con_2", 0, 1))
	short.GetGatewayTcpRoute().RankedConnectors = short.GetGatewayTcpRoute().RankedConnectors[:1]
	for _, tc := range []struct {
		name string
		res  *agentv1.Resource
		want string
	}{
		{"another connector", other, "not the route's connectors"},
		{"one missing", short, "not the route's connectors"},
		{"a connector twice at one priority", rankedTCP("rt_1", 5432, rank("con_1", 5, 1), rank("con_1", 5, 2)), "ranked twice at priority 5"},
		{"a weight above the bound", rankedTCP("rt_1", 5432, rank("con_1", 0, 1_000_001)), "above 1000000"},
	} {
		if errs := a.Validate(gatewaySnapshot(1, tc.res)); len(errs) == 0 || !strings.Contains(errs[0].GetMessage(), tc.want) {
			t.Errorf("%s: %v, want an error about %q", tc.name, errs, tc.want)
		}
	}
	a.Apply(t.Context(), valid, agent.Changes{})
	for route, want := range map[string][]gateway.RouteConnector{
		"rt_1": {{ID: "con_1", Weight: 3, Ranked: true}, {ID: "con_1", Priority: 5, Weight: 2, Ranked: true}, {ID: "con_2", Priority: 10, Weight: 1, Ranked: true}},
		"rt_2": {{ID: "con_1", Weight: 1}, {ID: "con_2", Weight: 1}},
		"rt_3": {{ID: "con_1", Priority: 4, Weight: 7, Ranked: true}},
		"rt_4": {{ID: "con_2", Priority: 6, Weight: 8, Ranked: true}},
		"rt_5": {{ID: "con_1", Priority: 2, Weight: 9, Ranked: true}},
		"rt_6": {{ID: "con_2", Priority: 3, Weight: 4, Ranked: true}},
	} {
		if got := assign.Connectors(route); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", route, got, want)
		}
	}
}

// TestApplier_Apply: the snapshot's routes listen, its assignment admits exactly its connectors,
// its revision goes into StreamOpen, and a connector dropped from it loses its data sessions.
func TestApplier_Apply(t *testing.T) {
	a, assign := gateway.NewApplier()
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: assign})
	t.Cleanup(m.Close)
	routes := gateway.NewTCPRoutes(gateway.TCPOptions{Host: "127.0.0.1", Sessions: m, Revision: a.Revision})
	t.Cleanup(routes.Close)
	udp := gateway.NewUDPRoutes(gateway.UDPOptions{Host: "127.0.0.1", Sessions: m, Revision: a.Revision})
	t.Cleanup(udp.Close)
	a.Bind(gateway.Served{TCP: routes, UDP: udp, Sessions: m})
	if assign.Known(cid("con_1")) || a.Revision() != nil {
		t.Fatal("known before any snapshot")
	}
	p1, p2, p3 := freePort(t), freePort(t), freeUDPPort(t)
	st := a.Apply(t.Context(), gatewaySnapshot(7, tcpResource("rt_1", uint32(p1), cid("con_1")), tcpResource("rt_2", uint32(p2), cid("con_1"), cid("con_2")),
		udpResource("rt_3", uint32(p3), cid("con_3"))), agent.Changes{})
	if len(st) != 0 {
		t.Fatal(st)
	}
	if !assign.Known(cid("con_2")) || !assign.Known(cid("con_3")) || assign.Known(cid("con_4")) || len(assign.Connectors("rt_2")) != 2 ||
		len(assign.Connectors("rt_3")) != 1 || a.Revision().GetSeq() != 7 {
		t.Fatalf("assignment after the snapshot: %v %v rev %v", assign.Connectors("rt_1"), assign.Connectors("rt_2"), a.Revision())
	}
	for _, p := range []uint16{p1, p2} {
		// Without a data session the gateway resets the connection, sometimes before Dial returns.
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p))))
		if err != nil && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("port %d: %v", p, err)
		}
		if c != nil {
			_ = c.Close()
		}
	}

	if _, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(p3)}); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("the udp route's port is not bound: %v", err)
	}
	taken, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = taken.Close() }()
	st = a.Apply(t.Context(), gatewaySnapshot(7, tcpResource("rt_1", uint32(p1), cid("con_1")), tcpResource("rt_2", uint32(p2), cid("con_1"), cid("con_2")),
		udpResource("rt_3", uint32(taken.LocalAddr().(*net.UDPAddr).Port), cid("con_3"))), agent.Changes{}) //nolint:gosec // G115: a port
	if len(st) != 1 || st[0].GetResourceId() != "rt_3" || st[0].GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_PORT_IN_USE {
		t.Fatalf("an occupied udp port: %v", st)
	}
	if r := a.Readiness(); len(r) != 1 || r[0].GetResourceId() != "rt_3" {
		t.Fatalf("readiness with an occupied udp port: %v", r)
	}

	c := start(t, m, connectorID("con_2"), hello("rt_2"))
	a.Apply(t.Context(), gatewaySnapshot(8, tcpResource("rt_1", uint32(p1), cid("con_1"))), agent.Changes{})
	if err := c.serveErr(t); err == nil {
		t.Fatal("the dropped connector's session ended without an error")
	}
	if assign.Known(cid("con_2")) || a.Revision().GetSeq() != 8 {
		t.Fatal("the dropped connector is still known")
	}
}

func httpResource(id, upstream string, hosts ...string) *agentv1.Resource {
	r := &agentv1.GatewayHTTPRoute{UpstreamProtocol: upstream, Connectors: []string{"con_1"}}
	for _, hp := range hosts {
		host, prefix, _ := strings.Cut(hp, "|")
		r.Hosts = append(r.Hosts, &agentv1.HTTPHost{Hostname: host, PathPrefix: prefix})
	}
	return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_GatewayHttpRoute{GatewayHttpRoute: r}}
}

func withHTTP(r *agentv1.Resource, f func(*agentv1.GatewayHTTPRoute)) *agentv1.Resource {
	f(r.GetGatewayHttpRoute())
	return r
}

// requireHeader is a require_header rule of a header with n zero hashes.
func requireHeader(name string, n int) *rpmgrv1.RequireHeaderParams {
	r := &rpmgrv1.RequireHeaderParams{Name: name}
	for range n {
		r.ValueSha256 = append(r.ValueSha256, make([]byte, 32))
	}
	return r
}

// withRequireHeader is an http route with a require_header rule.
func withRequireHeader(rh *rpmgrv1.RequireHeaderParams) *agentv1.Resource {
	return withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
		r.Access = &agentv1.RouteAccess{RequireHeader: []*rpmgrv1.RequireHeaderParams{rh}}
	})
}

// pageResource is a custom page of a kind with a zero hash of size bytes.
func pageResource(id string, kind rpmgrv1.GatewayPageKind, size int) *agentv1.Resource {
	return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_GatewayPage{GatewayPage: &agentv1.GatewayPage{Kind: kind, ContentSha256: make([]byte, size)}}}
}

func httpsResource(id string, tls ...*agentv1.UpstreamTLS) *agentv1.Resource {
	r := httpResource(id, "https", "secure.example.com")
	r.GetGatewayHttpRoute().UpstreamTls = tls
	return r
}

func passResource(id string, hostnames ...string) *agentv1.Resource {
	return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_GatewayPassthroughRoute{GatewayPassthroughRoute: &agentv1.GatewayPassthroughRoute{
		Hostnames: hostnames, Connectors: []string{"con_1"}}}}
}

// TestApplier_ValidateHTTP: http routes need normalised hostnames, path prefixes that start with
// "/", a known upstream protocol, and a hostname and prefix no other route serves; a hostname is
// never both an http and a passthrough route's.
func TestApplier_ValidateHTTP(t *testing.T) {
	a, _ := gateway.NewApplier()
	ok := gatewaySnapshot(1, httpResource("rt_1", "http", "app.example.com", "app.example.com|/api", "*.example.com"),
		pageResource("gwp_1", rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_NOT_FOUND, 32), pageResource("gwp_2", rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE, 32),
		httpResource("rt_2", "h2c", "app.example.com|/grpc"), passResource("rt_3", "db.example.com"),
		httpsResource("rt_4", &agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "a.internal", SpkiSha256: make([]byte, 32)},
			&agentv1.UpstreamTLS{TargetId: "tg_2", ServerName: "b.internal", Verification: agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_UNVERIFIED,
				ConnectorId: "con_1"},
			&agentv1.UpstreamTLS{TargetId: "tg_3", ServerName: "c.internal", Verification: agentv1.UpstreamVerification(99)},
			&agentv1.UpstreamTLS{TargetId: "tg_4", ServerName: "d.internal", SpkiSha256: make([]byte, 32),
				Verification: agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_PINNED_KEY, ConnectorId: "con_1"}))
	if errs := a.Validate(ok); len(errs) != 0 {
		t.Fatal(errs)
	}
	// Two routes may share a hostname and prefix with different header matches.
	shared := gatewaySnapshot(1, httpResource("rt_1", "http", "app.example.com|/api"),
		withHTTP(httpResource("rt_2", "http", "app.example.com|/api"), func(r *agentv1.GatewayHTTPRoute) {
			r.HeaderMatches = []*agentv1.HTTPHeaderMatch{{Name: "X-Env", Value: "beta"}}
		}), withHTTP(httpResource("rt_3", "http", "app.example.com|/api"), func(r *agentv1.GatewayHTTPRoute) {
			r.HeaderMatches = []*agentv1.HTTPHeaderMatch{{Name: "X-Env", Present: true}}
		}))
	if errs := a.Validate(shared); len(errs) != 0 {
		t.Fatal(errs)
	}
	for _, tc := range []struct {
		name string
		snap *agentv1.Snapshot
		want string
	}{
		{"no hosts", gatewaySnapshot(1, httpResource("rt_1", "http")), "without hostnames"},
		{"a grpc upstream", gatewaySnapshot(1, httpResource("rt_1", "grpc", "app.example.com")), "upstream protocol"},
		{"upstream TLS without a target", gatewaySnapshot(1, httpsResource("rt_1", &agentv1.UpstreamTLS{ServerName: "a"})), "without a target"},
		{"upstream TLS twice", gatewaySnapshot(1, httpsResource("rt_1", &agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "a"},
			&agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "b"})), "twice"},
		{"no server name", gatewaySnapshot(1, httpsResource("rt_1", &agentv1.UpstreamTLS{TargetId: "tg_1"})), "without a server name"},
		{"a bundle without certificates", gatewaySnapshot(1, httpsResource("rt_1", &agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "a",
			CaPem: []byte("nothing")})), "holds no certificate"},
		{"an unknown port 80 mode", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			r.Port80 = "proxy"
		})), "port 80 mode"},
		{"CR LF in a header value", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			r.RequestHeaders = []*agentv1.HTTPHeader{{Name: "X-Env", Value: "prod\r\nX-Admin: 1"}}
		})), "not a valid field value"},
		{"a reserved header", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			r.RequestHeaders = []*agentv1.HTTPHeader{{Name: "X-Forwarded-For", Value: "1.2.3.4"}}
		})), "gateway's own"},
		{"a response header that is the connection's", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"),
			func(r *agentv1.GatewayHTTPRoute) {
				r.ResponseHeaders = []*agentv1.HTTPHeader{{Name: "Transfer-Encoding", Value: "x"}}
			})), "gateway's own"},
		{"a header name with a space", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			r.ResponseHeaders = []*agentv1.HTTPHeader{{Name: "X Env", Value: "x"}}
		})), "header name"},
		{"a name not canonical", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			r.ResponseHeaders = []*agentv1.HTTPHeader{{Name: "x-env", Value: "x"}}
		})), "header name"},
		{"CR LF in the host header", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			r.HostHeader = "a\r\nb"
		})), "host header"},
		{"a trusted proxy that is no CIDR", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			r.TrustedProxies = []string{"10.0.0.1"}
		})), "not a CIDR"},
		{"a short pin", gatewaySnapshot(1, httpsResource("rt_1", &agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "a",
			SpkiSha256: make([]byte, 16)})), "not a SHA-256"},
		{"an unverified target with a pin", gatewaySnapshot(1, httpsResource("rt_1", &agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "a",
			SpkiSha256: make([]byte, 32), Verification: agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_UNVERIFIED})), "has a CA bundle or a pin"},
		{"an unverified target of no connector", gatewaySnapshot(1, httpsResource("rt_1", &agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "a",
			Verification: agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_UNVERIFIED})), "names no connector"},
		{"an unverified target with a CA bundle", gatewaySnapshot(1, httpsResource("rt_1", &agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "a",
			CaPem: []byte("x"), Verification: agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_UNVERIFIED})), "has a CA bundle or a pin"},
		{"a pinned-key target of no connector", gatewaySnapshot(1, httpsResource("rt_1", &agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "a",
			SpkiSha256: make([]byte, 32), Verification: agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_PINNED_KEY})), "names no connector"},
		{"a pinned-key target without a pin", gatewaySnapshot(1, httpsResource("rt_1", &agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "a",
			ConnectorId: "con_1", Verification: agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_PINNED_KEY})), "no SHA-256 pin"},
		{"a pinned-key target with a CA bundle", gatewaySnapshot(1, httpsResource("rt_1", &agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "a",
			ConnectorId: "con_1", SpkiSha256: make([]byte, 32), CaPem: []byte("x"), Verification: agentv1.UpstreamVerification_UPSTREAM_VERIFICATION_PINNED_KEY})), "no SHA-256 pin"},
		{"require-header on a tcp route", gatewaySnapshot(1, func() *agentv1.Resource {
			r := tcpResource("rt_1", 2222)
			r.GetGatewayTcpRoute().Access = &agentv1.RouteAccess{RequireHeader: []*rpmgrv1.RequireHeaderParams{requireHeader("X-Origin", 1)}}
			return r
		}()), "not http"},
		{"require-header with a bad name", gatewaySnapshot(1, withRequireHeader(&rpmgrv1.RequireHeaderParams{Name: "X Origin",
			ValueSha256: [][]byte{make([]byte, 32)}})), "header name"},
		{"require-header without values", gatewaySnapshot(1, withRequireHeader(requireHeader("X-Origin", 0))), "not 1 to 4"},
		{"a required trace header", gatewaySnapshot(1, withRequireHeader(requireHeader("tracestate", 1))), "trace context"},
		{"a required host header", gatewaySnapshot(1, withRequireHeader(requireHeader("Host", 1))), "gateway's own"},
		{"a required rpmgr header", gatewaySnapshot(1, withRequireHeader(requireHeader("Rpmgr-User-Email", 1))), "rpmgr header"},
		{"require-header with five values", gatewaySnapshot(1, withRequireHeader(requireHeader("X-Origin", 5))), "not 1 to 4"},
		{"require-header with a short hash", gatewaySnapshot(1, withRequireHeader(&rpmgrv1.RequireHeaderParams{Name: "X-Origin",
			ValueSha256: [][]byte{make([]byte, 16)}})), "16 bytes"},
		{"a page of no kind", gatewaySnapshot(1, pageResource("gwp_1", 0, 32)), "page kind"},
		{"a page without a hash", gatewaySnapshot(1, pageResource("gwp_1", rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_NOT_FOUND, 16)), "SHA-256"},
		{"two pages of a kind", gatewaySnapshot(1, pageResource("gwp_1", rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE, 32),
			pageResource("gwp_2", rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE, 32)), "a second maintenance page"},
		{"no upstream", gatewaySnapshot(1, httpResource("rt_1", "", "app.example.com")), "upstream protocol"},
		{"upper case", gatewaySnapshot(1, httpResource("rt_1", "http", "App.example.com")), "not normalised"},
		{"a relative prefix", gatewaySnapshot(1, httpResource("rt_1", "http", "app.example.com|api")), "start with /"},
		{"the same host and prefix twice", gatewaySnapshot(1, httpResource("rt_1", "http", "app.example.com|/api"),
			httpResource("rt_2", "http", "app.example.com|/api")), "also served by rt_1"},
		{"the same host, prefix and header matches twice", gatewaySnapshot(1,
			withHTTP(httpResource("rt_1", "http", "app.example.com|/api"), func(r *agentv1.GatewayHTTPRoute) {
				r.HeaderMatches = []*agentv1.HTTPHeaderMatch{{Name: "X-Env", Value: "beta"}}
			}), withHTTP(httpResource("rt_2", "http", "app.example.com|/api"), func(r *agentv1.GatewayHTTPRoute) {
				r.HeaderMatches = []*agentv1.HTTPHeaderMatch{{Name: "X-Env", Value: "beta"}}
			})), "also served by rt_1 with the same header matches"},
		{"an upstream header timeout above an hour", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			r.UpstreamResponseHeaderTimeoutSeconds = 3601
		})), "upstream timeout above 3600 seconds"},
		{"an upstream idle timeout above an hour", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			r.UpstreamIdleTimeoutSeconds = 3601
		})), "upstream timeout above 3600 seconds"},
		{"nine header matches", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			for i := range 9 {
				r.HeaderMatches = append(r.HeaderMatches, &agentv1.HTTPHeaderMatch{Name: "X-" + strings.Repeat("a", i+1), Present: true})
			}
		})), "at most 8"},
		{"CR LF in a header match", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			r.HeaderMatches = []*agentv1.HTTPHeaderMatch{{Name: "X-Env", Value: "a\r\nX-Admin: 1"}}
		})), "needs a valid"},
		{"a header matched twice", gatewaySnapshot(1, withHTTP(httpResource("rt_1", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
			r.HeaderMatches = []*agentv1.HTTPHeaderMatch{{Name: "X-Env", Value: "a"}, {Name: "X-Env", Present: true}}
		})), "matched twice"},
		{"http after passthrough", gatewaySnapshot(1, passResource("rt_1", "app.example.com"),
			httpResource("rt_2", "http", "app.example.com")), "also a hostname of rt_1"},
		{"passthrough after http", gatewaySnapshot(1, httpResource("rt_1", "http", "app.example.com|/x"),
			passResource("rt_2", "app.example.com")), "also a hostname of rt_1"},
	} {
		errs := a.Validate(tc.snap)
		if len(errs) == 0 || !strings.Contains(errs[0].GetMessage(), tc.want) {
			t.Errorf("%s: %v, want an error about %q", tc.name, errs, tc.want)
		}
	}
}

// TestApplier_ItemsAreNoRoutes: certificates, pages and domain tokens serve no route of their own,
// so the assignment holds no route for them; the routes of the snapshot it does hold.
func TestApplier_ItemsAreNoRoutes(t *testing.T) {
	a, assign := gateway.NewApplier()
	cert := &agentv1.Resource{Id: "crt_1", Kind: &agentv1.Resource_GatewayCertificate{GatewayCertificate: &agentv1.GatewayCertificate{
		ContentSha256: make([]byte, 32), Hostnames: []string{"app.example.com"}}}}
	if st := a.Apply(t.Context(), gatewaySnapshot(3, cert, pageResource("gwp_1", rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_NOT_FOUND, 32),
		tokenResource("dom_1", "example.com", "abc"), httpResource("rt_1", "http", "app.example.com")), agent.Changes{}); len(st) != 0 {
		t.Fatalf("status %v", st)
	}
	if got := gateway.AssignedRoutes(assign); !slices.Equal(got, []string{"rt_1"}) {
		t.Fatalf("assigned routes %v, want only rt_1", got)
	}
}

// TestApplier_Disable (R22): the drain mark of a disabled gateway drains its data sessions rather
// than closing them, and the connections of its removed tcp routes stay open for the gateway drain
// period, not the route drain period; a snapshot without the mark enables the gateway again.
func TestApplier_Disable(t *testing.T) {
	gateway.SetRouteTimers(t, 100*time.Millisecond, time.Second)
	a, assign := gateway.NewApplier()
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: assign})
	t.Cleanup(m.Close)
	routes := gateway.NewTCPRoutes(gateway.TCPOptions{Host: "127.0.0.1", Sessions: m, Revision: a.Revision})
	t.Cleanup(routes.Close)
	a.Bind(gateway.Served{TCP: routes, Sessions: m, DrainPeriod: 800 * time.Millisecond})
	drain := &agentv1.Resource{Id: "gw_01", Kind: &agentv1.Resource_GatewayDrain{GatewayDrain: &agentv1.GatewayDrain{}}}
	if errs := a.Validate(gatewaySnapshot(2, drain)); len(errs) != 0 {
		t.Fatalf("the drain mark is refused: %v", errs)
	}
	p1 := freePort(t)
	a.Apply(t.Context(), gatewaySnapshot(1, tcpResource("rt_1", uint32(p1), cid("con_1"))), agent.Changes{})
	c := start(t, m, connectorID("con_1"), hello("rt_1"))
	conn := dialPort(t, p1)
	if err := ping(conn, "before"); err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	if st := a.Apply(t.Context(), gatewaySnapshot(2, drain), agent.Changes{}); len(st) != 0 {
		t.Fatal(st)
	}
	if msg := <-c.msgs; msg.GetDrain().GetReason() != "gateway disabled" {
		t.Fatalf("got %v, want Drain", msg)
	}
	if _, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p1)))); err == nil {
		t.Fatal("the disabled gateway's port still accepts")
	}
	time.Sleep(300 * time.Millisecond)
	if err := ping(conn, "past the route drain period"); err != nil {
		t.Fatalf("a connection ended with the route drain period: %v", err)
	}
	_ = c.serveErr(t)
	if took := time.Since(begin); took < 700*time.Millisecond {
		t.Fatalf("the session closed after %s, before the gateway drain period", took)
	}
	if err := ping(conn, "after the gateway drain period"); err == nil {
		t.Fatal("a connection survived the gateway drain period")
	}

	a.Apply(t.Context(), gatewaySnapshot(3, tcpResource("rt_1", uint32(p1), cid("con_1"))), agent.Changes{})
	if again := start(t, m, connectorID("con_1"), hello("rt_1")); again.welcome == nil {
		t.Fatal("no session admitted once enabled")
	}
	if err := ping(dialPort(t, p1), "enabled again"); err != nil {
		t.Fatal(err)
	}
}

func tcpUDPResource(id string, port uint32, connectors ...string) *agentv1.Resource {
	return &agentv1.Resource{Id: id, Kind: &agentv1.Resource_GatewayTcpUdpRoute{GatewayTcpUdpRoute: &agentv1.GatewayTCPUDPRoute{
		Port: port, IdleTimeoutSeconds: 3600, FlowIdleTimeoutSeconds: 60, Connectors: connectors}}}
}

// TestApplier_TCPUDP: a tcp_udp route's port counts as a TCP and as a UDP port, so another route
// on it in either protocol is refused; applied, it listens on both, admits its connectors, and a
// port taken in either protocol makes the route not ready, until it is bound.
func TestApplier_TCPUDP(t *testing.T) {
	a, assign := gateway.NewApplier()
	for _, tc := range []struct {
		name string
		snap *agentv1.Snapshot
		want string
	}{
		{"port 0", gatewaySnapshot(1, tcpUDPResource("rt_1", 0)), "not a TCP port"},
		{"a tcp route on its port", gatewaySnapshot(1, tcpUDPResource("rt_1", 53), tcpResource("rt_2", 53)), "TCP port 53 is also the port of rt_1"},
		{"a udp route on its port", gatewaySnapshot(1, udpResource("rt_2", 53), tcpUDPResource("rt_1", 53)), "UDP port 53 is also the port of rt_2"},
		{"an empty connector", gatewaySnapshot(1, tcpUDPResource("rt_1", 53, "")), "empty connector"},
	} {
		errs := a.Validate(tc.snap)
		if len(errs) == 0 || !strings.Contains(errs[0].GetMessage(), tc.want) {
			t.Errorf("%s: %v, want an error about %q", tc.name, errs, tc.want)
		}
	}
	gateway.SetRouteTimers(t, time.Second, 50*time.Millisecond)
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: assign})
	t.Cleanup(m.Close)
	routes := gateway.NewTCPRoutes(gateway.TCPOptions{Host: "127.0.0.1", Sessions: m, Revision: a.Revision})
	t.Cleanup(routes.Close)
	udp := gateway.NewUDPRoutes(gateway.UDPOptions{Host: "127.0.0.1", Sessions: m, Revision: a.Revision})
	t.Cleanup(udp.Close)
	a.Bind(gateway.Served{TCP: routes, UDP: udp, Sessions: m})

	// A port free for TCP and UDP; held for UDP while the route is applied.
	port := freeUDPPort(t)
	if l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))); err != nil {
		t.Skipf("port %d is not free for TCP: %v", port, err)
	} else {
		_ = l.Close()
	}
	taken, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	st := a.Apply(t.Context(), gatewaySnapshot(1, tcpUDPResource("rt_1", uint32(port), cid("con_1"))), agent.Changes{})
	if len(st) != 1 || st[0].GetResourceId() != "rt_1" || st[0].GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_PORT_IN_USE ||
		!strings.Contains(st[0].GetDetail(), "udp port") {
		t.Fatalf("a taken udp port: %v", st)
	}
	if !assign.Known(cid("con_1")) || len(assign.Connectors("rt_1")) != 1 {
		t.Fatal("the route's connector is not admitted")
	}
	if _, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("the route's TCP port is not bound: %v", err)
	}
	_ = taken.Close()
	eventually(t, "the freed udp port was not bound", func() bool { return len(a.Readiness()) == 0 })
	if _, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("the route's UDP port is not bound: %v", err)
	}
	if st := a.Apply(t.Context(), gatewaySnapshot(2), agent.Changes{}); len(st) != 0 {
		t.Fatal(st)
	}
	eventually(t, "a removed route keeps its ports", func() bool {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		if err != nil {
			return false
		}
		_ = c.Close()
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		if err != nil {
			return false
		}
		_ = l.Close()
		return true
	})
}

// TestApplier_Maintenance: an http route's maintenance and message in the snapshot reach its
// requests, and leave them when a later snapshot clears them.
func TestApplier_Maintenance(t *testing.T) {
	a, assign := gateway.NewApplier()
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: assign})
	t.Cleanup(m.Close)
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Sessions: m})
	t.Cleanup(h.Close)
	a.Bind(gateway.Served{HTTP: h, Sessions: m})
	page := func() string {
		r := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
		r.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Body.String()
	}
	web := withHTTP(httpResource("rt_web", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
		r.Maintenance, r.MaintenanceMessage = true, "Back at 18:00."
	})
	if st := a.Apply(t.Context(), gatewaySnapshot(1, web), agent.Changes{}); len(st) != 0 {
		t.Fatal(st)
	}
	if b := page(); !strings.Contains(b, "<h1>Down for maintenance</h1>") || !strings.Contains(b, "Back at 18:00.") {
		t.Fatalf("in maintenance: %s", b)
	}
	if st := a.Apply(t.Context(), gatewaySnapshot(2, httpResource("rt_web", "http", "app.example.com")), agent.Changes{}); len(st) != 0 {
		t.Fatal(st)
	}
	if b := page(); !strings.Contains(b, "<h1>Service unavailable</h1>") { // no connector
		t.Fatalf("out of maintenance: %s", b)
	}
}

// TestApplier_HeaderMatches: an http route's header matches in the snapshot decide which of two
// routes of one hostname and prefix a request reaches; names arrive canonical.
func TestApplier_HeaderMatches(t *testing.T) {
	a, assign := gateway.NewApplier()
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: assign})
	t.Cleanup(m.Close)
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Sessions: m})
	t.Cleanup(h.Close)
	a.Bind(gateway.Served{HTTP: h, Sessions: m})
	beta := withHTTP(httpResource("rt_beta", "http", "app.example.com"), func(r *agentv1.GatewayHTTPRoute) {
		r.HeaderMatches = []*agentv1.HTTPHeaderMatch{{Name: "X-Env", Value: "beta"}}
	})
	if st := a.Apply(t.Context(), gatewaySnapshot(1, httpResource("rt_main", "http", "app.example.com"), beta), agent.Changes{}); len(st) != 0 {
		t.Fatal(st)
	}
	if got := gateway.RouteFor(h, "app.example.com", "/", http.Header{"X-Env": {"beta"}}); got != "rt_beta" {
		t.Errorf("with the header: %q", got)
	}
	if got := gateway.RouteFor(h, "app.example.com", "/", http.Header{"X-Env": {"prod"}}); got != "rt_main" {
		t.Errorf("with another value: %q", got)
	}
}

// TestApplier_RouteTimeouts (D94): an http route's own upstream timeouts in the snapshot are the
// ones its transport uses; 0 keeps the gateway's.
func TestApplier_RouteTimeouts(t *testing.T) {
	a, assign := gateway.NewApplier()
	m := gateway.NewSessions(gateway.SessionsOptions{TrustDomain: td, GatewayID: "gw_01", Assignment: assign})
	t.Cleanup(m.Close)
	h := gateway.NewHTTPRoutes(gateway.HTTPOptions{Sessions: m})
	t.Cleanup(h.Close)
	a.Bind(gateway.Served{HTTP: h, Sessions: m})
	own := withHTTP(httpResource("rt_own", "http", "own.example.com"), func(r *agentv1.GatewayHTTPRoute) {
		r.UpstreamResponseHeaderTimeoutSeconds, r.UpstreamIdleTimeoutSeconds = 300, 15
	})
	if st := a.Apply(t.Context(), gatewaySnapshot(1, own, httpResource("rt_def", "http", "def.example.com")), agent.Changes{}); len(st) != 0 {
		t.Fatal(st)
	}
	if header, idle := gateway.RouteTimeouts(h, "rt_own"); header != 5*time.Minute || idle != 15*time.Second {
		t.Errorf("the route's own: %v %v", header, idle)
	}
	if header, idle := gateway.RouteTimeouts(h, "rt_def"); header != time.Minute || idle != 2*time.Minute {
		t.Errorf("the gateway's: %v %v", header, idle)
	}
}
