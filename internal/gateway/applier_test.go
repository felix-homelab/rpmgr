// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
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
		httpResource("rt_2", "h2c", "app.example.com|/grpc"), passResource("rt_3", "db.example.com"),
		httpsResource("rt_4", &agentv1.UpstreamTLS{TargetId: "tg_1", ServerName: "a.internal", SpkiSha256: make([]byte, 32)}))
	if errs := a.Validate(ok); len(errs) != 0 {
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
		{"no upstream", gatewaySnapshot(1, httpResource("rt_1", "", "app.example.com")), "upstream protocol"},
		{"upper case", gatewaySnapshot(1, httpResource("rt_1", "http", "App.example.com")), "not normalised"},
		{"a relative prefix", gatewaySnapshot(1, httpResource("rt_1", "http", "app.example.com|api")), "start with /"},
		{"the same host and prefix twice", gatewaySnapshot(1, httpResource("rt_1", "http", "app.example.com|/api"),
			httpResource("rt_2", "http", "app.example.com|/api")), "also served by rt_1"},
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
