// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"slices"
	"strconv"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/connector"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/configrevision"
	"github.com/felix-homelab/rpmgr/internal/store/ent/healthcheck"
	"github.com/felix-homelab/rpmgr/internal/store/ent/resourcestatus"
)

// TestRouteHealthCheck (docs/07-api.md, "Services"; R29): a route takes one health check, set with
// the route or by an update of health_check, read back as given, and removed by an update without
// one or with the route; an interval below the minimum, a timeout not below the interval or above
// its maximum, a udp route's http check or tcp check without a port, half a status range, a
// relative path and a tcp check with a path are refused, as are a check port and a Unix socket
// target on one route, and an http check and an h2c target; a Viewer reads the check and changes
// nothing.
func TestRouteHealthCheck(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: udp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	httpCheck := &rpmgrv1.HealthCheck{Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, HttpPath: "/healthz?deep=1",
		ExpectedStatusMin: 200, ExpectedStatusMax: 204, IntervalSeconds: 5, TimeoutSeconds: 2, UnhealthyThreshold: 4, HealthyThreshold: 1}
	web := httpRoute("web", group, "web.example.com")
	web.HealthCheck = httpCheck
	created, err := createRoute(ada, org, web, "")
	if err != nil || !proto.Equal(created.GetHealthCheck(), httpCheck) {
		t.Fatalf("a route with a check: %v %v", created.GetHealthCheck(), err)
	}
	update := func(b *browser, id string, c *rpmgrv1.HealthCheck) (*rpmgrv1.Route, error) {
		r, err := b.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: &rpmgrv1.Route{Id: id, HealthCheck: c},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"health_check"}}}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetRoute(), nil
	}
	tcpCheck := &rpmgrv1.HealthCheck{Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP, Port: 8081}
	if up, err := update(ada, created.GetId(), tcpCheck); err != nil || !proto.Equal(up.GetHealthCheck(), tcpCheck) {
		t.Fatalf("a changed check: %v %v", up, err)
	}

	for name, c := range map[string]*rpmgrv1.HealthCheck{
		"no type":                 {IntervalSeconds: 5},
		"an interval of 1 s":      {Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP, IntervalSeconds: 1},
		"a timeout of 5 s at 5":   {Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP, IntervalSeconds: 5, TimeoutSeconds: 5},
		"a timeout above 1 min":   {Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP, IntervalSeconds: 600, TimeoutSeconds: 61},
		"a timeout above 10 s":    {Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP, TimeoutSeconds: 12},
		"a status minimum alone":  {Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, ExpectedStatusMin: 200},
		"statuses upside down":    {Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, ExpectedStatusMin: 300, ExpectedStatusMax: 200},
		"status 99":               {Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, ExpectedStatusMin: 99, ExpectedStatusMax: 200},
		"a relative path":         {Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, HttpPath: "healthz"},
		"a path with a space":     {Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, HttpPath: "/a b"},
		"a tcp check with a path": {Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP, HttpPath: "/"},
		"port 65536":              {Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP, Port: 65536},
	} {
		if _, err := update(ada, created.GetId(), c); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want INVALID_ARGUMENT", name, err)
		}
	}

	// A udp route: only a tcp check of a named port.
	dns := &rpmgrv1.Route{Name: "dns", GatewayGroupId: group, Spec: &rpmgrv1.Route_Udp{Udp: &rpmgrv1.UDPRouteSpec{Port: 20001}},
		HealthCheck: &rpmgrv1.HealthCheck{Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP}}
	if _, err := createRoute(ada, org, dns, ""); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a udp check without a port: %v", err)
	}
	dns.HealthCheck = &rpmgrv1.HealthCheck{Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, Port: 53}
	if _, err := createRoute(ada, org, dns, ""); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a udp http check: %v", err)
	}
	dns.HealthCheck = &rpmgrv1.HealthCheck{Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP, Port: 53}
	dnsRt, err := createRoute(ada, org, dns, "")
	if err != nil {
		t.Fatalf("a udp tcp check of a port: %v", err)
	}

	// A check port and a Unix socket target exclude each other.
	sock := &rpmgrv1.RouteTarget{ConnectorId: e.addConnector(t, org, "c1", nil).ID, Address: &rpmgrv1.RouteTarget_UnixPath{UnixPath: "/run/app.sock"},
		Enabled: true}
	if _, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: created.GetId(), Target: sock})); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a socket target under a check port: %v", err)
	}
	if _, err := update(ada, created.GetId(), &rpmgrv1.HealthCheck{Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP}); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: created.GetId(), Target: sock})); err != nil {
		t.Fatalf("a socket target under a check of the target's port: %v", err)
	}
	if _, err := update(ada, created.GetId(), tcpCheck); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("a check port over a socket target: %v", err)
	}

	// An http check speaks HTTP/1.1: no h2c target under it, either way round.
	grpc := httpRoute("grpc", group, "grpc.example.com")
	grpcRt, err := createRoute(ada, org, grpc, "")
	if err != nil {
		t.Fatal(err)
	}
	h2c := addressTarget(sock.GetConnectorId(), "10.0.0.8", 9000)
	h2c.UpstreamProtocol = rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_H2C
	if _, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: grpcRt.GetId(), Target: h2c})); err != nil {
		t.Fatal(err)
	}
	if _, err := update(ada, grpcRt.GetId(), httpCheck); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("an http check over an h2c target: %v", err)
	}
	if _, err := update(ada, grpcRt.GetId(), &rpmgrv1.HealthCheck{Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP}); err != nil {
		t.Errorf("a tcp check over an h2c target: %v", err)
	}
	web2 := httpRoute("web2", group, "web2.example.com")
	web2.HealthCheck = httpCheck
	web2Rt, err := createRoute(ada, org, web2, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: web2Rt.GetId(), Target: h2c})); code(err) != connect.CodeFailedPrecondition {
		t.Errorf("an h2c target under an http check: %v", err)
	}

	// A Viewer sees the check and changes nothing.
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	got, err := vwr.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: created.GetId()}))
	if err != nil || got.Msg.GetRoute().GetHealthCheck().GetType() != rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP {
		t.Fatalf("a Viewer reads: %v %v", got, err)
	}
	if _, err := update(vwr, created.GetId(), nil); code(err) != connect.CodePermissionDenied {
		t.Errorf("a Viewer removes the check: %v", err)
	}

	// Removed by an update without one, and with its route.
	if up, err := update(ada, created.GetId(), nil); err != nil || up.GetHealthCheck() != nil {
		t.Fatalf("a removed check: %v %v", up, err)
	}
	if _, err := ada.rt.DeleteRoute(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteRequest{RouteId: dnsRt.GetId()})); err != nil {
		t.Fatal(err)
	}
	if n := e.db.Client().HealthCheck.Query().Where(healthcheck.RouteIDIn(created.GetId(), dnsRt.GetId())).CountX(e.sys); n != 0 {
		t.Errorf("%d checks left", n)
	}
}

// TestRouteStatus_Health (D133): a target its connector reports unhealthy, while the route is ready
// there, is not serving with the reason targets_unhealthy and the route degraded; a route whose
// connectors all report every target unhealthy is unavailable, each target with its own failure
// where its connector reported one; a target whose connector runs no checks is listed as health
// not checked.
func TestRouteStatus_Health(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	epoch := c.Instance.GetX(e.sys, 1).DbEpoch
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
		PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := e.addConnector(t, org, "c1", nil).ID, e.addConnector(t, org, "c2", nil).ID
	pg := tcpRoute("pg", group, 20001)
	pg.HealthCheck = &rpmgrv1.HealthCheck{Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP}
	rt, err := createRoute(ada, org, pg, "")
	if err != nil {
		t.Fatal(err)
	}
	var tgs []string
	for _, con := range []string{c1, c1, c2} {
		r, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: rt.GetId(),
			Target: addressTarget(con, "10.0.0."+strconv.Itoa(5+len(tgs)), 5432)}))
		if err != nil {
			t.Fatal(err)
		}
		tgs = append(tgs, r.Msg.GetTarget().GetId())
	}
	applied := c.ConfigRevision.Query().Order(ent.Desc(configrevision.FieldID)).FirstX(e.sys).ID
	caps := map[string][]string{gw.GetId(): {"tunnel.quic"}, c1: {agentproto.CapHealthActive}, c2: nil}
	for _, id := range []string{gw.GetId(), c1, c2} {
		c.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetConnectedAt(e.clock).
			SetLastSeenAt(e.clock).SetCapabilities(caps[id]).ExecX(e.sys)
		c.AgentState.Create().SetID(id).SetOrgID(org).SetAppliedDbEpoch(epoch).SetAppliedSeq(applied).SetAppliedHash([]byte("h")).
			SetPushedDbEpoch(epoch).SetPushedSeq(applied).SetPushedHash([]byte("h")).SetPushedAt(e.clock).ExecX(e.sys)
	}
	for _, con := range []string{c1, c2} {
		c.DataSession.Create().SetOrgID(org).SetGatewayID(gw.GetId()).SetConnectorID(con).SetTransport("quic").SetEstablishedAt(e.clock).
			SetReportedAt(e.clock).ExecX(e.sys)
	}
	status := func() *rpmgrv1.RouteStatus {
		t.Helper()
		r, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: rt.GetId()}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetRoute().GetStatus()
	}
	if st := status(); st.GetState() != rpmgrv1.RouteState_ROUTE_STATE_READY || !slices.Equal(st.GetHealthNotChecked(), tgs[2:]) {
		t.Fatalf("every target ready: %v", st)
	}
	notReady := func(agent, resource string) {
		c.ResourceStatus.Create().SetOrgID(org).SetAgentID(agent).SetResourceID(resource).SetReason("NOT_READY_REASON_TARGETS_UNHEALTHY").
			SetDetail("connection refused").SetSince(e.clock).ExecX(e.sys)
	}
	notReady(c1, tgs[1])
	st := status()
	if st.GetState() != rpmgrv1.RouteState_ROUTE_STATE_DEGRADED || st.GetTargetsReady() != 2 || len(st.GetNotServing()) != 1 ||
		st.GetNotServing()[0].GetId() != tgs[1] || st.GetNotServing()[0].GetReason() != "TARGETS_UNHEALTHY" ||
		st.GetNotServing()[0].GetDetail() != "connection refused" {
		t.Fatalf("one unhealthy target: %v", st)
	}
	notReady(c1, rt.GetId())
	notReady(c2, rt.GetId())
	st = status()
	if st.GetState() != rpmgrv1.RouteState_ROUTE_STATE_UNAVAILABLE || st.GetTargetsReady() != 0 || len(st.GetNotServing()) != 3 {
		t.Fatalf("every target unhealthy: %v", st)
	}
	// A target's own failure is shown rather than the route's, which says less.
	c.ResourceStatus.Update().Where(resourcestatus.ResourceID(rt.GetId())).SetDetail("every target failed").ExecX(e.sys)
	for _, ns := range status().GetNotServing() {
		if want := map[bool]string{true: "connection refused", false: "every target failed"}[ns.GetId() == tgs[1]]; ns.GetDetail() != want {
			t.Errorf("target %s: detail %q, want %q", ns.GetId(), ns.GetDetail(), want)
		}
	}
}

// TestRouteHealthCheck_ConnectorAccepts: every check the API accepts, compiled for its connector,
// passes the connector's own validation, so that no accepted check makes a connector reject its
// snapshot: intervals near the minimum with and without a timeout, check ports, socket targets,
// status ranges, host header overrides, https targets and every route type; and the checks the
// connector would refuse, the API refuses too.
func TestRouteHealthCheck_ConnectorAccepts(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	for _, p := range []rpmgrv1.PortProtocol{tcp, udp} {
		if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org,
			PortPool: &rpmgrv1.PortPool{GatewayGroupId: group, Protocol: p, PortFrom: 20000, PortTo: 20099}})); err != nil {
			t.Fatal(err)
		}
	}
	con := e.addConnector(t, org, "nas", nil).ID
	tcpCheck := func(interval, timeout, port uint32) *rpmgrv1.HealthCheck {
		return &rpmgrv1.HealthCheck{Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP, IntervalSeconds: interval, TimeoutSeconds: timeout, Port: port}
	}
	httpCheck := &rpmgrv1.HealthCheck{Type: rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, HttpPath: "/healthz?x=1", ExpectedStatusMin: 100,
		ExpectedStatusMax: 599, IntervalSeconds: 3600, TimeoutSeconds: 60, UnhealthyThreshold: 10, HealthyThreshold: 10}
	port := uint32(20000)
	next := func() uint32 { port++; return port }
	web := func(name string, set func(*rpmgrv1.HTTPRouteSpec)) *rpmgrv1.Route {
		r := httpRoute(name, group, name+".example.com")
		if set != nil {
			set(r.GetHttp())
		}
		return r
	}
	https := addressTarget(con, "10.0.0.9", 8443)
	https.UpstreamProtocol, https.Tls = rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTPS, &rpmgrv1.UpstreamTLSSettings{ServerName: "app.internal"}
	socket := &rpmgrv1.RouteTarget{ConnectorId: con, Address: &rpmgrv1.RouteTarget_UnixPath{UnixPath: "/run/app.sock"}}
	cases := []struct {
		name    string
		route   *rpmgrv1.Route
		check   *rpmgrv1.HealthCheck
		targets []*rpmgrv1.RouteTarget
	}{
		{"interval 2 s, no timeout", tcpRoute("i2", group, next()), tcpCheck(2, 0, 0), nil},
		{"interval 3 s, no timeout", tcpRoute("i3", group, next()), tcpCheck(3, 0, 0), nil},
		{"interval 5 s, no timeout", tcpRoute("i5", group, next()), tcpCheck(5, 0, 0), nil},
		{"interval 6 s, no timeout", tcpRoute("i6", group, next()), tcpCheck(6, 0, 0), nil},
		{"interval 2 s, timeout 1 s", tcpRoute("i2t", group, next()), tcpCheck(2, 1, 0), nil},
		{"interval 5 s, timeout 4 s", tcpRoute("i5t", group, next()), tcpCheck(5, 4, 0), nil},
		{"no interval, timeout 9 s", tcpRoute("t9", group, next()), tcpCheck(0, 9, 0), nil},
		{"defaults", tcpRoute("def", group, next()), tcpCheck(0, 0, 0), nil},
		{"a check port", tcpRoute("port", group, next()), tcpCheck(0, 0, 65535), nil},
		{"an http check of a tcp route", tcpRoute("tcphttp", group, next()), httpCheck, nil},
		{"udp, a port", udpRoute("udp", group, next()), tcpCheck(2, 0, 53), nil},
		{"tcp_udp", tcpUDPRoute("both", group, next()), tcpCheck(0, 0, 0), nil},
		{"tls_passthrough", passthroughRoute("pass", group, "pass.example.com"), tcpCheck(0, 0, 8443), nil},
		{"http, the hostname", web("plain", nil), httpCheck, nil},
		{"http, a host header", web("hh", func(h *rpmgrv1.HTTPRouteSpec) { h.HostHeader = "backend.internal:8080" }), httpCheck, nil},
		{"http, preserve", web("keep", func(h *rpmgrv1.HTTPRouteSpec) { h.HostHeader = "preserve" }), httpCheck, nil},
		{"http, a socket", web("sock", nil), httpCheck, []*rpmgrv1.RouteTarget{socket}},
		{"http, https", web("tls", nil), httpCheck, []*rpmgrv1.RouteTarget{https}},
		{"http, a tcp check of a socket", web("socktcp", nil), tcpCheck(2, 0, 0), []*rpmgrv1.RouteTarget{socket}},
	}
	for _, c := range cases {
		c.route.HealthCheck = c.check
		rt, err := createRoute(ada, org, c.route, "")
		if err != nil {
			t.Fatalf("%s: the API refused %v: %v", c.name, c.check, err)
		}
		targets := c.targets
		if targets == nil {
			targets = []*rpmgrv1.RouteTarget{addressTarget(con, "10.0.0.5", 8080)}
		}
		for _, tg := range targets {
			if _, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: rt.GetId(),
				Target: proto.Clone(tg).(*rpmgrv1.RouteTarget)})); err != nil {
				t.Fatalf("%s: target %v: %v", c.name, tg, err)
			}
		}
	}

	snap := &agentv1.Snapshot{}
	if err := store.ReadTx(e.sys, e.db, func(tx *ent.Tx, _ store.Revision) error {
		a := snapshot.Agent{Identity: pki.Identity{TrustDomain: "rpmgr-teststor", Org: org, Kind: pki.KindConnector, ID: con}}
		for _, src := range routes.Sources() {
			rs, err := src(e.sys, tx, a)
			if err != nil {
				return err
			}
			snap.Resources = append(snap.Resources, rs...)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, r := range snap.GetResources() {
		if r.GetConnectorRoute().GetHealthCheck() != nil {
			checked++
		}
	}
	if checked != len(cases) {
		t.Fatalf("%d compiled checks, want %d", checked, len(cases))
	}
	if errs := connector.NewApplier(nil, nil).Validate(snap); len(errs) != 0 {
		t.Fatalf("the connector refuses checks the API accepted: %v", errs)
	}

	// What the connector refuses, the API refuses first.
	for name, rt := range map[string]*rpmgrv1.Route{
		"interval 1 s":               tcpRoute("x1", group, next()),
		"an http check, passthrough": passthroughRoute("x2", group, "x2.example.com"),
		"timeout 61 s":               tcpRoute("x3", group, next()),
	} {
		switch name {
		case "interval 1 s":
			rt.HealthCheck = tcpCheck(1, 0, 0)
		case "an http check, passthrough":
			rt.HealthCheck = httpCheck
		default:
			rt.HealthCheck = tcpCheck(3600, 61, 0)
		}
		if _, err := createRoute(ada, org, rt, ""); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want INVALID_ARGUMENT", name, err)
		}
	}
}
