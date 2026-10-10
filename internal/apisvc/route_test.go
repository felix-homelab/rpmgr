// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// verified adds a verified domain claim of org.
func (e *env) verified(t *testing.T, org, fqdn string, wildcard bool) string {
	t.Helper()
	return e.db.Client().Domain.Create().SetOrgID(org).SetFqdn(fqdn).SetWildcard(wildcard).SetStatus(domain.StatusVerified).
		SetChallengeValue("v").SaveX(e.sys).ID
}

func httpRoute(name, group string, hostnames ...string) *rpmgrv1.Route {
	return &rpmgrv1.Route{Name: name, GatewayGroupId: group, Spec: &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{Hostnames: hostnames}}}
}

func passthroughRoute(name, group string, hostnames ...string) *rpmgrv1.Route {
	return &rpmgrv1.Route{Name: name, GatewayGroupId: group, Spec: &rpmgrv1.Route_TlsPassthrough{TlsPassthrough: &rpmgrv1.TLSPassthroughRouteSpec{
		Hostnames: hostnames}}}
}

func createRoute(b *browser, org string, rt *rpmgrv1.Route, requestID string) (*rpmgrv1.Route, error) {
	r, err := b.rt.CreateRoute(context.Background(), connect.NewRequest(&rpmgrv1.CreateRouteRequest{OrgId: org, Route: rt, RequestId: requestID}))
	if err != nil {
		return nil, err
	}
	return r.Msg.GetRoute(), nil
}

// TestRoutes: tls_passthrough routes are created with their hostnames under verified domains,
// read, listed and deleted; a hostname is one passthrough route in a group; a Viewer reads but
// creates nothing.
func TestRoutes(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	db := passthroughRoute("db", group, "db.example.com", "DB2.example.com.")
	db.Labels, db.Description, db.Transport = map[string]string{"tier": "data"}, "the database", rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC
	got, err := createRoute(ada, org, db, "req-1")
	if err != nil || got.GetEtag() != "1" || !got.GetEnabled() || got.GetLabels()["tier"] != "data" || got.GetDescription() != "the database" ||
		got.GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC || len(got.GetTlsPassthrough().GetHostnames()) != 2 ||
		got.GetTlsPassthrough().GetHostnames()[1] != "db2.example.com" || got.GetCreateTime() == nil {
		t.Fatalf("a passthrough route: %v %v", got, err)
	}
	if again, err := createRoute(ada, org, db, "req-1"); err != nil || again.GetId() != got.GetId() {
		t.Fatalf("a retry: %v %v", again, err)
	}
	if _, err := createRoute(ada, org, passthroughRoute("mq", group, "mq.example.com"), ""); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		rt   *rpmgrv1.Route
		code connect.Code
	}{
		"a taken name":      {passthroughRoute("db", group, "new.example.com"), connect.CodeAlreadyExists},
		"a taken hostname":  {passthroughRoute("db-2", group, "db.example.com"), connect.CodeAlreadyExists},
		"no spec":           {&rpmgrv1.Route{Name: "nospec", GatewayGroupId: group}, connect.CodeInvalidArgument},
		"no hostname":       {passthroughRoute("none", group), connect.CodeInvalidArgument},
		"a bad hostname":    {passthroughRoute("bad", group, "exa_mple.example.com"), connect.CodeInvalidArgument},
		"a malformed name":  {passthroughRoute("Not A Slug", group, "x.example.com"), connect.CodeInvalidArgument},
		"an unknown policy": {func() *rpmgrv1.Route { r := passthroughRoute("tp", group, "tp.example.com"); r.Transport = 9; return r }(), connect.CodeInvalidArgument},
		"a missing group":   {passthroughRoute("g", "gwg_missing", "g.example.com"), connect.CodeNotFound},
		"a hostname twice":  {passthroughRoute("twice", group, "t.example.com", "t.example.com"), connect.CodeInvalidArgument},
	} {
		if _, err := createRoute(ada, org, c.rt, ""); code(err) != c.code {
			t.Errorf("%s: %v, want %v", name, err, c.code)
		}
	}

	list, err := ada.rt.ListRoutes(ctx, connect.NewRequest(&rpmgrv1.ListRoutesRequest{OrgId: org, PageSize: 1}))
	if err != nil || len(list.Msg.GetRoutes()) != 1 || list.Msg.GetNextPageToken() == "" {
		t.Fatalf("the first page: %v %v", list, err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := createRoute(vwr, org, passthroughRoute("v", group, "v.example.com"), ""); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer creates: %v", err)
	}
	read, err := vwr.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: got.GetId()}))
	if err != nil || read.Msg.GetRoute().GetTlsPassthrough().GetHostnames()[0] != "db.example.com" {
		t.Fatalf("a Viewer reads: %v %v", read, err)
	}
	del := func(id, etag string) error {
		_, err := ada.rt.DeleteRoute(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteRequest{RouteId: id, Etag: etag}))
		return err
	}
	if err := del(got.GetId(), "7"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	if err := del(got.GetId(), "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := createRoute(ada, org, passthroughRoute("db-again", group, "db.example.com"), ""); err != nil {
		t.Fatalf("the freed hostname: %v", err)
	}
	if _, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: got.GetId()})); code(err) != connect.CodeNotFound {
		t.Fatalf("a deleted route: %v", err)
	}
}

// TestUnverifiedDomainRejected (docs/12-testing-and-quality.md, "Security testing"): a route on
// a hostname outside the org's verified domains is refused: under no claim, under a pending
// claim, under another org's verified domain, below or a wildcard of an exact claim; nothing is
// created; once the claim is verified, the same route is created.
func TestUnverifiedDomainRejected(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	orgB := storetest.Org(t, e.db, "org-b")
	e.verified(t, orgB, "b.example", true)
	e.verified(t, org, "exact.example", false)
	pending := e.db.Client().Domain.Create().SetOrgID(org).SetFqdn("pending.example").SetWildcard(true).SetChallengeValue("v").SaveX(e.sys)
	for name, rt := range map[string]*rpmgrv1.Route{
		"no claim":                    passthroughRoute("a", group, "nowhere.example"),
		"a pending claim":             passthroughRoute("b", group, "app.pending.example"),
		"another org's domain":        passthroughRoute("c", group, "app.b.example"),
		"a name below an exact claim": passthroughRoute("d", group, "app.exact.example"),
		"a wildcard of an exact one":  passthroughRoute("e", group, "*.exact.example"),
		"one of two not owned":        passthroughRoute("f", group, "exact.example", "nowhere.example"),
		"an http route, no claim":     httpRoute("g", group, "nowhere.example"),
		"an http route, pending":      httpRoute("h", group, "web.pending.example"),
	} {
		if _, err := createRoute(ada, org, rt, ""); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonDomainNotVerified {
			t.Errorf("%s: %v", name, err)
		}
	}
	routes, _ := ada.rt.ListRoutes(context.Background(), connect.NewRequest(&rpmgrv1.ListRoutesRequest{OrgId: org}))
	if n := len(routes.Msg.GetRoutes()); n != 0 {
		t.Fatalf("%d routes were created", n)
	}
	e.db.Client().Domain.UpdateOne(pending).SetStatus(domain.StatusVerified).ExecX(e.sys)
	if _, err := createRoute(ada, org, passthroughRoute("b", group, "app.pending.example"), ""); err != nil {
		t.Fatalf("after the claim was verified: %v", err)
	}
}

// TestHTTPRoutes: http routes, next to tls_passthrough ones, are created with their hostnames under verified
// domains, read, listed and deleted; a hostname is one passthrough route or http routes with
// distinct path prefixes in a group; header names are canonical and the gateway's own refused;
// ACME is refused for a wildcard hostname; a Viewer reads but creates nothing.
func TestHTTPRoutes(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	web := httpRoute("web", group, "app.example.com")
	web.GetHttp().PathPrefix = "/api"
	web.GetHttp().RequestHeadersSet = map[string]string{"x-env": "prod"}
	web.Labels = map[string]string{"tier": "front"}
	got, err := createRoute(ada, org, web, "req-1")
	h := got.GetHttp()
	if err != nil || got.GetEtag() != "1" || !got.GetEnabled() || h.GetPathPrefix() != "/api" || h.GetRequestHeadersSet()["X-Env"] != "prod" ||
		h.GetWebsocket() != true || h.GetPort80() != rpmgrv1.Port80Mode_PORT80_MODE_REDIRECT || h.GetTlsMode() != rpmgrv1.TLSMode_TLS_MODE_ACME ||
		h.GetHostHeader() != "preserve" || got.GetLabels()["tier"] != "front" || len(h.GetHostnames()) != 1 {
		t.Fatalf("an http route: %v %v", got, err)
	}
	if again, err := createRoute(ada, org, web, "req-1"); err != nil || again.GetId() != got.GetId() {
		t.Fatalf("a retry: %v %v", again, err)
	}
	if _, err := createRoute(ada, org, passthroughRoute("db", group, "db.example.com"), ""); err != nil {
		t.Fatal(err)
	}
	other := httpRoute("web-root", group, "app.example.com")
	if _, err := createRoute(ada, org, other, ""); err != nil {
		t.Fatalf("the same hostname with another prefix: %v", err)
	}

	cert := func(mode rpmgrv1.TLSMode, id string, hostnames ...string) *rpmgrv1.Route {
		r := httpRoute("tls", group, hostnames...)
		r.GetHttp().TlsMode, r.GetHttp().CertificateId = mode, id
		return r
	}
	headers := func(set map[string]string) *rpmgrv1.Route {
		r := httpRoute("hdr", group, "hdr.example.com")
		r.GetHttp().ResponseHeadersSet = set
		return r
	}
	for name, c := range map[string]struct {
		rt         *rpmgrv1.Route
		code       connect.Code
		reasonWant string
	}{
		"a taken name":                {httpRoute("web", group, "new.example.com"), connect.CodeAlreadyExists, ""},
		"passthrough on an http name": {passthroughRoute("pt", group, "app.example.com"), connect.CodeAlreadyExists, ""},
		"http on a passthrough name":  {httpRoute("h2", group, "db.example.com"), connect.CodeAlreadyExists, ""},
		"the same name and prefix": {func() *rpmgrv1.Route {
			r := httpRoute("h3", group, "app.example.com")
			r.GetHttp().PathPrefix = "/api"
			return r
		}(), connect.CodeAlreadyExists, ""},
		"no spec":     {&rpmgrv1.Route{Name: "nospec", GatewayGroupId: group}, connect.CodeInvalidArgument, ""},
		"no hostname": {httpRoute("none", group), connect.CodeInvalidArgument, ""},
		"a prefix without /": {func() *rpmgrv1.Route {
			r := httpRoute("p", group, "p.example.com")
			r.GetHttp().PathPrefix = "api"
			return r
		}(), connect.CodeInvalidArgument, ""},
		"a bad header name":          {headers(map[string]string{"Bad Header": "x"}), connect.CodeInvalidArgument, ""},
		"a header with a line break": {headers(map[string]string{"X-Note": "a\r\nSet-Cookie: x"}), connect.CodeInvalidArgument, ""},
		"the gateway's header":       {headers(map[string]string{"x-forwarded-for": "1.2.3.4"}), connect.CodeInvalidArgument, ""},
		"a bad host header": {func() *rpmgrv1.Route {
			r := httpRoute("hh", group, "hh.example.com")
			r.GetHttp().HostHeader = "bad host"
			return r
		}(), connect.CodeInvalidArgument, ""},
		"a certificate mode, no id":  {cert(rpmgrv1.TLSMode_TLS_MODE_CERTIFICATE, "", "c.example.com"), connect.CodeInvalidArgument, ""},
		"ACME with a certificate id": {cert(rpmgrv1.TLSMode_TLS_MODE_ACME, "crt_x", "c.example.com"), connect.CodeInvalidArgument, ""},
		"a missing certificate":      {cert(rpmgrv1.TLSMode_TLS_MODE_CERTIFICATE, "crt_missing", "c.example.com"), connect.CodeNotFound, ""},
		"ACME for a wildcard":        {cert(rpmgrv1.TLSMode_TLS_MODE_UNSPECIFIED, "", "*.example.com"), connect.CodeFailedPrecondition, apisvc.ReasonWildcardACME},
		"a missing group":            {httpRoute("g", "gwg_missing", "g.example.com"), connect.CodeNotFound, ""},
	} {
		_, err := createRoute(ada, org, c.rt, "")
		if code(err) != c.code || c.reasonWant != "" && reason(err) != c.reasonWant {
			t.Errorf("%s: %v, want %v %s", name, err, c.code, c.reasonWant)
		}
	}

	list, err := ada.rt.ListRoutes(ctx, connect.NewRequest(&rpmgrv1.ListRoutesRequest{OrgId: org, PageSize: 2}))
	if err != nil || len(list.Msg.GetRoutes()) != 2 || list.Msg.GetNextPageToken() == "" {
		t.Fatalf("the first page: %v %v", list, err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := createRoute(vwr, org, httpRoute("v", group, "v.example.com"), ""); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer creates: %v", err)
	}
	read, err := vwr.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: got.GetId()}))
	if err != nil || read.Msg.GetRoute().GetHttp().GetHostnames()[0] != "app.example.com" {
		t.Fatalf("a Viewer reads: %v %v", read, err)
	}
	del := func(id, etag string) error {
		_, err := ada.rt.DeleteRoute(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteRequest{RouteId: id, Etag: etag}))
		return err
	}
	if err := del(got.GetId(), "7"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	if err := del(got.GetId(), "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := createRoute(ada, org, func() *rpmgrv1.Route {
		r := httpRoute("again", group, "app.example.com")
		r.GetHttp().PathPrefix = "/api"
		return r
	}(), ""); err != nil {
		t.Fatalf("the freed hostname and prefix: %v", err)
	}
	if _, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: got.GetId()})); code(err) != connect.CodeNotFound {
		t.Fatalf("a deleted route: %v", err)
	}
}

// TestRoutes_GatewayAcceptsThem: routes the API accepts, with every http setting, access
// policies and a target each, an HTTPS one verified by a pin, compile into a snapshot the gateway
// validates without an error.
func TestRoutes_GatewayAcceptsThem(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	e.verified(t, org, "example.com", true)
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	off := false
	full := httpRoute("full", group, "app.example.com", "www.example.com")
	h := full.GetHttp()
	h.PathPrefix, h.Port80, h.HstsMaxAgeSeconds, h.HostHeader = "/v1", rpmgrv1.Port80Mode_PORT80_MODE_SERVE, 31536000, "upstream.internal"
	h.RequestHeadersSet = map[string]string{"x-env": "prod", "Authorization": "Bearer abc"}
	h.ResponseHeadersSet = map[string]string{"cache-control": "no-store"}
	h.Websocket, h.MaxBodyBytes = &off, 1<<20
	for _, p := range []*rpmgrv1.PortPool{{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009},
		{GatewayGroupId: group, Protocol: udp, PortFrom: 30000, PortTo: 30009}} {
		if _, err := ada.gw.CreatePortPool(context.Background(), connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org, PortPool: p})); err != nil {
			t.Fatal(err)
		}
	}
	con := e.addConnector(t, org, "nas", nil).ID
	policy := func(name string, rules ...*rpmgrv1.AccessRule) string {
		r, err := ada.pol.CreateAccessPolicy(context.Background(), connect.NewRequest(&rpmgrv1.CreateAccessPolicyRequest{OrgId: org,
			AccessPolicy: &rpmgrv1.AccessPolicy{Name: name, Rules: rules}}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.GetAccessPolicy().GetId()
	}
	ips := policy("ips", ipAllow("10.0.0.0/8"), &rpmgrv1.AccessRule{Rule: &rpmgrv1.AccessRule_IpDeny{IpDeny: &rpmgrv1.IPRuleParams{Cidrs: []string{"::/0"}}}})
	full.PolicyIds = []string{policy("auth", basicAuth(user("alice", "correct horse battery"))), ips}
	pg := tcpRoute("pg", group, 0)
	pg.PolicyIds = []string{ips}
	for _, rt := range []*rpmgrv1.Route{full, httpRoute("plain", group, "plain.example.com"), passthroughRoute("db", group, "db.example.com"),
		pg, udpRoute("dns", group, 0)} {
		created, err := createRoute(ada, org, rt, "")
		if err != nil {
			t.Fatal(err)
		}
		tg := addressTarget(con, "10.0.0.5", 8443)
		switch rt.GetName() {
		case "full":
			tg.UpstreamProtocol, tg.Tls = rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTPS,
				&rpmgrv1.UpstreamTLSSettings{ServerName: "app.internal", SpkiSha256: strings.Repeat("ab", 32)}
		case "pg":
			tg.ProxyProtocol = rpmgrv1.ProxyProtocol_PROXY_PROTOCOL_V2
		}
		if _, err := ada.rt.CreateRouteTarget(context.Background(), connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: created.GetId(),
			Target: tg})); err != nil {
			t.Fatal(err)
		}
	}
	var snap *agentv1.Snapshot
	if err := store.ReadTx(e.sys, e.db, func(tx *ent.Tx, _ store.Revision) error {
		a := snapshot.Agent{Identity: pki.Identity{TrustDomain: "rpmgr-teststor", Org: org, Kind: pki.KindGateway, ID: gw.GetId()}}
		snap = &agentv1.Snapshot{}
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
	if len(snap.GetResources()) != 5 {
		t.Fatalf("compiled %d resources, want 5", len(snap.GetResources()))
	}
	for _, res := range snap.GetResources() {
		if h := res.GetGatewayHttpRoute(); h.GetHostHeader() == "upstream.internal" && (len(h.GetAccess().GetBasicAuth()) != 1 || len(h.GetAccess().GetIpRules()) != 2) {
			t.Fatalf("the access policies of the full route: %v", h.GetAccess())
		}
		if r := res.GetGatewayTcpRoute(); r != nil && len(r.GetAccess().GetIpRules()) != 2 {
			t.Fatalf("the access policy of the tcp route: %v", r.GetAccess())
		}
	}
	a, _ := gateway.NewApplier()
	if errs := a.Validate(snap); len(errs) != 0 {
		t.Fatalf("the gateway refuses the API's routes: %v", errs)
	}
}

// TestUpdateRoute: an update changes only the masked fields under the etag; a changed spec
// replaces the route's settings and hostnames with every rule checked again, and a refused one
// changes nothing; a route's type, group and ID cannot change; a Viewer changes nothing.
func TestUpdateRoute(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	web := httpRoute("web", group, "app.example.com")
	web.GetHttp().PathPrefix = "/api"
	got, err := createRoute(ada, org, web, "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := createRoute(ada, org, passthroughRoute("db", group, "db.example.com"), "")
	if err != nil {
		t.Fatal(err)
	}
	update := func(b *browser, id string, mask []string, in *rpmgrv1.Route, etag string) (*rpmgrv1.Route, error) {
		in.Id = id
		r, err := b.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: in, UpdateMask: &fieldmaskpb.FieldMask{Paths: mask},
			Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetRoute(), nil
	}
	up, err := update(ada, got.GetId(), []string{"description", "transport"}, &rpmgrv1.Route{Description: "the API",
		Transport: rpmgrv1.DataTransport_DATA_TRANSPORT_H2, Name: "ignored"}, "1")
	if err != nil || up.GetDescription() != "the API" || up.GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_H2 || up.GetName() != "web" ||
		up.GetEtag() != "2" || up.GetHttp().GetPathPrefix() != "/api" {
		t.Fatalf("a description and a transport: %v %v", up, err)
	}
	if _, err := update(ada, got.GetId(), []string{"description"}, &rpmgrv1.Route{}, "1"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	up, err = update(ada, got.GetId(), []string{"http.hostnames", "http.response_headers_set", "transport", "enabled"},
		&rpmgrv1.Route{Spec: &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{Hostnames: []string{"app.example.com", "www.example.com"},
			ResponseHeadersSet: map[string]string{"cache-control": "no-store"}}}}, "")
	if err != nil || len(up.GetHttp().GetHostnames()) != 2 || up.GetHttp().GetResponseHeadersSet()["Cache-Control"] != "no-store" ||
		up.GetHttp().GetPathPrefix() != "/api" || up.GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_UNSPECIFIED || up.GetEnabled() {
		t.Fatalf("new hostnames and headers, the default transport, disabled: %v %v", up, err)
	}
	if n := e.db.Client().RouteHostname.Query().Where(routehostname.RouteID(got.GetId())).CountX(e.sys); n != 2 {
		t.Fatalf("%d hostname rows", n)
	}
	before := up
	for name, c := range map[string]struct {
		id     string
		mask   []string
		in     *rpmgrv1.Route
		code   connect.Code
		reason string
	}{
		"an unverified hostname": {got.GetId(), []string{"http.hostnames"}, &rpmgrv1.Route{Spec: &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{
			Hostnames: []string{"nowhere.example"}}}}, connect.CodeFailedPrecondition, apisvc.ReasonDomainNotVerified},
		"ACME for a wildcard": {got.GetId(), []string{"http.hostnames"}, &rpmgrv1.Route{Spec: &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{
			Hostnames: []string{"*.example.com"}}}}, connect.CodeFailedPrecondition, apisvc.ReasonWildcardACME},
		"the gateway's header": {got.GetId(), []string{"http.request_headers_set"}, &rpmgrv1.Route{Spec: &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{
			RequestHeadersSet: map[string]string{"Forwarded": "x"}}}}, connect.CodeInvalidArgument, ""},
		"no hostname left": {got.GetId(), []string{"http.hostnames"}, &rpmgrv1.Route{}, connect.CodeInvalidArgument, ""},
		"a certificate mode without one": {got.GetId(), []string{"http.tls_mode"}, &rpmgrv1.Route{Spec: &rpmgrv1.Route_Http{Http: &rpmgrv1.HTTPRouteSpec{
			TlsMode: rpmgrv1.TLSMode_TLS_MODE_CERTIFICATE}}}, connect.CodeInvalidArgument, ""},
		"a taken name":                    {got.GetId(), []string{"name"}, &rpmgrv1.Route{Name: "db"}, connect.CodeAlreadyExists, ""},
		"no name":                         {got.GetId(), []string{"name"}, &rpmgrv1.Route{}, connect.CodeInvalidArgument, ""},
		"a passthrough route made http":   {db.GetId(), []string{"http.hostnames"}, &rpmgrv1.Route{}, connect.CodeInvalidArgument, ""},
		"an http route made passthrough":  {got.GetId(), []string{"tls_passthrough.hostnames"}, &rpmgrv1.Route{}, connect.CodeInvalidArgument, ""},
		"the group":                       {got.GetId(), []string{"gateway_group_id"}, &rpmgrv1.Route{}, connect.CodeInvalidArgument, ""},
		"the whole spec":                  {got.GetId(), []string{"http"}, &rpmgrv1.Route{}, connect.CodeInvalidArgument, ""},
		"an empty mask":                   {got.GetId(), nil, &rpmgrv1.Route{}, connect.CodeInvalidArgument, ""},
		"a passthrough host of http name": {db.GetId(), []string{"tls_passthrough.hostnames"}, &rpmgrv1.Route{Spec: &rpmgrv1.Route_TlsPassthrough{TlsPassthrough: &rpmgrv1.TLSPassthroughRouteSpec{Hostnames: []string{"www.example.com"}}}}, connect.CodeAlreadyExists, ""},
	} {
		_, err := update(ada, c.id, c.mask, c.in, "")
		if code(err) != c.code || c.reason != "" && reason(err) != c.reason {
			t.Errorf("%s: %v, want %v %s", name, err, c.code, c.reason)
		}
	}
	after, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: got.GetId()}))
	if err == nil {
		after.Msg.GetRoute().Status = nil // a read adds it, a write does not
	}
	if err != nil || !proto.Equal(after.Msg.GetRoute(), before) {
		t.Fatalf("refused updates changed the route:\n%v\n%v", after.Msg.GetRoute(), before)
	}
	if up, err := update(ada, db.GetId(), []string{"tls_passthrough.hostnames"}, &rpmgrv1.Route{Spec: &rpmgrv1.Route_TlsPassthrough{
		TlsPassthrough: &rpmgrv1.TLSPassthroughRouteSpec{Hostnames: []string{"pg.example.com"}}}}, ""); err != nil ||
		up.GetTlsPassthrough().GetHostnames()[0] != "pg.example.com" {
		t.Fatalf("a passthrough route's hostname: %v %v", up, err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := update(vwr, got.GetId(), []string{"enabled"}, &rpmgrv1.Route{Enabled: true}, ""); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer updates: %v", err)
	}
}

func tcpRoute(name, group string, port uint32) *rpmgrv1.Route {
	return &rpmgrv1.Route{Name: name, GatewayGroupId: group, Spec: &rpmgrv1.Route_Tcp{Tcp: &rpmgrv1.TCPRouteSpec{Port: port}}}
}

func udpRoute(name, group string, port uint32) *rpmgrv1.Route {
	return &rpmgrv1.Route{Name: name, GatewayGroupId: group, Spec: &rpmgrv1.Route_Udp{Udp: &rpmgrv1.UDPRouteSpec{Port: port}}}
}

// TestPortRoutes: tcp and udp routes take an explicit or a random port of the group's pools,
// within the org's quota; a port changes by allocating the new one before freeing the old, so a
// refused port leaves the route as it was; a deleted route frees its port.
func TestPortRoutes(t *testing.T) {
	_, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	for _, p := range []*rpmgrv1.PortPool{{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009},
		{GatewayGroupId: group, Protocol: udp, PortFrom: 30000, PortTo: 30001}} {
		if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org, PortPool: p})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ada.gw.SetPortQuota(ctx, connect.NewRequest(&rpmgrv1.SetPortQuotaRequest{OrgId: org, GatewayGroupId: group, Protocol: tcp,
		MaxPorts: 3})); err != nil {
		t.Fatal(err)
	}
	pg, err := createRoute(ada, org, tcpRoute("pg", group, 20005), "")
	if err != nil || pg.GetTcp().GetPort() != 20005 || pg.GetTcp().GetIdleTimeoutSeconds() != 3600 {
		t.Fatalf("an explicit tcp port: %v %v", pg, err)
	}
	random, err := createRoute(ada, org, tcpRoute("redis", group, 0), "")
	if p := random.GetTcp().GetPort(); err != nil || p < 20000 || p > 20009 || p == 20005 {
		t.Fatalf("a random tcp port: %v %v", random, err)
	}
	dns, err := createRoute(ada, org, udpRoute("dns", group, 0), "")
	if p := dns.GetUdp().GetPort(); err != nil || (p != 30000 && p != 30001) || dns.GetUdp().GetFlowIdleTimeoutSeconds() != 60 {
		t.Fatalf("a random udp port: %v %v", dns, err)
	}
	if _, err := createRoute(ada, org, udpRoute("ntp", group, 0), ""); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		rt     *rpmgrv1.Route
		code   connect.Code
		reason string
	}{
		"a taken port":         {tcpRoute("taken", group, 20005), connect.CodeAlreadyExists, ""},
		"a port outside pools": {tcpRoute("outside", group, 25000), connect.CodeFailedPrecondition, apisvc.ReasonPortNotInPool},
		"a udp pool used up":   {udpRoute("third", group, 0), connect.CodeResourceExhausted, apisvc.ReasonPoolExhausted},
		"port 65536":           {tcpRoute("big", group, 65536), connect.CodeInvalidArgument, ""},
		"a zero flow idle time": {func() *rpmgrv1.Route {
			zero := uint32(0)
			r := udpRoute("z", group, 0)
			r.GetUdp().FlowIdleTimeoutSeconds = &zero
			return r
		}(), connect.CodeInvalidArgument, ""},
	} {
		_, err := createRoute(ada, org, c.rt, "")
		if code(err) != c.code || c.reason != "" && reason(err) != c.reason {
			t.Errorf("%s: %v, want %v %s", name, err, c.code, c.reason)
		}
	}
	third, err := createRoute(ada, org, tcpRoute("third", group, 0), "")
	if err != nil {
		t.Fatalf("the third tcp port, within the quota: %v", err)
	}
	if _, err := createRoute(ada, org, tcpRoute("fourth", group, 0), ""); reason(err) != apisvc.ReasonQuotaReached {
		t.Fatalf("a fourth tcp port beyond the quota: %v", err)
	}

	update := func(id string, mask []string, in *rpmgrv1.Route) (*rpmgrv1.Route, error) {
		in.Id = id
		r, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: in, UpdateMask: &fieldmaskpb.FieldMask{Paths: mask}}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetRoute(), nil
	}
	// A port of the pool that no route has: the random ones may have any.
	free := uint32(20000)
	for slices.Contains([]uint32{20005, random.GetTcp().GetPort(), third.GetTcp().GetPort()}, free) {
		free++
	}
	zero := uint32(0)
	up, err := update(pg.GetId(), []string{"tcp.port", "tcp.idle_timeout_seconds"}, &rpmgrv1.Route{Spec: &rpmgrv1.Route_Tcp{Tcp: &rpmgrv1.TCPRouteSpec{
		Port: free, IdleTimeoutSeconds: &zero}}})
	if err != nil || up.GetTcp().GetPort() != free || up.GetTcp().GetIdleTimeoutSeconds() != 0 {
		t.Fatalf("a new port and no idle timeout: %v %v", up, err)
	}
	if _, err := update(pg.GetId(), []string{"tcp.port"}, tcpRoute("", "", random.GetTcp().GetPort())); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("a taken port: %v", err)
	}
	if got, _ := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: pg.GetId()})); got.Msg.GetRoute().GetTcp().GetPort() != free {
		t.Fatalf("a refused port changed the route: %v", got.Msg.GetRoute())
	}
	if _, err := update(dns.GetId(), []string{"tcp.port"}, tcpRoute("", "", 20001)); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a udp route made tcp: %v", err)
	}
	// The quota is used up, so the freed 20005 is taken by moving a route, not by a new one.
	if up, err := update(random.GetId(), []string{"tcp.port"}, tcpRoute("", "", 20005)); err != nil || up.GetTcp().GetPort() != 20005 {
		t.Fatalf("the freed port: %v %v", up, err)
	}
	if _, err := ada.rt.DeleteRoute(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteRequest{RouteId: dns.GetId()})); err != nil {
		t.Fatal(err)
	}
	if _, err := createRoute(ada, org, udpRoute("dns-2", group, dns.GetUdp().GetPort()), ""); err != nil {
		t.Fatalf("the port of a deleted route: %v", err)
	}
}

func addressTarget(connector, host string, port uint32) *rpmgrv1.RouteTarget {
	return &rpmgrv1.RouteTarget{ConnectorId: connector, Address: &rpmgrv1.RouteTarget_HostPort{HostPort: &rpmgrv1.HostPort{Host: host, Port: port}}}
}

// TestRouteTargets: a target of a connector of the org is added to a route, enabled, with what it
// speaks, its PROXY header and its TLS settings checked against the route's type; an http route's
// enabled targets speak one protocol; a decommissioned connector, another org's connector and a
// missing CA bundle are refused; targets are updated under their etags and deleted; the route
// lists them by priority; a Viewer changes nothing.
func TestRouteTargets(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	for _, p := range []*rpmgrv1.PortPool{{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009},
		{GatewayGroupId: group, Protocol: udp, PortFrom: 30000, PortTo: 30009}} {
		if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org, PortPool: p})); err != nil {
			t.Fatal(err)
		}
	}
	con := e.addConnector(t, org, "nas", nil).ID
	gone := e.addConnector(t, org, "old", func(c *ent.ConnectorCreate) { c.SetDecommissionedAt(e.clock) }).ID
	orgB := storetest.Org(t, e.db, "org-b")
	theirs := e.addConnector(t, orgB, "theirs", nil).ID
	routeID := map[string]string{}
	for _, rt := range []*rpmgrv1.Route{httpRoute("web", group, "web.example.com"), httpRoute("secure", group, "secure.example.com"),
		tcpRoute("pg", group, 0), udpRoute("dns", group, 0), passthroughRoute("db", group, "db.example.com")} {
		got, err := createRoute(ada, org, rt, "")
		if err != nil {
			t.Fatal(err)
		}
		routeID[rt.GetName()] = got.GetId()
	}
	add := func(b *browser, route string, tg *rpmgrv1.RouteTarget) (*rpmgrv1.RouteTarget, error) {
		r, err := b.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: routeID[route], Target: tg}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetTarget(), nil
	}
	web, err := add(ada, "web", addressTarget(con, "10.0.0.5", 8080))
	if err != nil || !web.GetEnabled() || web.GetUpstreamProtocol() != rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTP || web.GetWeight() != 1 ||
		web.GetEtag() != "1" || web.GetProxyProtocol() != rpmgrv1.ProxyProtocol_PROXY_PROTOCOL_NONE {
		t.Fatalf("an http target: %v %v", web, err)
	}
	pin := strings.Repeat("ab", 32)
	https := func(host string, tls *rpmgrv1.UpstreamTLSSettings) *rpmgrv1.RouteTarget {
		tg := addressTarget(con, host, 8443)
		tg.UpstreamProtocol, tg.Tls = rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTPS, tls
		return tg
	}
	if tg, err := add(ada, "secure", https("10.0.0.6", &rpmgrv1.UpstreamTLSSettings{ServerName: "app.internal", SpkiSha256: pin})); err != nil ||
		tg.GetTls().GetSpkiSha256() != pin || tg.GetTls().GetServerName() != "app.internal" {
		t.Fatalf("an https target: %v %v", tg, err)
	}
	proxied := addressTarget(con, "10.0.0.7", 5432)
	proxied.ProxyProtocol, proxied.Priority = rpmgrv1.ProxyProtocol_PROXY_PROTOCOL_V2, 1
	if _, err := add(ada, "pg", proxied); err != nil {
		t.Fatalf("a tcp target with PROXY v2: %v", err)
	}
	if _, err := add(ada, "pg", &rpmgrv1.RouteTarget{ConnectorId: con, Address: &rpmgrv1.RouteTarget_UnixPath{UnixPath: "/run/pg/.s.PGSQL.5432"}}); err != nil {
		t.Fatalf("a tcp target on a socket: %v", err)
	}
	if _, err := add(ada, "dns", addressTarget(con, "10.0.0.53", 53)); err != nil {
		t.Fatalf("a udp target: %v", err)
	}
	unix := func(p string) *rpmgrv1.RouteTarget {
		return &rpmgrv1.RouteTarget{ConnectorId: con, Address: &rpmgrv1.RouteTarget_UnixPath{UnixPath: p}}
	}
	for name, c := range map[string]struct {
		route string
		tg    *rpmgrv1.RouteTarget
		code  connect.Code
	}{
		"a second protocol on an http route": {"web", https("10.0.0.8", nil), connect.CodeFailedPrecondition},
		"TCP on an http route":               {"web", func() *rpmgrv1.RouteTarget { tg := addressTarget(con, "h", 1); tg.UpstreamProtocol = 1; return tg }(), connect.CodeInvalidArgument},
		"HTTP on a tcp route":                {"pg", func() *rpmgrv1.RouteTarget { tg := addressTarget(con, "h", 1); tg.UpstreamProtocol = 2; return tg }(), connect.CodeInvalidArgument},
		"a socket for a udp route":           {"dns", unix("/run/dns.sock"), connect.CodeInvalidArgument},
		"a PROXY header for a udp route":     {"dns", func() *rpmgrv1.RouteTarget { tg := addressTarget(con, "h", 53); tg.ProxyProtocol = 2; return tg }(), connect.CodeInvalidArgument},
		"a PROXY header for an http route":   {"web", func() *rpmgrv1.RouteTarget { tg := addressTarget(con, "h", 80); tg.ProxyProtocol = 2; return tg }(), connect.CodeInvalidArgument},
		"TLS settings for HTTP": {"web", func() *rpmgrv1.RouteTarget {
			tg := addressTarget(con, "h", 80)
			tg.Tls = &rpmgrv1.UpstreamTLSSettings{ServerName: "x"}
			return tg
		}(), connect.CodeInvalidArgument},
		"HTTPS on a socket, no server name": {"secure", func() *rpmgrv1.RouteTarget { tg := unix("/run/app.sock"); tg.UpstreamProtocol = 3; return tg }(), connect.CodeInvalidArgument},
		"a bad pin":                         {"secure", https("10.0.0.9", &rpmgrv1.UpstreamTLSSettings{SpkiSha256: "abc"}), connect.CodeInvalidArgument},
		"a missing CA bundle":               {"secure", https("10.0.0.9", &rpmgrv1.UpstreamTLSSettings{CaBundleId: "cab_missing"}), connect.CodeNotFound},
		"no address":                        {"pg", &rpmgrv1.RouteTarget{ConnectorId: con}, connect.CodeInvalidArgument},
		"an unclean path":                   {"pg", unix("/run/../x.sock"), connect.CodeInvalidArgument},
		"a relative path":                   {"pg", unix("run/x.sock"), connect.CodeInvalidArgument},
		"port 0":                            {"pg", addressTarget(con, "10.0.0.7", 0), connect.CodeInvalidArgument},
		"weight 1001":                       {"pg", func() *rpmgrv1.RouteTarget { tg := addressTarget(con, "h", 1); tg.Weight = 1001; return tg }(), connect.CodeInvalidArgument},
		"a decommissioned connector":        {"pg", addressTarget(gone, "10.0.0.7", 5432), connect.CodeFailedPrecondition},
		"another org's connector":           {"pg", addressTarget(theirs, "10.0.0.7", 5432), connect.CodeNotFound},
		"a missing connector":               {"pg", addressTarget("con_missing", "10.0.0.7", 5432), connect.CodeNotFound},
	} {
		if _, err := add(ada, c.route, c.tg); code(err) != c.code {
			t.Errorf("%s: %v, want %v", name, err, c.code)
		}
	}

	read, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: routeID["pg"]}))
	if ts := read.Msg.GetRoute().GetTargets(); err != nil || len(ts) != 2 || ts[0].GetUnixPath() == "" || ts[1].GetPriority() != 1 {
		t.Fatalf("the tcp route's targets by priority: %v %v", read, err)
	}
	update := func(id string, mask []string, in *rpmgrv1.RouteTarget, etag string) (*rpmgrv1.RouteTarget, error) {
		in.Id = id
		r, err := ada.rt.UpdateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteTargetRequest{Target: in,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: mask}, Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetTarget(), nil
	}
	up, err := update(web.GetId(), []string{"weight", "enabled"}, &rpmgrv1.RouteTarget{Weight: 5}, "1")
	if err != nil || up.GetWeight() != 5 || up.GetEnabled() || up.GetEtag() != "2" {
		t.Fatalf("a weight and disabled: %v %v", up, err)
	}
	if _, err := update(web.GetId(), []string{"weight"}, &rpmgrv1.RouteTarget{Weight: 2}, "1"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	if _, err := update(web.GetId(), []string{"connector_id"}, &rpmgrv1.RouteTarget{ConnectorId: con}, ""); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a new connector: %v", err)
	}
	// With the HTTP target disabled, an HTTPS one may join; enabling the HTTP one again is refused.
	if _, err := add(ada, "web", https("10.0.0.8", nil)); err != nil {
		t.Fatalf("an https target next to a disabled http one: %v", err)
	}
	if _, err := update(web.GetId(), []string{"enabled"}, &rpmgrv1.RouteTarget{Enabled: true}, ""); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("enabling a target of another protocol: %v", err)
	}
	if up, err := update(web.GetId(), []string{"host_port"}, addressTarget("", "10.0.0.15", 8081), ""); err != nil ||
		up.GetHostPort().GetHost() != "10.0.0.15" {
		t.Fatalf("a new address: %v %v", up, err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := add(vwr, "pg", addressTarget(con, "10.0.0.7", 1)); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer adds: %v", err)
	}
	if _, err := ada.rt.DeleteRouteTarget(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteTargetRequest{RouteTargetId: web.GetId(), Etag: "1"})); reason(err) !=
		api.ReasonEtagMismatch {
		t.Fatalf("a stale etag on delete: %v", err)
	}
	if _, err := ada.rt.DeleteRouteTarget(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteTargetRequest{RouteTargetId: web.GetId()})); err != nil {
		t.Fatal(err)
	}
	if read, _ := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: routeID["web"]})); len(read.Msg.GetRoute().GetTargets()) != 1 {
		t.Fatalf("after the delete: %v", read.Msg.GetRoute().GetTargets())
	}
}

// TestPreviewRoute: a preview runs the write's checks and refuses what it would refuse, shows the
// route as it would be stored, the gateways that would serve it and the connectors its streams
// would go to, and saves nothing: no route, no change, no revision.
func TestPreviewRoute(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	off, err := createGateway(ada, org, group, "gw2", "gw2.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: &rpmgrv1.Gateway{Id: off.GetId()},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"enabled"}}})); err != nil {
		t.Fatal(err)
	}
	con := e.addConnector(t, org, "nas", nil).ID
	web, err := createRoute(ada, org, httpRoute("web", group, "web.example.com"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: web.GetId(),
		Target: addressTarget(con, "10.0.0.5", 8080)})); err != nil {
		t.Fatal(err)
	}
	revision := func() store.Revision {
		var rev store.Revision
		if err := store.ReadTx(e.sys, e.db, func(_ *ent.Tx, r store.Revision) error { rev = r; return nil }); err != nil {
			t.Fatal(err)
		}
		return rev
	}
	before := revision()
	preview := func(b *browser, rt *rpmgrv1.Route, mask []string, etag string) (*rpmgrv1.PreviewRouteResponse, error) {
		req := &rpmgrv1.PreviewRouteRequest{OrgId: org, Route: rt, Etag: etag}
		if mask != nil {
			req.UpdateMask = &fieldmaskpb.FieldMask{Paths: mask}
		}
		r, err := b.rt.PreviewRoute(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	p, err := preview(ada, httpRoute("new", group, "New.example.com"), nil, "")
	if err != nil || p.GetRoute().GetId() != "" || p.GetRoute().GetHttp().GetHostnames()[0] != "new.example.com" ||
		!slices.Equal(p.GetGatewayIds(), []string{gw.GetId()}) || len(p.GetConnectorIds()) != 0 || len(p.GetProblems()) != 0 {
		t.Fatalf("a new route: %v %v", p, err)
	}
	if _, err := preview(ada, httpRoute("bad", group, "nowhere.example"), nil, ""); reason(err) != apisvc.ReasonDomainNotVerified {
		t.Fatalf("an unverified hostname: %v", err)
	}
	if _, err := preview(ada, httpRoute("web", group, "other.example.com"), nil, ""); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("a taken name: %v", err)
	}
	change := httpRoute("", "", "web.example.com", "www.example.com")
	change.Id = web.GetId()
	p, err = preview(ada, change, []string{"http.hostnames"}, "")
	if err != nil || p.GetRoute().GetId() != web.GetId() || len(p.GetRoute().GetHttp().GetHostnames()) != 2 ||
		!slices.Equal(p.GetConnectorIds(), []string{con}) || !slices.Equal(p.GetGatewayIds(), []string{gw.GetId()}) {
		t.Fatalf("a change: %v %v", p, err)
	}
	if _, err := preview(ada, change, []string{"http.hostnames"}, "7"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a change with a stale etag: %v", err)
	}
	if after := revision(); after != before {
		t.Fatalf("a preview made revision %v after %v", after, before)
	}
	got, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: web.GetId()}))
	if err != nil || len(got.Msg.GetRoute().GetHttp().GetHostnames()) != 1 || got.Msg.GetRoute().GetEtag() != web.GetEtag() {
		t.Fatalf("a preview changed the route: %v %v", got, err)
	}
	if list, _ := ada.rt.ListRoutes(ctx, connect.NewRequest(&rpmgrv1.ListRoutesRequest{OrgId: org})); len(list.Msg.GetRoutes()) != 1 {
		t.Fatalf("a preview created a route: %v", list.Msg.GetRoutes())
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := preview(vwr, httpRoute("v", group, "v.example.com"), nil, ""); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer previews: %v", err)
	}
}
