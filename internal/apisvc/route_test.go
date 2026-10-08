// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// verified adds a verified domain claim of org.
func (e *env) verified(t *testing.T, org, fqdn string, wildcard bool) string {
	t.Helper()
	return e.db.Client().Domain.Create().SetOrgID(org).SetFqdn(fqdn).SetWildcard(wildcard).SetStatus(domain.StatusVerified).
		SetChallengeValue("v").SaveX(e.sys).ID
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
