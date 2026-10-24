// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/datasession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/hook"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
)

// addConnector adds an enrolled connector to the org, as enrollment does.
func (e *env) addConnector(t *testing.T, org, name string, edit func(*ent.ConnectorCreate)) *ent.Connector {
	t.Helper()
	c := e.db.Client().Connector.Create().SetOrgID(org).SetName(name).SetSpiffeID("spiffe://rpmgr-teststor/org/" + org + "/connector/" + name).
		SetPubkeySha256("k").SetLabels(map[string]string{"site": "office"})
	if edit != nil {
		edit(c)
	}
	return c.SaveX(e.sys)
}

// TestConnectors_Read: connectors are listed by ID without the decommissioned ones unless asked;
// each carries its control session, connected only while it is live; the status adds its data sessions as its gateways report them
// and the routes it reports not ready; a Viewer reads all of it.
func TestConnectors_Read(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	nas := e.addConnector(t, org, "nas", func(c *ent.ConnectorCreate) { c.SetTransport(connector.TransportH2) })
	pi := e.addConnector(t, org, "pi", nil)
	old := e.addConnector(t, org, "old", func(c *ent.ConnectorCreate) { c.SetDecommissionedAt(e.clock).SetEnabled(false) })
	seen := e.clock.Add(-time.Minute).UTC().Truncate(time.Second)
	e.db.Client().AgentSession.Create().SetID(nas.ID).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").
		SetRemoteAddr("192.0.2.9:40000").SetAgentVersion("v0.1.0").SetCapabilities([]string{"ota"}).SetConnectedAt(seen).SetLastSeenAt(seen).ExecX(e.sys)
	for _, d := range []struct {
		gw, tr string
		rtt    int64
	}{{"gw_b", "h2", 0}, {"gw_a", "quic", 14}, {"gw_a", "h2", 0}} {
		e.db.Client().DataSession.Create().SetOrgID(org).SetGatewayID(d.gw).SetConnectorID(nas.ID).SetTransport(datasessionTransport(d.tr)).
			SetRttMs(d.rtt).SetEstablishedAt(seen).SetReportedAt(seen).ExecX(e.sys)
	}
	// pi was last connected an hour ago and has disconnected since.
	e.db.Client().AgentSession.Create().SetID(pi.ID).SetOrgID(org).SetSessionEpoch(4).SetControllerNode("ctn_1").
		SetAgentVersion("v0.0.9").SetConnectedAt(seen.Add(-time.Hour)).SetLastSeenAt(seen.Add(-time.Hour)).
		SetDisconnectedAt(seen.Add(-time.Hour)).ExecX(e.sys)
	e.db.Client().ResourceStatus.Create().SetOrgID(org).SetAgentID(nas.ID).SetResourceID("rt_1").
		SetReason("NOT_READY_REASON_BLOCKED_BY_LOCAL_POLICY").SetDetail("10.0.0.5:5432").SetSince(seen).ExecX(e.sys)

	list := func(b *browser, all bool, size int32, page string) *rpmgrv1.ListConnectorsResponse {
		t.Helper()
		r, err := b.con.ListConnectors(ctx, connect.NewRequest(&rpmgrv1.ListConnectorsRequest{OrgId: org, ShowDecommissioned: all,
			PageSize: size, PageToken: page}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg
	}
	if got := list(ada, false, 0, ""); len(got.GetConnectors()) != 2 {
		t.Fatalf("connectors in service: %v", got)
	}
	first := list(ada, true, 2, "")
	rest := list(ada, true, 2, first.GetNextPageToken())
	if len(first.GetConnectors()) != 2 || len(rest.GetConnectors()) != 1 || rest.GetNextPageToken() != "" {
		t.Fatalf("two pages: %v / %v", first, rest)
	}
	byName := map[string]*rpmgrv1.Connector{}
	for _, c := range append(first.GetConnectors(), rest.GetConnectors()...) {
		byName[c.GetName()] = c
	}
	n := byName["nas"]
	if !n.GetSession().GetConnected() || n.GetSession().GetVersion() != "v0.1.0" || n.GetSession().GetRemoteAddr() != "192.0.2.9:40000" ||
		!n.GetSession().GetLastSeenTime().AsTime().Equal(seen) || n.GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_H2 ||
		n.GetLabels()["site"] != "office" || n.GetEtag() != "1" || !n.GetSession().GetOverTheAir() {
		t.Fatalf("nas: %v", n)
	}
	if p := byName["pi"]; p.GetSession().GetConnected() || p.GetSession().GetVersion() != "v0.0.9" || p.GetSession().GetOverTheAir() ||
		p.GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_UNSPECIFIED {
		t.Fatalf("pi, disconnected: %v", p)
	}
	if o := byName["old"]; o.GetDecommissionTime() == nil || o.GetEnabled() {
		t.Fatalf("old: %v", o)
	}

	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	st, err := vwr.con.GetConnectorStatus(ctx, connect.NewRequest(&rpmgrv1.GetConnectorStatusRequest{ConnectorId: nas.ID}))
	if err != nil {
		t.Fatal(err)
	}
	s := st.Msg.GetStatus()
	ds := s.GetDataSessions()
	// By gateway, then transport name: h2 before quic.
	if len(ds) != 3 || ds[0].GetGatewayId() != "gw_a" || ds[0].GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_H2 ||
		ds[0].GetRtt() != nil || ds[1].GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC ||
		ds[1].GetRtt().AsDuration() != 14*time.Millisecond || ds[2].GetGatewayId() != "gw_b" {
		t.Fatalf("data sessions: %v", ds)
	}
	if nr := s.GetNotReady(); len(nr) != 1 || nr[0].GetReason() != "BLOCKED_BY_LOCAL_POLICY" || nr[0].GetDetail() != "10.0.0.5:5432" ||
		nr[0].GetResourceId() != "rt_1" {
		t.Fatalf("not ready: %v", nr)
	}
	if !s.GetSession().GetConnected() {
		t.Fatal("the status has no session")
	}
	quiet, err := vwr.con.GetConnectorStatus(ctx, connect.NewRequest(&rpmgrv1.GetConnectorStatusRequest{ConnectorId: pi.ID}))
	if err != nil || quiet.Msg.GetStatus().GetSession().GetConnected() || len(quiet.Msg.GetStatus().GetDataSessions()) != 0 ||
		quiet.Msg.GetStatus().GetSession().GetLastSeenTime() == nil {
		t.Fatalf("a connector without sessions: %v %v", quiet, err)
	}
	if g, err := vwr.con.GetConnector(ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: old.ID})); err != nil ||
		g.Msg.GetConnector().GetName() != "old" {
		t.Fatalf("a decommissioned connector: %v %v", g, err)
	}
	for _, id := range []string{"con_missing"} {
		if _, err := ada.con.GetConnector(ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: id})); code(err) != connect.CodeNotFound {
			t.Fatalf("a missing connector: %v", err)
		}
		if _, err := ada.con.GetConnectorStatus(ctx, connect.NewRequest(&rpmgrv1.GetConnectorStatusRequest{ConnectorId: id})); code(err) != connect.CodeNotFound {
			t.Fatalf("a missing connector's status: %v", err)
		}
	}
}

func datasessionTransport(s string) datasession.Transport { return datasession.Transport(s) }

// TestConnectors_Write: an update changes only the masked fields and checks the etag; an unset
// transport is the instance default again; decommissioning revokes the identity in the same
// transaction, records it and applies the deny-list once; the tombstone cannot be changed; a
// Viewer changes nothing.
func TestConnectors_Write(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	nas := e.addConnector(t, org, "nas", nil)
	e.addConnector(t, org, "pi", nil)
	update := func(b *browser, mask []string, in *rpmgrv1.Connector, etag string) (*rpmgrv1.Connector, error) {
		in.Id = nas.ID
		r, err := b.con.UpdateConnector(ctx, connect.NewRequest(&rpmgrv1.UpdateConnectorRequest{Connector: in,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: mask}, Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetConnector(), nil
	}
	up, err := update(ada, []string{"name", "transport"}, &rpmgrv1.Connector{Name: "nas-2", Transport: rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC,
		Labels: map[string]string{"ignored": "x"}}, "1")
	if err != nil || up.GetName() != "nas-2" || up.GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC || up.GetLabels()["site"] != "office" ||
		up.GetLabels()["ignored"] != "" || up.GetEtag() != "2" {
		t.Fatalf("an update: %v %v", up, err)
	}
	if up, err = update(ada, []string{"labels", "enabled", "transport"}, &rpmgrv1.Connector{Labels: map[string]string{"site": "lab", "tier": "db"}}, "2"); err != nil ||
		len(up.GetLabels()) != 2 || up.GetEnabled() || up.GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_UNSPECIFIED {
		t.Fatalf("new labels, disabled, the default transport: %v %v", up, err)
	}
	if e.db.Client().Connector.GetX(e.sys, nas.ID).Transport != nil {
		t.Fatal("the transport policy was not cleared")
	}
	if _, err := update(ada, []string{"name"}, &rpmgrv1.Connector{Name: "late"}, "1"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	for name, c := range map[string]struct {
		mask []string
		in   *rpmgrv1.Connector
		want connect.Code
	}{
		"a taken name":       {[]string{"name"}, &rpmgrv1.Connector{Name: "pi"}, connect.CodeAlreadyExists},
		"a malformed name":   {[]string{"name"}, &rpmgrv1.Connector{Name: "Not A Slug"}, connect.CodeInvalidArgument},
		"no name":            {[]string{"name"}, &rpmgrv1.Connector{}, connect.CodeInvalidArgument},
		"a bad label":        {[]string{"labels"}, &rpmgrv1.Connector{Labels: map[string]string{"Bad Key": "x"}}, connect.CodeInvalidArgument},
		"an unknown policy":  {[]string{"transport"}, &rpmgrv1.Connector{Transport: rpmgrv1.DataTransport(9)}, connect.CodeInvalidArgument},
		"the ephemeral flag": {[]string{"ephemeral"}, &rpmgrv1.Connector{Ephemeral: true}, connect.CodeInvalidArgument},
		"the session":        {[]string{"session"}, &rpmgrv1.Connector{}, connect.CodeInvalidArgument},
		"an empty mask":      {nil, &rpmgrv1.Connector{}, connect.CodeInvalidArgument},
	} {
		if _, err := update(ada, c.mask, c.in, ""); code(err) != c.want {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}

	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := update(vwr, []string{"enabled"}, &rpmgrv1.Connector{Enabled: true}, ""); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer updates: %v", err)
	}
	decommission := func(b *browser, etag string) (*rpmgrv1.Connector, error) {
		r, err := b.con.DecommissionConnector(ctx, connect.NewRequest(&rpmgrv1.DecommissionConnectorRequest{ConnectorId: nas.ID, Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetConnector(), nil
	}
	if _, err := decommission(vwr, ""); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer decommissions: %v", err)
	}
	if _, err := decommission(ada, "1"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	gone, err := decommission(ada, "")
	if err != nil || gone.GetDecommissionTime() == nil || gone.GetEnabled() {
		t.Fatalf("a decommission: %v %v", gone, err)
	}
	spiffe := "spiffe://rpmgr-teststor/org/" + org + "/connector/" + nas.ID
	if _, err := e.db.Client().RevokedIdentity.Get(e.sys, spiffe); err != nil {
		t.Fatalf("the identity is not revoked: %v", err)
	}
	if entries, err := revlog.Read(e.log); err != nil || len(entries) != 1 || entries[0].Subject != spiffe {
		t.Fatalf("the revocation log: %v %v", entries, err)
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("identity.revoke"), auditentry.TargetID(nas.ID)).CountX(e.sys); n != 1 ||
		e.denied.Load() != 1 {
		t.Fatalf("%d audit entries, the deny-list applied %d times", n, e.denied.Load())
	}
	if again, err := decommission(ada, ""); err != nil || !again.GetDecommissionTime().AsTime().Equal(gone.GetDecommissionTime().AsTime()) ||
		e.denied.Load() != 1 {
		t.Fatalf("a second decommission: %v %v", again, err)
	}
	if _, err := update(ada, []string{"enabled"}, &rpmgrv1.Connector{Enabled: true}, ""); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("an update of a tombstone: %v", err)
	}
}

// TestConnectors_DecommissionDeletesRoutes (D78): a decommission deletes the connector's targets and
// each route it leaves with no target, whose ports and hostnames are free again; a route with a
// target on another connector keeps that one, also a disabled target or one on a disabled
// connector, and a route that had no target stays; the decommission and each deleted route are
// audited, also when the identity was revoked already, the response names the routes, and a
// second decommission deletes nothing.
func TestConnectors_DecommissionDeletesRoutes(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	for _, p := range []*rpmgrv1.PortPool{{GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009},
		{GatewayGroupId: group, Protocol: udp, PortFrom: 30000, PortTo: 30009}} {
		if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org, PortPool: p})); err != nil {
			t.Fatal(err)
		}
	}
	nas := e.addConnector(t, org, "nas", nil)
	pi := e.addConnector(t, org, "pi", nil)
	off := e.addConnector(t, org, "off", func(c *ent.ConnectorCreate) { c.SetEnabled(false) })
	ids := map[string]string{}
	for _, rt := range []*rpmgrv1.Route{tcpRoute("pg", group, 20005), udpRoute("dns", group, 30000), httpRoute("web", group, "web.example.com"),
		tcpRoute("shared", group, 20006), tcpRoute("idle", group, 20007), tcpRoute("standby", group, 20008), tcpRoute("paused", group, 20009)} {
		got, err := createRoute(ada, org, rt, "")
		if err != nil {
			t.Fatal(err)
		}
		ids[rt.GetName()] = got.GetId()
	}
	for _, tg := range []struct{ route, connector string }{{"pg", nas.ID}, {"dns", nas.ID}, {"web", nas.ID}, {"shared", nas.ID}, {"shared", pi.ID},
		{"standby", nas.ID}, {"standby", pi.ID}, {"paused", nas.ID}, {"paused", off.ID}} {
		if _, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: ids[tg.route],
			Target: addressTarget(tg.connector, "10.0.0.5", 5432)})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := createRoute(ada, org, tcpRoute("pg-2", group, 20005), ""); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("the port of a served route: %v", err)
	}
	e.db.Client().RouteTarget.Update().Where(routetarget.RouteID(ids["standby"]), routetarget.ConnectorID(pi.ID)).SetEnabled(false).ExecX(e.sys)

	r, err := ada.con.DecommissionConnector(ctx, connect.NewRequest(&rpmgrv1.DecommissionConnectorRequest{ConnectorId: nas.ID}))
	if err != nil {
		t.Fatal(err)
	}
	var deleted []string
	for _, d := range r.Msg.GetDeletedRoutes() {
		if d.GetId() != ids[d.GetName()] {
			t.Errorf("deleted route %v", d)
		}
		deleted = append(deleted, d.GetName())
	}
	if slices.Sort(deleted); !slices.Equal(deleted, []string{"dns", "pg", "web"}) {
		t.Fatalf("deleted routes %v", deleted)
	}
	for _, name := range []string{"pg", "dns", "web"} {
		if _, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: ids[name]})); code(err) != connect.CodeNotFound {
			t.Errorf("route %s after the decommission: %v", name, err)
		}
	}
	for name, other := range map[string]string{"shared": pi.ID, "standby": pi.ID, "paused": off.ID} {
		kept, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: ids[name]}))
		if err != nil || len(kept.Msg.GetRoute().GetTargets()) != 1 || kept.Msg.GetRoute().GetTargets()[0].GetConnectorId() != other {
			t.Errorf("the %s route: %v %v", name, kept, err)
		}
	}
	if _, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: ids["idle"]})); err != nil {
		t.Fatalf("the route without targets: %v", err)
	}
	pools, err := ada.gw.ListPortPools(ctx, connect.NewRequest(&rpmgrv1.ListPortPoolsRequest{OrgId: org, GatewayGroupId: group}))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pools.Msg.GetPortPools() {
		if want := map[rpmgrv1.PortProtocol]int32{tcp: 4, udp: 0}[p.GetProtocol()]; p.GetAllocatedPorts() != want {
			t.Errorf("%v pool: %d ports allocated, want %d", p.GetProtocol(), p.GetAllocatedPorts(), want)
		}
	}
	for _, rt := range []*rpmgrv1.Route{tcpRoute("pg-2", group, 20005), udpRoute("dns-2", group, 30000), httpRoute("web-2", group, "web.example.com")} {
		if _, err := createRoute(ada, org, rt, ""); err != nil {
			t.Errorf("%s on what a deleted route held: %v", rt.GetName(), err)
		}
	}
	s, _ := ada.session()
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("route.delete"), auditentry.TargetIDIn(ids["pg"], ids["dns"], ids["web"]),
		auditentry.ActorID(s.GetUserId())).CountX(e.sys); n != 3 {
		t.Fatalf("%d audit entries for the deleted routes", n)
	}
	again, err := ada.con.DecommissionConnector(ctx, connect.NewRequest(&rpmgrv1.DecommissionConnectorRequest{ConnectorId: nas.ID}))
	if err != nil || len(again.Msg.GetDeletedRoutes()) != 0 {
		t.Fatalf("a second decommission: %v %v", again, err)
	}

	// After a restore an identity can be revoked already, which records nothing; the decommission
	// is audited all the same.
	restored := e.addConnector(t, org, "restored", nil)
	tx, err := e.db.Client().Tx(e.sys)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := castore.RevokeIdentity(e.sys, tx, pki.Identity{TrustDomain: "rpmgr-teststor", Org: org, Kind: pki.KindConnector, ID: restored.ID},
		"restored", time.Now()); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.con.DecommissionConnector(ctx, connect.NewRequest(&rpmgrv1.DecommissionConnectorRequest{ConnectorId: restored.ID})); err != nil {
		t.Fatal(err)
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("identity.revoke"), auditentry.TargetID(restored.ID)).CountX(e.sys); n != 0 {
		t.Fatalf("the restored identity was revoked again: %d entries", n)
	}
	for _, id := range []string{nas.ID, restored.ID} {
		if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("connector.decommission"), auditentry.TargetID(id),
			auditentry.ActorID(s.GetUserId())).CountX(e.sys); n != 1 {
			t.Errorf("%d decommission audit entries for %s", n, id)
		}
	}
}

// TestConnectors_DecommissionRollsBack: a route the decommission cannot delete fails it as a whole,
// so the connector, its identity, its targets and its routes stay as they were.
func TestConnectors_DecommissionRollsBack(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	if _, err := ada.gw.CreatePortPool(ctx, connect.NewRequest(&rpmgrv1.CreatePortPoolRequest{OrgId: org, PortPool: &rpmgrv1.PortPool{
		GatewayGroupId: group, Protocol: tcp, PortFrom: 20000, PortTo: 20009}})); err != nil {
		t.Fatal(err)
	}
	nas := e.addConnector(t, org, "nas", nil)
	pg, err := createRoute(ada, org, tcpRoute("pg", group, 20005), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.rt.CreateRouteTarget(ctx, connect.NewRequest(&rpmgrv1.CreateRouteTargetRequest{RouteId: pg.GetId(),
		Target: addressTarget(nas.ID, "10.0.0.5", 5432)})); err != nil {
		t.Fatal(err)
	}
	e.db.Client().Route.Use(func(next ent.Mutator) ent.Mutator {
		return hook.RouteFunc(func(ctx context.Context, m *ent.RouteMutation) (ent.Value, error) {
			if m.Op().Is(ent.OpDeleteOne) {
				return nil, errors.New("the store failed")
			}
			return next.Mutate(ctx, m)
		})
	})
	if _, err := ada.con.DecommissionConnector(ctx, connect.NewRequest(&rpmgrv1.DecommissionConnectorRequest{ConnectorId: nas.ID})); err == nil {
		t.Fatal("a decommission whose route could not go succeeded")
	}
	c := e.db.Client()
	if row := c.Connector.GetX(e.sys, nas.ID); row.DecommissionedAt != nil || !row.Enabled || c.RevokedIdentity.Query().CountX(e.sys) != 0 ||
		e.denied.Load() != 0 {
		t.Fatalf("the connector after a failed decommission: %+v, %d revoked", row, c.RevokedIdentity.Query().CountX(e.sys))
	}
	if !c.Route.Query().Where(route.ID(pg.GetId())).ExistX(e.sys) || c.RouteTarget.Query().Where(routetarget.ConnectorID(nas.ID)).CountX(e.sys) != 1 ||
		c.PortAllocation.Query().CountX(e.sys) != 1 {
		t.Fatal("the route, its target or its port changed with a failed decommission")
	}
}
