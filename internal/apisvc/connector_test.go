// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/datasession"
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
// each carries its control session; the status adds its data sessions as its gateways report them
// and the routes it reports not ready; a Viewer reads all of it.
func TestConnectors_Read(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	nas := e.addConnector(t, org, "nas", func(c *ent.ConnectorCreate) { c.SetTransport(connector.TransportH2) })
	pi := e.addConnector(t, org, "pi", nil)
	old := e.addConnector(t, org, "old", func(c *ent.ConnectorCreate) { c.SetDecommissionedAt(e.clock).SetEnabled(false) })
	seen := e.clock.Add(-time.Minute).UTC().Truncate(time.Second)
	e.db.Client().AgentSession.Create().SetID(nas.ID).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").
		SetRemoteAddr("192.0.2.9:40000").SetAgentVersion("v0.1.0").SetConnectedAt(seen).SetLastSeenAt(seen).ExecX(e.sys)
	for _, d := range []struct {
		gw, tr string
		rtt    int64
	}{{"gw_b", "h2", 0}, {"gw_a", "quic", 14}, {"gw_a", "h2", 0}} {
		e.db.Client().DataSession.Create().SetOrgID(org).SetGatewayID(d.gw).SetConnectorID(nas.ID).SetTransport(datasessionTransport(d.tr)).
			SetRttMs(d.rtt).SetEstablishedAt(seen).SetReportedAt(seen).ExecX(e.sys)
	}
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
		n.GetLabels()["site"] != "office" || n.GetEtag() != "1" {
		t.Fatalf("nas: %v", n)
	}
	if p := byName["pi"]; p.GetSession().GetConnected() || p.GetTransport() != rpmgrv1.DataTransport_DATA_TRANSPORT_UNSPECIFIED {
		t.Fatalf("pi: %v", p)
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
	if err != nil || quiet.Msg.GetStatus().GetSession().GetConnected() || len(quiet.Msg.GetStatus().GetDataSessions()) != 0 {
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
