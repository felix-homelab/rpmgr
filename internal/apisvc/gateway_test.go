// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
)

// TestGatewayGroups: an Owner creates, reads, lists, changes and deletes gateway groups: a name is
// unique in the org and slug-shaped; a create is idempotent by request_id; an update changes only
// the masked fields and checks the etag; a delete is refused while the group has a gateway, and a
// Viewer changes nothing.
func TestGatewayGroups(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	s, _ := ada.session()
	org := s.GetMemberships()[0].GetOrgId()
	create := func(b *browser, name, requestID string) (*rpmgrv1.CreateGatewayGroupResponse, error) {
		r, err := b.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org, RequestId: requestID,
			GatewayGroup: &rpmgrv1.GatewayGroup{Name: name, Region: "Frankfurt", TrustedProxyCidrs: []string{"10.0.0.0/8"}}}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	eu, err := create(ada, "eu", "req-1")
	if err != nil || eu.GetGatewayGroup().GetEtag() != "1" || eu.GetRevision().GetSeq() == 0 {
		t.Fatalf("create: %v %v", eu, err)
	}
	if again, err := create(ada, "eu", "req-1"); err != nil || again.GetGatewayGroup().GetId() != eu.GetGatewayGroup().GetId() {
		t.Fatalf("a retry: %v %v", again, err)
	}
	if _, err := create(ada, "eu", ""); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("a taken name: %v", err)
	}
	for _, bad := range []string{"Not A Slug", ""} {
		if _, err := create(ada, bad, ""); code(err) != connect.CodeInvalidArgument {
			t.Fatalf("the name %q: %v", bad, err)
		}
	}
	for _, n := range []string{"us", "ap"} {
		if _, err := create(ada, n, ""); err != nil {
			t.Fatal(err)
		}
	}
	first, err := ada.gw.ListGatewayGroups(ctx, connect.NewRequest(&rpmgrv1.ListGatewayGroupsRequest{OrgId: org, PageSize: 2}))
	if err != nil || len(first.Msg.GetGatewayGroups()) != 2 || first.Msg.GetNextPageToken() == "" {
		t.Fatalf("the first page: %v %v", first, err)
	}
	rest, err := ada.gw.ListGatewayGroups(ctx, connect.NewRequest(&rpmgrv1.ListGatewayGroupsRequest{OrgId: org, PageSize: 2,
		PageToken: first.Msg.GetNextPageToken()}))
	if err != nil || len(rest.Msg.GetGatewayGroups()) != 1 {
		t.Fatalf("the last page: %v %v", rest, err)
	}

	id := eu.GetGatewayGroup().GetId()
	update := func(mask []string, in *rpmgrv1.GatewayGroup, etag string) (*rpmgrv1.UpdateGatewayGroupResponse, error) {
		in.Id = id
		r, err := ada.gw.UpdateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayGroupRequest{GatewayGroup: in,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: mask}, Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	up, err := update([]string{"region"}, &rpmgrv1.GatewayGroup{Region: "Paris", Name: "ignored"}, "1")
	if err != nil || up.GetGatewayGroup().GetRegion() != "Paris" || up.GetGatewayGroup().GetName() != "eu" ||
		up.GetGatewayGroup().GetEtag() != "2" || len(up.GetGatewayGroup().GetTrustedProxyCidrs()) != 1 {
		t.Fatalf("an update: %v %v", up, err)
	}
	if _, err := update([]string{"region"}, &rpmgrv1.GatewayGroup{Region: "Rome"}, "1"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	for name, mask := range map[string][]string{"empty": nil, "the ID": {"id"}, "the etag": {"etag"}} {
		if _, err := update(mask, &rpmgrv1.GatewayGroup{}, ""); code(err) != connect.CodeInvalidArgument {
			t.Errorf("a mask of %s: %v", name, err)
		}
	}
	if _, err := update([]string{"trusted_proxy_cidrs"}, &rpmgrv1.GatewayGroup{TrustedProxyCidrs: []string{"not a cidr"}}, ""); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a bad CIDR: %v", err)
	}

	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := create(vwr, "viewer-made", ""); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer creates: %v", err)
	}
	if r, err := vwr.gw.GetGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.GetGatewayGroupRequest{GatewayGroupId: id})); err != nil ||
		r.Msg.GetGatewayGroup().GetName() != "eu" {
		t.Fatalf("a Viewer reads: %v %v", r, err)
	}

	gw := e.db.Client().Gateway.Create().SetOrgID(org).SetGatewayGroupID(id).SetName("gw1").SetTunnelEndpoints([]string{"gw1.example.com:443"}).
		SaveX(e.sys)
	del := func() error {
		_, err := ada.gw.DeleteGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.DeleteGatewayGroupRequest{GatewayGroupId: id}))
		return err
	}
	if err := del(); reason(err) != apisvc.ReasonDependantsExist {
		t.Fatalf("a group with a gateway: %v", err)
	}
	e.db.Client().Gateway.UpdateOneID(gw.ID).SetDecommissionedAt(e.clock).ExecX(e.sys)
	if err := del(); err != nil {
		t.Fatalf("a group with a decommissioned gateway: %v", err)
	}
	if _, err := ada.gw.GetGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.GetGatewayGroupRequest{GatewayGroupId: id})); code(err) != connect.CodeNotFound {
		t.Fatalf("a deleted group: %v", err)
	}
}

// gatewayEnv is an Owner's browser with a gateway group in its org.
func gatewayEnv(t *testing.T) (*env, *browser, string, string) {
	t.Helper()
	e := newEnv(t)
	ada := e.browser()
	if err := ada.login("ada@example.com", pw); err != nil {
		t.Fatal(err)
	}
	s, _ := ada.session()
	org := s.GetMemberships()[0].GetOrgId()
	g, err := ada.gw.CreateGatewayGroup(context.Background(), connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org,
		GatewayGroup: &rpmgrv1.GatewayGroup{Name: "eu"}}))
	if err != nil {
		t.Fatal(err)
	}
	return e, ada, org, g.Msg.GetGatewayGroup().GetId()
}

func createGateway(b *browser, org, group, name string, endpoints ...string) (*rpmgrv1.Gateway, error) {
	r, err := b.gw.CreateGateway(context.Background(), connect.NewRequest(&rpmgrv1.CreateGatewayRequest{OrgId: org,
		Gateway: &rpmgrv1.Gateway{GatewayGroupId: group, Name: name, TunnelEndpoints: endpoints}}))
	if err != nil {
		return nil, err
	}
	return r.Msg.GetGateway(), nil
}

// TestGateways: an Owner creates gateways in a group, each in the lowest free slot, and a fifth is
// refused; tunnel endpoints must be one to eight distinct host:port addresses; the status shows a
// control session; an update changes only the masked fields, and enabled false drains; a Viewer
// reads but changes nothing.
func TestGateways(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	var gws []*rpmgrv1.Gateway
	for i, n := range []string{"gw1", "gw2", "gw3", "gw4"} {
		g, err := createGateway(ada, org, group, n, n+".example.com:443")
		if err != nil || g.GetSlot() != int32(i+1) || !g.GetEnabled() || g.GetStatus().GetEnrolled() || g.GetEtag() != "1" { //nolint:gosec // G115: i < 4
			t.Fatalf("%s: %v %v", n, g, err)
		}
		gws = append(gws, g)
	}
	if _, err := createGateway(ada, org, group, "gw5", "gw5.example.com:443"); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a fifth gateway: %v", err)
	}
	if _, err := createGateway(ada, org, "gwg_missing", "gw6", "gw6.example.com:443"); code(err) != connect.CodeNotFound {
		t.Fatalf("a group that does not exist: %v", err)
	}
	many := make([]string, 9)
	for i := range many {
		many[i] = "gw.example.com:" + string(rune('1'+i))
	}
	for name, eps := range map[string][]string{
		"none": nil, "no port": {"gw.example.com"}, "a URL": {"https://gw.example.com:443"}, "port 0": {"gw.example.com:0"},
		"twice": {"gw.example.com:443", "gw.example.com:443"}, "nine": many,
	} {
		if _, err := createGateway(ada, org, group, "bad", eps...); code(err) != connect.CodeInvalidArgument {
			t.Errorf("endpoints %s: %v", name, err)
		}
	}

	e.db.Client().AgentSession.Create().SetID(gws[0].GetId()).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctl_1").
		SetRemoteAddr("192.0.2.7:51000").SetAgentVersion("v0.1.0").SetCapabilities([]string{}).SetConnectedAt(e.clock).
		SetLastSeenAt(e.clock).ExecX(e.sys)
	got, err := ada.gw.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: gws[0].GetId()}))
	if st := got.Msg.GetGateway().GetStatus(); err != nil || !st.GetConnected() || st.GetVersion() != "v0.1.0" ||
		st.GetRemoteAddr() != "192.0.2.7:51000" || !st.GetLastSeenTime().AsTime().Equal(e.clock.Truncate(0)) {
		t.Fatalf("a connected gateway: %v %v", got, err)
	}
	first, err := ada.gw.ListGateways(ctx, connect.NewRequest(&rpmgrv1.ListGatewaysRequest{OrgId: org, GatewayGroupId: group, PageSize: 3}))
	if err != nil || len(first.Msg.GetGateways()) != 3 || first.Msg.GetNextPageToken() == "" {
		t.Fatalf("the first page: %v %v", first, err)
	}
	rest, err := ada.gw.ListGateways(ctx, connect.NewRequest(&rpmgrv1.ListGatewaysRequest{OrgId: org, GatewayGroupId: group, PageSize: 3,
		PageToken: first.Msg.GetNextPageToken()}))
	if err != nil || len(rest.Msg.GetGateways()) != 1 {
		t.Fatalf("the last page: %v %v", rest, err)
	}
	if r, err := ada.gw.ListGateways(ctx, connect.NewRequest(&rpmgrv1.ListGatewaysRequest{OrgId: org, GatewayGroupId: "gwg_other"})); err != nil ||
		len(r.Msg.GetGateways()) != 0 {
		t.Fatalf("another group's: %v %v", r, err)
	}

	id := gws[1].GetId()
	update := func(mask []string, in *rpmgrv1.Gateway, etag string) (*rpmgrv1.Gateway, error) {
		in.Id = id
		r, err := ada.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: in,
			UpdateMask: &fieldmaskpb.FieldMask{Paths: mask}, Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetGateway(), nil
	}
	up, err := update([]string{"tunnel_endpoints"}, &rpmgrv1.Gateway{TunnelEndpoints: []string{"203.0.113.9:443", "[2001:db8::9]:443"},
		Name: "ignored"}, "1")
	if err != nil || len(up.GetTunnelEndpoints()) != 2 || up.GetName() != "gw2" || up.GetEtag() != "2" || !up.GetEnabled() {
		t.Fatalf("new endpoints: %v %v", up, err)
	}
	if _, err := update([]string{"name"}, &rpmgrv1.Gateway{Name: "late"}, "1"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	if _, err := update([]string{"tunnel_endpoints"}, &rpmgrv1.Gateway{}, ""); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("no endpoints left: %v", err)
	}
	for _, path := range []string{"slot", "gateway_group_id", "status", "decommission_time"} {
		if _, err := update([]string{path}, &rpmgrv1.Gateway{}, ""); code(err) != connect.CodeInvalidArgument {
			t.Errorf("a mask of %s: %v", path, err)
		}
	}
	if _, err := update([]string{"name"}, &rpmgrv1.Gateway{Name: "gw1"}, ""); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("a taken name: %v", err)
	}
	drain, err := ada.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: &rpmgrv1.Gateway{Id: id},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"enabled"}}}))
	if err != nil || drain.Msg.GetGateway().GetEnabled() || drain.Msg.GetRevision().GetSeq() == 0 {
		t.Fatalf("a drain: %v %v", drain, err)
	}

	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := createGateway(vwr, org, group, "vgw", "vgw.example.com:443"); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer creates: %v", err)
	}
	if _, err := vwr.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: &rpmgrv1.Gateway{Id: id, Enabled: true},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"enabled"}}})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a Viewer updates: %v", err)
	}
	if _, err := vwr.gw.DecommissionGateway(ctx, connect.NewRequest(&rpmgrv1.DecommissionGatewayRequest{GatewayId: id})); code(err) !=
		connect.CodePermissionDenied {
		t.Fatalf("a Viewer decommissions: %v", err)
	}
	if r, err := vwr.gw.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: id})); err != nil || r.Msg.GetGateway().GetEnabled() {
		t.Fatalf("a Viewer reads: %v %v", r, err)
	}
}

// TestDecommissionGateway: decommissioning revokes the gateway's identity in the same
// transaction, records it in the revocation log and the audit log, applies the deny-list at once
// and frees the slot; the tombstone is listed only on request, cannot be changed, and a second
// decommission changes nothing.
func TestDecommissionGateway(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	var gws []*rpmgrv1.Gateway
	for _, n := range []string{"gw1", "gw2", "gw3", "gw4"} {
		g, err := createGateway(ada, org, group, n, n+".example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		gws = append(gws, g)
	}
	id := gws[1].GetId()
	decommission := func(etag string) (*rpmgrv1.Gateway, error) {
		r, err := ada.gw.DecommissionGateway(ctx, connect.NewRequest(&rpmgrv1.DecommissionGatewayRequest{GatewayId: id, Etag: etag}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetGateway(), nil
	}
	if _, err := decommission("7"); reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	if e.denied.Load() != 0 {
		t.Fatal("a refused decommission applied the deny-list")
	}
	gone, err := decommission("1")
	if err != nil || gone.GetDecommissionTime() == nil || gone.GetEnabled() {
		t.Fatalf("a decommission: %v %v", gone, err)
	}
	spiffe := "spiffe://rpmgr-teststor/org/" + org + "/gateway/" + id
	if _, err := e.db.Client().RevokedIdentity.Get(e.sys, spiffe); err != nil {
		t.Fatalf("the identity is not revoked: %v", err)
	}
	entries, err := revlog.Read(e.log)
	if err != nil || len(entries) != 1 || entries[0].Kind != revlog.IdentityRevoked || entries[0].Subject != spiffe || entries[0].Actor != e.ada {
		t.Fatalf("the revocation log: %v %v", entries, err)
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.Action("identity.revoke"), auditentry.TargetID(id)).CountX(e.sys); n != 1 {
		t.Fatalf("%d audit entries of the revocation", n)
	}
	if e.denied.Load() != 1 {
		t.Fatalf("the deny-list was applied %d times", e.denied.Load())
	}

	again, err := decommission("")
	if err != nil || !again.GetDecommissionTime().AsTime().Equal(gone.GetDecommissionTime().AsTime()) || e.denied.Load() != 1 {
		t.Fatalf("a second decommission: %v %v", again, err)
	}
	if entries, _ := revlog.Read(e.log); len(entries) != 1 {
		t.Fatalf("a second decommission logged again: %d entries", len(entries))
	}
	if _, err := ada.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: &rpmgrv1.Gateway{Id: id, Enabled: true},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"enabled"}}})); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("an update of a tombstone: %v", err)
	}
	list := func(all bool) int {
		r, err := ada.gw.ListGateways(ctx, connect.NewRequest(&rpmgrv1.ListGatewaysRequest{OrgId: org, ShowDecommissioned: all}))
		if err != nil {
			t.Fatal(err)
		}
		return len(r.Msg.GetGateways())
	}
	if list(false) != 3 || list(true) != 4 {
		t.Fatalf("listed %d, with tombstones %d", list(false), list(true))
	}
	next, err := createGateway(ada, org, group, "gw5", "gw5.example.com:443")
	if err != nil || next.GetSlot() != gws[1].GetSlot() {
		t.Fatalf("the freed slot: %v %v", next, err)
	}
	if _, err := createGateway(ada, org, group, "gw2", "gw2.example.com:443"); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a sixth gateway: %v", err)
	}
	if _, err := ada.gw.DecommissionGateway(ctx, connect.NewRequest(&rpmgrv1.DecommissionGatewayRequest{GatewayId: "gw_missing"})); code(err) !=
		connect.CodeNotFound {
		t.Fatalf("a gateway that does not exist: %v", err)
	}
}
