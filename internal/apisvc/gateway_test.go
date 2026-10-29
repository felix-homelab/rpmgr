// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaypage"
	"github.com/felix-homelab/rpmgr/internal/store/ent/schema"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
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
		st.GetRemoteAddr() != "192.0.2.7:51000" || !st.GetLastSeenTime().AsTime().Equal(e.clock.Truncate(0)) || st.GetOverTheAir() {
		t.Fatalf("a connected gateway: %v %v", got, err)
	}
	// Disconnected, and connected but not seen for longer than a session lives: neither is connected.
	for name, edit := range map[string]func(*ent.AgentSessionUpdateOne){
		"disconnected": func(u *ent.AgentSessionUpdateOne) { u.SetDisconnectedAt(e.clock) },
		"not seen": func(u *ent.AgentSessionUpdateOne) {
			u.ClearDisconnectedAt().SetLastSeenAt(e.clock.Add(-schema.AgentSessionSeenFor))
		},
	} {
		u := e.db.Client().AgentSession.UpdateOneID(gws[0].GetId())
		edit(u)
		u.ExecX(e.sys)
		got, err := ada.gw.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: gws[0].GetId()}))
		if err != nil || got.Msg.GetGateway().GetStatus().GetConnected() || got.Msg.GetGateway().GetStatus().GetVersion() != "v0.1.0" {
			t.Fatalf("a %s gateway: %v %v", name, got, err)
		}
	}
	// A gateway whose session announced over-the-air updates can be updated by a rollout (D129).
	e.db.Client().AgentSession.UpdateOneID(gws[0].GetId()).SetCapabilities([]string{"ota", "relay.v1"}).ExecX(e.sys)
	if got, err := ada.gw.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: gws[0].GetId()})); err != nil ||
		!got.Msg.GetGateway().GetStatus().GetOverTheAir() {
		t.Fatalf("a gateway that announced ota: %v %v", got, err)
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
// and frees the slot and the name; the tombstone is listed only on request, cannot be changed, and a
// second decommission changes nothing. A new or renamed gateway takes a tombstone's name, never an
// active gateway's.
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

	us, err := ada.gw.CreateGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.CreateGatewayGroupRequest{OrgId: org,
		GatewayGroup: &rpmgrv1.GatewayGroup{Name: "us"}}))
	if err != nil {
		t.Fatal(err)
	}
	reused, err := createGateway(ada, org, us.Msg.GetGatewayGroup().GetId(), "gw2", "gw2.us.example.com:443")
	if err != nil || reused.GetId() == id {
		t.Fatalf("the name of a decommissioned gateway: %v %v", reused, err)
	}
	if _, err := createGateway(ada, org, us.Msg.GetGatewayGroup().GetId(), "gw1", "gw1.us.example.com:443"); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("the name of an active gateway: %v", err)
	}
	rename := func(gw *rpmgrv1.Gateway, name string) error {
		_, err := ada.gw.UpdateGateway(ctx, connect.NewRequest(&rpmgrv1.UpdateGatewayRequest{Gateway: &rpmgrv1.Gateway{Id: gw.GetId(), Name: name},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"name"}}}))
		return err
	}
	if err := rename(next, "gw2"); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("a rename to an active gateway's name: %v", err)
	}
	if _, err := ada.gw.DecommissionGateway(ctx, connect.NewRequest(&rpmgrv1.DecommissionGatewayRequest{GatewayId: reused.GetId()})); err != nil {
		t.Fatal(err)
	}
	if err := rename(next, "gw2"); err != nil {
		t.Fatalf("a rename to the name two tombstones hold: %v", err)
	}
	if _, err := ada.gw.DecommissionGateway(ctx, connect.NewRequest(&rpmgrv1.DecommissionGatewayRequest{GatewayId: "gw_missing"})); code(err) !=
		connect.CodeNotFound {
		t.Fatalf("a gateway that does not exist: %v", err)
	}
}

// TestGatewayPages (D132): the group's owner org sets, lists, replaces and deletes the group's own
// pages, each audited by the page's hash and size rather than its HTML; a page that is too large,
// empty or of no kind is refused (a string that is not UTF-8 never reaches the service: protobuf
// refuses it on the wire); another org and a Viewer change nothing; deleting the group takes its
// pages along. Shared groups, whose pages are the Instance Admin's, come with P2-M11.
func TestGatewayPages(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	set := func(b *browser, group string, kind rpmgrv1.GatewayPageKind, html string) (*rpmgrv1.GatewayPage, error) {
		r, err := b.gw.SetGatewayPage(ctx, connect.NewRequest(&rpmgrv1.SetGatewayPageRequest{
			GatewayPage: &rpmgrv1.GatewayPage{GatewayGroupId: group, Kind: kind, Html: html}}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetGatewayPage(), nil
	}
	list := func(b *browser) ([]*rpmgrv1.GatewayPage, error) {
		r, err := b.gw.ListGatewayPages(ctx, connect.NewRequest(&rpmgrv1.ListGatewayPagesRequest{GatewayGroupId: group}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetGatewayPages(), nil
	}
	const notFound, maintenance = rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_NOT_FOUND, rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE
	p, err := set(ada, group, maintenance, "<p>Back soon: {{message}}</p>")
	if err != nil || p.GetKind() != maintenance || p.GetHtml() != "<p>Back soon: {{message}}</p>" || p.GetUpdateUserId() == "" || p.GetUpdateTime() == nil {
		t.Fatalf("set: %v %v", p, err)
	}
	if _, err := set(ada, group, notFound, "<p>first</p>"); err != nil {
		t.Fatal(err)
	}
	if _, err := set(ada, group, notFound, "<p>{{hostname}} is not here</p>"); err != nil {
		t.Fatalf("replace: %v", err)
	}
	got, err := list(ada)
	if err != nil || len(got) != 2 || got[0].GetKind() != maintenance && got[1].GetKind() != maintenance {
		t.Fatalf("list: %v %v", got, err)
	}
	stored := e.db.Client().GatewayPage.Query().Where(gatewaypage.KindEQ(gatewaypage.KindNotFound)).OnlyX(e.sys)
	if sum := sha256.Sum256([]byte("<p>{{hostname}} is not here</p>")); !bytes.Equal(stored.ContentSha256, sum[:]) || stored.OrgID != org {
		t.Fatalf("stored %v", stored)
	}

	for name, tc := range map[string]struct {
		kind rpmgrv1.GatewayPageKind
		html string
		code connect.Code
	}{
		"too large":       {notFound, strings.Repeat("a", 64<<10+1), connect.CodeInvalidArgument},
		"empty":           {notFound, "", connect.CodeInvalidArgument},
		"no kind":         {rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_UNSPECIFIED, "<p>x</p>", connect.CodeInvalidArgument},
		"an unknown kind": {rpmgrv1.GatewayPageKind(9), "<p>x</p>", connect.CodeInvalidArgument},
	} {
		if _, err := set(ada, group, tc.kind, tc.html); code(err) != tc.code {
			t.Errorf("%s: %v, want %v", name, err, tc.code)
		}
	}
	if _, err := set(ada, group, notFound, strings.Repeat("a", 64<<10)); err != nil {
		t.Errorf("a page of exactly 64 KiB: %v", err)
	}

	// Another org's owner neither sees nor changes the group's pages; a Viewer reads them only.
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if _, err := set(bob, group, notFound, "<p>mine</p>"); code(err) != connect.CodeNotFound && code(err) != connect.CodePermissionDenied {
		t.Errorf("another org sets: %v", err)
	}
	if _, err := list(bob); code(err) != connect.CodeNotFound && code(err) != connect.CodePermissionDenied {
		t.Errorf("another org lists: %v", err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if got, err := list(vwr); err != nil || len(got) != 2 {
		t.Errorf("a Viewer lists: %v %v", got, err)
	}
	if _, err := set(vwr, group, notFound, "<p>x</p>"); code(err) != connect.CodePermissionDenied {
		t.Errorf("a Viewer sets: %v", err)
	}

	del := func(kind rpmgrv1.GatewayPageKind) error {
		_, err := ada.gw.DeleteGatewayPage(ctx, connect.NewRequest(&rpmgrv1.DeleteGatewayPageRequest{GatewayGroupId: group, Kind: kind}))
		return err
	}
	if err := del(notFound); err != nil {
		t.Fatal(err)
	}
	if err := del(notFound); code(err) != connect.CodeNotFound {
		t.Errorf("a page deleted twice: %v", err)
	}
	if n := e.db.Client().AuditEntry.Query().Where(auditentry.ActionIn("rpmgr.v1.GatewayService.SetGatewayPage",
		"rpmgr.v1.GatewayService.DeleteGatewayPage")).CountX(e.sys); n < 5 {
		t.Errorf("%d audit entries of page changes", n)
	}
	const replaced = "<p>{{hostname}} is not here</p>"
	sum := sha256.Sum256([]byte(replaced))
	entries := e.db.Client().AuditEntry.Query().Where(auditentry.Action("rpmgr.v1.GatewayService.SetGatewayPage")).AllX(e.sys)
	if !slices.ContainsFunc(entries, func(a *ent.AuditEntry) bool {
		return strings.Contains(a.Diff, hex.EncodeToString(sum[:])) && strings.Contains(a.Diff, fmt.Sprintf(`"html_bytes":%d`, len(replaced))) && strings.Contains(a.Diff, group)
	}) {
		t.Errorf("no audit entry names the page by its hash and size")
	}
	for _, a := range entries {
		if strings.Contains(a.Diff, "is not here") || strings.Contains(a.Diff, "Back soon") {
			t.Errorf("an audit entry holds the HTML: %s", a.Diff)
		}
	}
	if _, err := ada.gw.DeleteGatewayGroup(ctx, connect.NewRequest(&rpmgrv1.DeleteGatewayGroupRequest{GatewayGroupId: group})); err != nil {
		t.Fatalf("a group with a page: %v", err)
	}
	if n := e.db.Client().GatewayPage.Query().CountX(e.sys); n != 0 {
		t.Errorf("%d pages left after their group", n)
	}
}

// TestGatewayPagePreview (D136): an Owner gets a link that shows the group's page exactly as its
// gateways render it, with sample values, under the custom-page CSP plus a sandbox, framed only by
// the web UI; a page with script, handlers and javascript: URLs cannot run them (the CSP allows no
// script at all); a kind without a page shows the built-in page; the link fails once expired,
// altered or once the page changed; another org and a Viewer get no link.
func TestGatewayPagePreview(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	const hostile = `<p onclick="alert(1)">{{status}} {{hostname}} {{message}} {{request_id}}</p><script>alert(2)</script>` +
		`<a href="javascript:alert(3)">x</a>`
	if _, err := ada.gw.SetGatewayPage(ctx, connect.NewRequest(&rpmgrv1.SetGatewayPageRequest{GatewayPage: &rpmgrv1.GatewayPage{
		GatewayGroupId: group, Kind: rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE, Html: hostile}})); err != nil {
		t.Fatal(err)
	}
	preview := func(b *browser, kind rpmgrv1.GatewayPageKind) (string, error) {
		r, err := b.gw.PreviewGatewayPage(ctx, connect.NewRequest(&rpmgrv1.PreviewGatewayPageRequest{GatewayGroupId: group, Kind: kind}))
		if err != nil {
			return "", err
		}
		if !r.Msg.GetExpireTime().AsTime().After(e.clock) {
			t.Errorf("a link that ends at %v", r.Msg.GetExpireTime().AsTime())
		}
		return r.Msg.GetUrl(), nil
	}
	// fetch requests a link with the Sec-Fetch headers a browser sends, none if dest is empty.
	fetch := func(method, url, dest, site string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, url, nil)
		if dest != "" {
			r.Header.Set("Sec-Fetch-Dest", dest)
			r.Header.Set("Sec-Fetch-Site", site)
		}
		w := httptest.NewRecorder()
		e.previews.ServeHTTP(w, r)
		return w
	}
	// open requests a link as the web UI's frame does.
	open := func(url string) *httptest.ResponseRecorder {
		return fetch(http.MethodGet, url, "iframe", "same-origin")
	}
	refused := func(name string, w *httptest.ResponseRecorder, code int) {
		t.Helper()
		if w.Code != code || w.Header().Get("Content-Security-Policy") != "default-src 'none'; sandbox" ||
			strings.Contains(w.Body.String(), "alert") || strings.Contains(w.Body.String(), "<p") {
			t.Errorf("%s: %d %v %q", name, w.Code, w.Header(), w.Body.String())
		}
	}
	url, err := preview(ada, rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE)
	if err != nil || !strings.HasPrefix(url, apisvc.PreviewPath) {
		t.Fatalf("a link: %q %v", url, err)
	}
	w := open(url)
	h := w.Header()
	if w.Code != http.StatusOK || h.Get("Content-Type") != "text/html; charset=utf-8" || h.Get("X-Content-Type-Options") != "nosniff" ||
		h.Get("Cache-Control") != "no-store" || h.Get("Cross-Origin-Resource-Policy") != "same-origin" {
		t.Fatalf("%d %v", w.Code, h)
	}
	csp := h.Get("Content-Security-Policy")
	if !strings.HasPrefix(csp, "default-src 'none'; style-src 'unsafe-inline'; img-src data:") || !strings.HasSuffix(csp, "; sandbox") ||
		!strings.Contains(csp, "frame-ancestors 'self'") || strings.Contains(csp, "script-src") {
		t.Fatalf("CSP %q", csp)
	}
	if want := `<p onclick="alert(1)">503 www.example.com Back soon: the service is being updated. 0123456789abcdef</p>`; !strings.HasPrefix(w.Body.String(), want) {
		t.Errorf("body %q, want it to start with %q", w.Body.String(), want)
	}
	// A kind without a page of its own: the built-in page, under its own policy and the sandbox.
	nf, err := preview(ada, rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_NOT_FOUND)
	if err != nil {
		t.Fatal(err)
	}
	if w := open(nf); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Site not available") ||
		!strings.HasSuffix(w.Header().Get("Content-Security-Policy"), "; sandbox") {
		t.Errorf("the built-in page: %d %v", w.Code, w.Header())
	}

	// Refused links: altered, unsigned, expired, of a changed page; POST. The signature ends the
	// link in base64url, whose last character carries unused bits, so a character inside it is
	// changed, and always to another one.
	i := len(url) - 10
	other := byte('A')
	if url[i] == 'A' {
		other = 'B'
	}
	for name, u := range map[string]string{
		"altered":  url[:i] + string(other) + url[i+1:],
		"no token": apisvc.PreviewPath,
		"garbage":  apisvc.PreviewPath + "x.y",
	} {
		refused(name, open(u), http.StatusNotFound)
	}
	refused("POST", fetch(http.MethodPost, url, "iframe", "same-origin"), http.StatusMethodNotAllowed)
	// Only a frame of the controller's own origin: not a page opened on its own, not another site's
	// frame, not a request without the headers browsers send.
	for name, w := range map[string]*httptest.ResponseRecorder{
		"opened on its own":        fetch(http.MethodGet, url, "document", "none"),
		"a top-level navigation":   fetch(http.MethodGet, url, "document", "same-origin"),
		"another site's frame":     fetch(http.MethodGet, url, "iframe", "cross-site"),
		"a same-site frame":        fetch(http.MethodGet, url, "iframe", "same-site"),
		"no Sec-Fetch headers":     fetch(http.MethodGet, url, "", ""),
		"HEAD without the headers": fetch(http.MethodHead, url, "", ""),
	} {
		refused(name, w, http.StatusNotFound)
	}
	if w := fetch(http.MethodHead, url, "iframe", "same-origin"); w.Code != http.StatusOK || w.Body.Len() != 0 ||
		!strings.HasSuffix(w.Header().Get("Content-Security-Policy"), "; sandbox") {
		t.Errorf("HEAD from the frame: %d %v", w.Code, w.Header())
	}
	if _, err := ada.gw.SetGatewayPage(ctx, connect.NewRequest(&rpmgrv1.SetGatewayPageRequest{GatewayPage: &rpmgrv1.GatewayPage{
		GatewayGroupId: group, Kind: rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE, Html: "<p>changed</p>"}})); err != nil {
		t.Fatal(err)
	}
	if w := open(url); w.Code != http.StatusNotFound {
		t.Errorf("a changed page: %d", w.Code)
	}
	fresh, _ := preview(ada, rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE)
	e.clock = e.clock.Add(6 * time.Minute)
	if w := open(fresh); w.Code != http.StatusNotFound {
		t.Errorf("an expired link: %d", w.Code)
	}

	// Who gets a link: not another org's owner, not a Viewer.
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if _, err := preview(bob, rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE); code(err) != connect.CodeNotFound && code(err) != connect.CodePermissionDenied {
		t.Errorf("another org: %v", err)
	}
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	if _, err := preview(vwr, rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE); code(err) != connect.CodePermissionDenied {
		t.Errorf("a Viewer: %v", err)
	}
}
