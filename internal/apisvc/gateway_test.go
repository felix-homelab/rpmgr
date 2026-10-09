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
