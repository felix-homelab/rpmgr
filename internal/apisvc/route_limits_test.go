// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routelimit"
)

// TestRouteLimits (docs/03-connections.md, "Route limits"): a route is created with limits, which
// it returns; an update changes one limit by its path and keeps the others; limits of 0 leave no
// row; a value above its bound is refused and changes nothing; deleting the route deletes them.
func TestRouteLimits(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	e.verified(t, org, "example.com", true)
	in := passthroughRoute("db", group, "db.example.com")
	in.Limits = &rpmgrv1.RouteLimits{MaxConnections: 100, RequestsPerSecond: 20, BandwidthBytesPerSecond: 1 << 20}
	rt, err := createRoute(ada, org, in, "")
	if err != nil || !proto.Equal(rt.GetLimits(), in.GetLimits()) {
		t.Fatalf("created with limits: %v %v", rt.GetLimits(), err)
	}
	update := func(mask string, l *rpmgrv1.RouteLimits) (*rpmgrv1.Route, error) {
		r, err := ada.rt.UpdateRoute(ctx, connect.NewRequest(&rpmgrv1.UpdateRouteRequest{Route: &rpmgrv1.Route{Id: rt.GetId(), Limits: l},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{mask}}}))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetRoute(), nil
	}
	up, err := update("limits.max_connections", &rpmgrv1.RouteLimits{MaxConnections: 5, RequestsPerSecond: 999})
	if want := (&rpmgrv1.RouteLimits{MaxConnections: 5, RequestsPerSecond: 20, BandwidthBytesPerSecond: 1 << 20}); err != nil ||
		!proto.Equal(up.GetLimits(), want) {
		t.Fatalf("one limit by its path: %v %v", up.GetLimits(), err)
	}
	for _, l := range []*rpmgrv1.RouteLimits{{MaxConnections: 1_000_001}, {RequestsPerSecond: 1_000_001}, {BandwidthBytesPerSecond: 100_000_000_001}} {
		if _, err := update("limits", l); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("limits %v above the bounds: %v", l, err)
		}
	}
	if _, err := update("limits", &rpmgrv1.RouteLimits{BandwidthBytesPerSecond: 1023}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a bandwidth below 1 KiB a second: %v", err)
	}
	if up, err := update("limits.bandwidth_bytes_per_second", &rpmgrv1.RouteLimits{BandwidthBytesPerSecond: 1024}); err != nil ||
		up.GetLimits().GetBandwidthBytesPerSecond() != 1024 {
		t.Fatalf("a bandwidth of 1 KiB a second: %v %v", up.GetLimits(), err)
	}
	if _, err := update("limits.bandwidth_bytes_per_second", &rpmgrv1.RouteLimits{BandwidthBytesPerSecond: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	got, err := ada.rt.GetRoute(ctx, connect.NewRequest(&rpmgrv1.GetRouteRequest{RouteId: rt.GetId()}))
	if err != nil || got.Msg.GetRoute().GetLimits().GetMaxConnections() != 5 {
		t.Fatalf("after refused updates: %v %v", got.Msg.GetRoute().GetLimits(), err)
	}
	c := e.db.Client()
	if up, err := update("limits", &rpmgrv1.RouteLimits{}); err != nil || up.GetLimits() != nil ||
		c.RouteLimit.Query().Where(routelimit.RouteID(rt.GetId())).ExistX(e.sys) {
		t.Fatalf("limits of 0: %v %v", up.GetLimits(), err)
	}
	if _, err := update("limits", &rpmgrv1.RouteLimits{RequestsPerSecond: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := ada.rt.DeleteRoute(ctx, connect.NewRequest(&rpmgrv1.DeleteRouteRequest{RouteId: rt.GetId()})); err != nil {
		t.Fatal(err)
	}
	if c.RouteLimit.Query().ExistX(e.sys) {
		t.Fatal("a deleted route kept its limits")
	}
}
