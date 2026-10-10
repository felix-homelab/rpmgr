// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestMetricsService (docs/07-api.md, "Services"): a route's traffic comes per hour or per day,
// oldest first, for the last day or the range asked for, within limits; the overview sums an
// org's last 24 hours per hour and names its 10 busiest routes; another org sees none of it.
func TestMetricsService(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	c := e.db.Client()
	hour := e.clock.UTC().Truncate(time.Hour)
	today := time.Date(hour.Year(), hour.Month(), hour.Day(), 0, 0, 0, 0, time.UTC)
	var routes []string
	for i := range 12 {
		routes = append(routes, c.Route.Create().SetOrgID(org).SetName(fmt.Sprint("r", i)).SetType("tcp").SetGatewayGroupID(group).SaveX(e.sys).ID)
	}
	hourly := func(route string, at time.Time, in int64) {
		c.RouteTrafficHourly.Create().SetOrgID(org).SetRouteID(route).SetBucket(at).SetBytesIn(in).SetBytesOut(in / 10).SetConnections(1).
			SetErrors(0).ExecX(e.sys)
	}
	hourly(routes[0], hour.Add(-30*time.Hour), 7)
	hourly(routes[0], hour.Add(-2*time.Hour), 100)
	hourly(routes[0], hour, 50)
	for i := 1; i < 12; i++ {
		hourly(routes[i], hour, int64(i*10))
	}
	for _, d := range []time.Time{today.Add(-48 * time.Hour), today} {
		c.RouteTrafficDaily.Create().SetOrgID(org).SetRouteID(routes[0]).SetBucket(d).SetBytesIn(500).SetBytesOut(50).SetConnections(5).
			SetErrors(1).ExecX(e.sys)
	}

	get := func(req *rpmgrv1.GetRouteTrafficRequest) ([]*rpmgrv1.TrafficBucket, error) {
		r, err := ada.met.GetRouteTraffic(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		return r.Msg.GetBuckets(), nil
	}
	b, err := get(&rpmgrv1.GetRouteTrafficRequest{RouteId: routes[0]})
	if err != nil || len(b) != 2 || !b[0].GetStart().AsTime().Equal(hour.Add(-2*time.Hour)) || b[1].GetBytesIn() != 50 || b[1].GetBytesOut() != 5 {
		t.Fatalf("the last day: %v %v", b, err)
	}
	b, err = get(&rpmgrv1.GetRouteTrafficRequest{RouteId: routes[0], From: timestamppb.New(hour.Add(-31 * time.Hour)), To: timestamppb.New(hour)})
	if err != nil || len(b) != 2 || b[0].GetBytesIn() != 7 || b[1].GetBytesIn() != 100 {
		t.Fatalf("a range ending before the current hour: %v %v", b, err)
	}
	b, err = get(&rpmgrv1.GetRouteTrafficRequest{RouteId: routes[0], Resolution: rpmgrv1.TrafficResolution_TRAFFIC_RESOLUTION_DAILY})
	if err != nil || len(b) != 2 || !b[1].GetStart().AsTime().Equal(today) || b[1].GetErrors() != 1 || b[1].GetConnections() != 5 {
		t.Fatalf("daily: %v %v", b, err)
	}
	for name, req := range map[string]*rpmgrv1.GetRouteTrafficRequest{
		"from after to":         {RouteId: routes[0], From: timestamppb.New(hour), To: timestamppb.New(hour.Add(-time.Hour))},
		"32 days of hours":      {RouteId: routes[0], From: timestamppb.New(hour.Add(-32 * 24 * time.Hour))},
		"401 days of days":      {RouteId: routes[0], Resolution: rpmgrv1.TrafficResolution_TRAFFIC_RESOLUTION_DAILY, From: timestamppb.New(hour.Add(-401 * 24 * time.Hour))},
		"an unknown resolution": {RouteId: routes[0], Resolution: 9},
	} {
		if _, err := get(req); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}

	o, err := ada.met.GetOverview(ctx, connect.NewRequest(&rpmgrv1.GetOverviewRequest{OrgId: org}))
	if err != nil {
		t.Fatal(err)
	}
	m := o.Msg
	if len(m.GetHours()) != 2 || m.GetHours()[0].GetBytesIn() != 100 || m.GetHours()[1].GetBytesIn() != 50+660 || m.GetTotal().GetBytesIn() != 810 {
		t.Fatalf("the hours: %v, total %v", m.GetHours(), m.GetTotal())
	}
	if len(m.GetBusiestRoutes()) != 10 || m.GetBusiestRoutes()[0].GetRouteId() != routes[0] || m.GetBusiestRoutes()[1].GetRouteId() != routes[11] ||
		m.GetBusiestRoutes()[9].GetRouteId() != routes[3] {
		t.Fatalf("the busiest routes: %v", m.GetBusiestRoutes())
	}

	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if _, err := bob.met.GetRouteTraffic(ctx, connect.NewRequest(&rpmgrv1.GetRouteTrafficRequest{RouteId: routes[0]})); code(err) != connect.CodeNotFound {
		t.Fatalf("another org's route: %v", err)
	}
	if ob, err := bob.met.GetOverview(ctx, connect.NewRequest(&rpmgrv1.GetOverviewRequest{OrgId: orgB})); err != nil || len(ob.Msg.GetHours()) != 0 ||
		len(ob.Msg.GetBusiestRoutes()) != 0 {
		t.Fatalf("another org's overview: %v %v", ob, err)
	}
}
