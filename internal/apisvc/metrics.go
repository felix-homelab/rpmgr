// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetrafficdaily"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetraffichourly"
)

// The ranges of GetRouteTraffic (docs/07-api.md, "Services"): the default and the longest.
const (
	day             = 24 * time.Hour
	hourlyDefault   = day
	hourlyMax       = 31 * day
	dailyDefault    = 30 * day
	dailyMax        = 400 * day
	busiestRoutes   = 10
	overviewBuckets = 24
)

// Metrics implements MetricsService over the route traffic rollups (docs/06-data-model.md,
// "Desired vs observed state"). The caller's scope limits every query to its org.
type Metrics struct {
	rpmgrv1connect.UnimplementedMetricsServiceHandler
	DB  *store.DB
	Now func() time.Time
}

func (m *Metrics) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

// bucketRow is a rollup row of either resolution.
type bucketRow struct {
	route     string
	start     time.Time
	in, out   int64
	conns, ko int64
}

func bucketOf(start time.Time, in, out, conns, errs int64) *rpmgrv1.TrafficBucket {
	return &rpmgrv1.TrafficBucket{Start: timestamppb.New(start), BytesIn: uint64(max(in, 0)), BytesOut: uint64(max(out, 0)), //nolint:gosec // G115: not negative
		Connections: uint64(max(conns, 0)), Errors: uint64(max(errs, 0))} //nolint:gosec // G115: not negative
}

// GetRouteTraffic implements MetricsService.
func (m *Metrics) GetRouteTraffic(ctx context.Context, req *connect.Request[rpmgrv1.GetRouteTrafficRequest]) (
	*connect.Response[rpmgrv1.GetRouteTrafficResponse], error) {
	msg := req.Msg
	daily := msg.GetResolution() == rpmgrv1.TrafficResolution_TRAFFIC_RESOLUTION_DAILY
	span, longest := hourlyDefault, hourlyMax
	if daily {
		span, longest = dailyDefault, dailyMax
	}
	to := m.now()
	if msg.GetTo() != nil {
		to = msg.GetTo().AsTime().UTC()
	}
	from := to.Add(-span)
	if msg.GetFrom() != nil {
		from = msg.GetFrom().AsTime().UTC()
	}
	if !from.Before(to) || to.Sub(from) > longest {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: from must be before to, at most 31 days of hourly or 400 days of daily buckets"))
	}
	rows, err := m.rows(ctx, daily, from, to, msg.GetRouteId())
	if err != nil {
		return nil, err
	}
	out := &rpmgrv1.GetRouteTrafficResponse{}
	for _, r := range rows {
		out.Buckets = append(out.Buckets, bucketOf(r.start, r.in, r.out, r.conns, r.ko))
	}
	return connect.NewResponse(out), nil
}

// rows returns the buckets that start in [from, to), from rounded down to its bucket, oldest
// first; of one route if route is set.
func (m *Metrics) rows(ctx context.Context, daily bool, from, to time.Time, route string) ([]bucketRow, error) {
	var out []bucketRow
	rc := m.DB.ReadClient()
	if daily {
		q := rc.RouteTrafficDaily.Query().Where(routetrafficdaily.BucketGTE(from.Truncate(day)), routetrafficdaily.BucketLT(to)).
			Order(ent.Asc(routetrafficdaily.FieldBucket), ent.Asc(routetrafficdaily.FieldRouteID))
		if route != "" {
			q.Where(routetrafficdaily.RouteID(route))
		}
		all, err := q.All(ctx)
		if err != nil {
			return nil, storeError(err)
		}
		for _, r := range all {
			out = append(out, bucketRow{r.RouteID, r.Bucket.UTC(), r.BytesIn, r.BytesOut, r.Connections, r.Errors})
		}
		return out, nil
	}
	q := rc.RouteTrafficHourly.Query().Where(routetraffichourly.BucketGTE(from.Truncate(time.Hour)), routetraffichourly.BucketLT(to)).
		Order(ent.Asc(routetraffichourly.FieldBucket), ent.Asc(routetraffichourly.FieldRouteID))
	if route != "" {
		q.Where(routetraffichourly.RouteID(route))
	}
	all, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	for _, r := range all {
		out = append(out, bucketRow{r.RouteID, r.Bucket.UTC(), r.BytesIn, r.BytesOut, r.Connections, r.Errors})
	}
	return out, nil
}

// GetOverview implements MetricsService.
func (m *Metrics) GetOverview(ctx context.Context, _ *connect.Request[rpmgrv1.GetOverviewRequest]) (
	*connect.Response[rpmgrv1.GetOverviewResponse], error) {
	now := m.now()
	first := now.Truncate(time.Hour).Add(-(overviewBuckets - 1) * time.Hour)
	rows, err := m.rows(ctx, false, first, now.Add(time.Hour), "")
	if err != nil {
		return nil, err
	}
	var hours []bucketRow
	var total bucketRow
	routes := map[string]*bucketRow{}
	for _, r := range rows {
		if n := len(hours); n == 0 || !hours[n-1].start.Equal(r.start) {
			hours = append(hours, bucketRow{start: r.start})
		}
		for _, sum := range []*bucketRow{&hours[len(hours)-1], &total, routeSum(routes, r.route)} {
			sum.in, sum.out, sum.conns, sum.ko = sum.in+r.in, sum.out+r.out, sum.conns+r.conns, sum.ko+r.ko
		}
	}
	out := &rpmgrv1.GetOverviewResponse{Total: bucketOf(first, total.in, total.out, total.conns, total.ko)}
	for _, h := range hours {
		out.Hours = append(out.Hours, bucketOf(h.start, h.in, h.out, h.conns, h.ko))
	}
	busiest := make([]*bucketRow, 0, len(routes))
	for _, r := range routes {
		busiest = append(busiest, r)
	}
	slices.SortFunc(busiest, func(a, b *bucketRow) int {
		if d := (b.in + b.out) - (a.in + a.out); d != 0 {
			return int(min(max(d, -1), 1))
		}
		return strings.Compare(a.route, b.route)
	})
	for _, r := range busiest[:min(len(busiest), busiestRoutes)] {
		out.BusiestRoutes = append(out.BusiestRoutes, &rpmgrv1.RouteTraffic{RouteId: r.route, Total: bucketOf(first, r.in, r.out, r.conns, r.ko)})
	}
	return connect.NewResponse(out), nil
}

func routeSum(routes map[string]*bucketRow, id string) *bucketRow {
	if routes[id] == nil {
		routes[id] = &bucketRow{route: id}
	}
	return routes[id]
}
