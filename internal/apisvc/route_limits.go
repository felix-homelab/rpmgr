// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routelimit"
)

// MinBandwidth is the smallest bandwidth limit of a route, bytes a second (docs/03-connections.md,
// "Route limits"): below it a gateway's step of 512 bytes would wait for longer than half a second.
const MinBandwidth = 1024

// setRouteLimits records a route's limits (docs/03-connections.md, "Route limits"): a row while
// any is set, none for a route without limits.
func setRouteLimits(ctx context.Context, tx *ent.Tx, row *ent.Route, l *rpmgrv1.RouteLimits) error {
	if b := l.GetBandwidthBytesPerSecond(); b > 0 && b < MinBandwidth {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
			"apisvc: a bandwidth of %d bytes a second is below %d, under which data would wait for seconds at a time", b, MinBandwidth))
	}
	if _, err := tx.RouteLimit.Delete().Where(routelimit.RouteID(row.ID)).Exec(ctx); err != nil {
		return err
	}
	if l.GetMaxConnections() == 0 && l.GetRequestsPerSecond() == 0 && l.GetBandwidthBytesPerSecond() == 0 {
		return nil
	}
	return tx.RouteLimit.Create().SetOrgID(row.OrgID).SetRouteID(row.ID).SetMaxConnections(int64(l.GetMaxConnections())).
		SetRequestsPerSec(int64(l.GetRequestsPerSecond())).
		SetBandwidthBytesPerSec(int64(l.GetBandwidthBytesPerSecond())). //nolint:gosec // G115: protovalidate bounds it
		Exec(ctx)
}

// routeLimitsOf returns a route's limits, nil without any.
func routeLimitsOf(ctx context.Context, c *ent.Client, routeID string) (*rpmgrv1.RouteLimits, error) {
	l, err := c.RouteLimit.Query().Where(routelimit.RouteID(routeID)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rpmgrv1.RouteLimits{MaxConnections: uint32(l.MaxConnections), RequestsPerSecond: uint32(l.RequestsPerSec), //nolint:gosec // G115: bounded on write
		BandwidthBytesPerSecond: uint64(l.BandwidthBytesPerSec)}, nil //nolint:gosec // G115: non-negative
}
