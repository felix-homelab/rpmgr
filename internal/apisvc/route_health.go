// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/healthcheck"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
)

// The bounds of a health check (docs/03-connections.md, "Timeouts, keepalive and backoff"): an
// interval of at least 2 s and a timeout below it and at most 1 min; routes.CheckTimes has the
// defaults.
const (
	minCheckIntervalSeconds = 2
	maxCheckTimeoutSeconds  = 60
)

// checkHealth checks a route's health check (docs/03-connections.md, "Target health"): a udp
// route has only a tcp check of a port it names, a tls_passthrough route only a tcp check, as its
// targets speak TLS the gateway does not end; an interval of at least the minimum and a timeout
// below it and at most the maximum; an http path a request line can carry; both statuses or neither, from 100.
func checkHealth(in *rpmgrv1.Route) error {
	c := in.GetHealthCheck()
	if c == nil {
		return nil
	}
	invalid := func(format string, args ...any) error {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: health check: "+format, args...))
	}
	interval, timeout := routes.CheckTimes(int(c.GetIntervalSeconds()), int(c.GetTimeoutSeconds()))
	tcp := c.GetType() == rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP
	switch {
	case in.GetUdp() != nil && (!tcp || c.GetPort() == 0):
		return invalid("a udp route has only a tcp check, of a port it names")
	case in.GetTlsPassthrough() != nil && !tcp:
		return invalid("a tls_passthrough route has only a tcp check: its targets expect TLS the gateway passes through")
	case interval < minCheckIntervalSeconds:
		return invalid("an interval of %d s, below the minimum of %d s", interval, minCheckIntervalSeconds)
	case timeout >= interval || timeout > maxCheckTimeoutSeconds:
		return invalid("a timeout of %d s, not below the interval of %d s or above %d s", timeout, interval, maxCheckTimeoutSeconds)
	case tcp && (c.GetHttpPath() != "" || c.GetExpectedStatusMin() != 0 || c.GetExpectedStatusMax() != 0):
		return invalid("a tcp check has no path or statuses")
	case c.GetHttpPath() != "" && (!strings.HasPrefix(c.GetHttpPath(), "/") ||
		strings.IndexFunc(c.GetHttpPath(), func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r > unicode.MaxASCII }) >= 0):
		return invalid("path %q: a path and query starting with /, in ASCII without spaces", c.GetHttpPath())
	case (c.GetExpectedStatusMin() == 0) != (c.GetExpectedStatusMax() == 0):
		return invalid("give both expected statuses, or neither for 200 to 399")
	case c.GetExpectedStatusMin() != 0 && (c.GetExpectedStatusMin() < 100 || c.GetExpectedStatusMin() > c.GetExpectedStatusMax()):
		return invalid("expected statuses %d to %d", c.GetExpectedStatusMin(), c.GetExpectedStatusMax())
	}
	return nil
}

// setHealthCheck replaces a route's health check with c; nil removes it. A check of a port of its
// own needs targets that have ports, not Unix sockets; an http check needs targets that speak
// HTTP/1.1, which h2c targets do not.
func setHealthCheck(ctx context.Context, tx *ent.Tx, row *ent.Route, c *rpmgrv1.HealthCheck) error {
	if _, err := tx.HealthCheck.Delete().Where(healthcheck.RouteID(row.ID)).Exec(ctx); err != nil || c == nil {
		return err
	}
	if c.GetPort() != 0 {
		sockets, err := tx.RouteTarget.Query().Where(routetarget.RouteID(row.ID), routetarget.UnixPathNEQ("")).Exist(ctx)
		if err != nil {
			return err
		}
		if sockets {
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: health check: a check port, but a target is a Unix socket"))
		}
	}
	if c.GetType() == rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP {
		h2c, err := tx.RouteTarget.Query().Where(routetarget.RouteID(row.ID), routetarget.UpstreamProtocolEQ(routetarget.UpstreamProtocolH2c)).Exist(ctx)
		if err != nil {
			return err
		}
		if h2c {
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: health check: an http check speaks HTTP/1.1, but a target speaks h2c; use a tcp check"))
		}
	}
	typ := healthcheck.TypeHTTP
	if c.GetType() == rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP {
		typ = healthcheck.TypeTCP
	}
	return tx.HealthCheck.Create().SetOrgID(row.OrgID).SetRouteID(row.ID).SetType(typ).SetPort(int(c.GetPort())).
		SetHTTPPath(c.GetHttpPath()).SetExpectedStatusMin(int(c.GetExpectedStatusMin())).SetExpectedStatusMax(int(c.GetExpectedStatusMax())).
		SetIntervalSeconds(int(c.GetIntervalSeconds())).SetTimeoutSeconds(int(c.GetTimeoutSeconds())).
		SetUnhealthyThreshold(int(c.GetUnhealthyThreshold())).SetHealthyThreshold(int(c.GetHealthyThreshold())).Exec(ctx)
}

// healthCheckOf is a route's health check as the API shows it, or nil.
func healthCheckOf(ctx context.Context, c *ent.Client, routeID string) (*rpmgrv1.HealthCheck, error) {
	row, err := c.HealthCheck.Query().Where(healthcheck.RouteID(routeID)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	typ := rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP
	if row.Type == healthcheck.TypeTCP {
		typ = rpmgrv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP
	}
	u := func(v int) uint32 { return uint32(v) } //nolint:gosec // G115: the schema bounds them
	return &rpmgrv1.HealthCheck{Type: typ, Port: u(row.Port), HttpPath: row.HTTPPath, ExpectedStatusMin: u(row.ExpectedStatusMin),
		ExpectedStatusMax: u(row.ExpectedStatusMax), IntervalSeconds: u(row.IntervalSeconds), TimeoutSeconds: u(row.TimeoutSeconds),
		UnhealthyThreshold: u(row.UnhealthyThreshold), HealthyThreshold: u(row.HealthyThreshold)}, nil
}
