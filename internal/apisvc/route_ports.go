// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routeudp"
)

// The reasons of refused ports.
const (
	ReasonPortNotInPool  = "PORT_NOT_IN_POOL"
	ReasonPoolExhausted  = "POOL_EXHAUSTED"
	ReasonQuotaReached   = "QUOTA_REACHED"
	defaultIdleTimeout   = 3600
	defaultFlowIdleTimer = 60
)

// portError gives the port rules' errors their API codes; it returns nil for other errors.
func portError(err error) error {
	switch {
	case errors.Is(err, routes.ErrPortTaken):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, routes.ErrNotInPool):
		return withReason(connect.NewError(connect.CodeFailedPrecondition, err), ReasonPortNotInPool)
	case errors.Is(err, routes.ErrPoolExhausted):
		return withReason(connect.NewError(connect.CodeResourceExhausted, err), ReasonPoolExhausted)
	case errors.Is(err, routes.ErrQuotaReached):
		return withReason(connect.NewError(connect.CodeResourceExhausted, err), ReasonQuotaReached)
	case errors.Is(err, routes.ErrNoGroup):
		return connect.NewError(connect.CodeNotFound, errors.New("apisvc: not found"))
	}
	return nil
}

// allocate allocates port of protocol p for row, 0 for a random free one, in place of the
// allocation replaces if it is set, and records the route on the allocation.
func allocate(ctx context.Context, tx *ent.Tx, row *ent.Route, p routes.Protocol, port uint32, replaces string) (*ent.PortAllocation, error) {
	a, err := routes.AllocateReplacing(ctx, tx, row.OrgID, row.GatewayGroupID, p, int(port), replaces)
	if err != nil {
		return nil, err
	}
	return tx.PortAllocation.UpdateOne(a).SetRouteID(row.ID).Save(ctx)
}

// allocateBoth is allocate for a tcp_udp route: one port number for TCP and for UDP, in place of
// the allocations replacesTCP and replacesUDP if they are set.
func allocateBoth(ctx context.Context, tx *ent.Tx, row *ent.Route, port uint32, replacesTCP, replacesUDP string) (tcp,
	udp *ent.PortAllocation, err error) {
	if tcp, udp, err = routes.AllocateBoth(ctx, tx, row.OrgID, row.GatewayGroupID, int(port), replacesTCP, replacesUDP); err != nil {
		return nil, nil, err
	}
	if tcp, err = tx.PortAllocation.UpdateOne(tcp).SetRouteID(row.ID).Save(ctx); err != nil {
		return nil, nil, err
	}
	udp, err = tx.PortAllocation.UpdateOne(udp).SetRouteID(row.ID).Save(ctx)
	return tcp, udp, err
}

// createPortRoute stores a tcp, udp or tcp_udp route's ports and settings: a tcp_udp route has a
// tcp and a udp part, on one port number.
func createPortRoute(ctx context.Context, tx *ent.Tx, row *ent.Route, in *rpmgrv1.Route) error {
	switch {
	case in.GetTcp() != nil:
		a, err := allocate(ctx, tx, row, routes.TCP, in.GetTcp().GetPort(), "")
		if err != nil {
			return err
		}
		return tx.RouteTCP.Create().SetOrgID(row.OrgID).SetRouteID(row.ID).SetPortAllocationID(a.ID).SetIdleTimeoutSeconds(idleTimeout(in.GetTcp().IdleTimeoutSeconds)).Exec(ctx)
	case in.GetUdp() != nil:
		a, err := allocate(ctx, tx, row, routes.UDP, in.GetUdp().GetPort(), "")
		if err != nil {
			return err
		}
		return tx.RouteUDP.Create().SetOrgID(row.OrgID).SetRouteID(row.ID).SetPortAllocationID(a.ID).SetFlowIdleTimeoutSeconds(flowIdleTimeout(in.GetUdp().FlowIdleTimeoutSeconds)).Exec(ctx)
	case in.GetTcpUdp() != nil:
		spec := in.GetTcpUdp()
		tcp, udp, err := allocateBoth(ctx, tx, row, spec.GetPort(), "", "")
		if err != nil {
			return err
		}
		if err := tx.RouteTCP.Create().SetOrgID(row.OrgID).SetRouteID(row.ID).SetPortAllocationID(tcp.ID).
			SetIdleTimeoutSeconds(idleTimeout(spec.IdleTimeoutSeconds)).Exec(ctx); err != nil {
			return err
		}
		return tx.RouteUDP.Create().SetOrgID(row.OrgID).SetRouteID(row.ID).SetPortAllocationID(udp.ID).
			SetFlowIdleTimeoutSeconds(flowIdleTimeout(spec.FlowIdleTimeoutSeconds)).Exec(ctx)
	}
	return nil
}

// idleTimeout is a tcp or tcp_udp route's idle timeout in seconds, given as set: the default when
// it is not set, on create and when an update clears it.
func idleTimeout(set *uint32) int {
	if set == nil {
		return defaultIdleTimeout
	}
	return int(*set)
}

// flowIdleTimeout is a udp or tcp_udp route's flow idle timeout in seconds, given as set: the
// default when it is not set, on create and when an update clears it.
func flowIdleTimeout(set *uint32) int {
	if set == nil {
		return defaultFlowIdleTimer
	}
	return int(*set)
}

// updatePortRoute changes a tcp, udp or tcp_udp route's settings, and its port: the new one is
// allocated, not counting the old one towards the quota, before the old one is freed; a refused
// port rolls the transaction back. A tcp_udp route moves its TCP and its UDP port together.
func updatePortRoute(ctx context.Context, tx *ent.Tx, row *ent.Route, was, next *rpmgrv1.Route) error {
	switch row.Type {
	case route.TypeTCP:
		cur, err := tx.RouteTCP.Query().Where(routetcp.RouteID(row.ID)).Only(ctx)
		if err != nil {
			return err
		}
		u := tx.RouteTCP.UpdateOne(cur).SetIdleTimeoutSeconds(idleTimeout(next.GetTcp().IdleTimeoutSeconds))
		if p := next.GetTcp().GetPort(); p != was.GetTcp().GetPort() {
			a, err := allocate(ctx, tx, row, routes.TCP, p, cur.PortAllocationID)
			if err != nil {
				return err
			}
			u.SetPortAllocationID(a.ID)
			if err := u.Exec(ctx); err != nil {
				return err
			}
			return routes.Release(ctx, tx, cur.PortAllocationID)
		}
		return u.Exec(ctx)
	case route.TypeUDP:
		cur, err := tx.RouteUDP.Query().Where(routeudp.RouteID(row.ID)).Only(ctx)
		if err != nil {
			return err
		}
		u := tx.RouteUDP.UpdateOne(cur).SetFlowIdleTimeoutSeconds(flowIdleTimeout(next.GetUdp().FlowIdleTimeoutSeconds))
		if p := next.GetUdp().GetPort(); p != was.GetUdp().GetPort() {
			a, err := allocate(ctx, tx, row, routes.UDP, p, cur.PortAllocationID)
			if err != nil {
				return err
			}
			u.SetPortAllocationID(a.ID)
			if err := u.Exec(ctx); err != nil {
				return err
			}
			return routes.Release(ctx, tx, cur.PortAllocationID)
		}
		return u.Exec(ctx)
	case route.TypeTCPUDP:
		return updateTCPUDP(ctx, tx, row, was.GetTcpUdp(), next.GetTcpUdp())
	}
	return nil
}

// updateTCPUDP is updatePortRoute for a tcp_udp route.
func updateTCPUDP(ctx context.Context, tx *ent.Tx, row *ent.Route, was, next *rpmgrv1.TCPUDPRouteSpec) error {
	curTCP, err := tx.RouteTCP.Query().Where(routetcp.RouteID(row.ID)).Only(ctx)
	if err != nil {
		return err
	}
	curUDP, err := tx.RouteUDP.Query().Where(routeudp.RouteID(row.ID)).Only(ctx)
	if err != nil {
		return err
	}
	ut := tx.RouteTCP.UpdateOne(curTCP).SetIdleTimeoutSeconds(idleTimeout(next.IdleTimeoutSeconds))
	uu := tx.RouteUDP.UpdateOne(curUDP).SetFlowIdleTimeoutSeconds(flowIdleTimeout(next.FlowIdleTimeoutSeconds))
	moved := next.GetPort() != was.GetPort()
	if moved {
		tcp, udp, err := allocateBoth(ctx, tx, row, next.GetPort(), curTCP.PortAllocationID, curUDP.PortAllocationID)
		if err != nil {
			return err
		}
		ut.SetPortAllocationID(tcp.ID)
		uu.SetPortAllocationID(udp.ID)
	}
	if err := ut.Exec(ctx); err != nil {
		return err
	}
	if err := uu.Exec(ctx); err != nil {
		return err
	}
	if !moved {
		return nil
	}
	if err := routes.Release(ctx, tx, curTCP.PortAllocationID); err != nil {
		return err
	}
	return routes.Release(ctx, tx, curUDP.PortAllocationID)
}

// setPortSpec sets out's spec to a tcp, udp or tcp_udp route's.
func setPortSpec(ctx context.Context, c *ent.Client, row *ent.Route, out *rpmgrv1.Route) error {
	switch row.Type {
	case route.TypeTCP:
		t, err := c.RouteTCP.Query().Where(routetcp.RouteID(row.ID)).Only(ctx)
		if err != nil {
			return err
		}
		a, err := c.PortAllocation.Get(ctx, t.PortAllocationID)
		if err != nil {
			return err
		}
		idle := uint32(t.IdleTimeoutSeconds)                                                                       //nolint:gosec // G115: non-negative, bounded by the API
		out.Spec = &rpmgrv1.Route_Tcp{Tcp: &rpmgrv1.TCPRouteSpec{Port: uint32(a.Port), IdleTimeoutSeconds: &idle}} //nolint:gosec // G115: a port
	case route.TypeUDP:
		u, err := c.RouteUDP.Query().Where(routeudp.RouteID(row.ID)).Only(ctx)
		if err != nil {
			return err
		}
		a, err := c.PortAllocation.Get(ctx, u.PortAllocationID)
		if err != nil {
			return err
		}
		idle := uint32(u.FlowIdleTimeoutSeconds)                                                                       //nolint:gosec // G115: positive, bounded by the API
		out.Spec = &rpmgrv1.Route_Udp{Udp: &rpmgrv1.UDPRouteSpec{Port: uint32(a.Port), FlowIdleTimeoutSeconds: &idle}} //nolint:gosec // G115: a port
	case route.TypeTCPUDP:
		t, err := c.RouteTCP.Query().Where(routetcp.RouteID(row.ID)).WithPort().Only(ctx)
		if err != nil {
			return err
		}
		u, err := c.RouteUDP.Query().Where(routeudp.RouteID(row.ID)).Only(ctx)
		if err != nil {
			return err
		}
		idle, flowIdle := uint32(t.IdleTimeoutSeconds), uint32(u.FlowIdleTimeoutSeconds)                   //nolint:gosec // G115: non-negative, bounded by the API
		out.Spec = &rpmgrv1.Route_TcpUdp{TcpUdp: &rpmgrv1.TCPUDPRouteSpec{Port: uint32(t.Edges.Port.Port), //nolint:gosec // G115: a port
			IdleTimeoutSeconds: &idle, FlowIdleTimeoutSeconds: &flowIdle}}
	}
	return nil
}
