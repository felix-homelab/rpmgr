// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"
	"path"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
)

// targetFields are the fields of a target a client may change; its connector stays.
var targetFields = []string{"host_port", "unix_path", "upstream_protocol", "tls", "proxy_protocol", "weight", "priority", "enabled"}

// The upstream protocols and PROXY versions by the API's names, and back.
var (
	storeUpstreams = map[rpmgrv1.UpstreamProtocol]routetarget.UpstreamProtocol{
		rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_TCP: routetarget.UpstreamProtocolTCP, rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTP: routetarget.UpstreamProtocolHTTP,
		rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_HTTPS: routetarget.UpstreamProtocolHTTPS, rpmgrv1.UpstreamProtocol_UPSTREAM_PROTOCOL_H2C: routetarget.UpstreamProtocolH2c}
	storeProxies = map[rpmgrv1.ProxyProtocol]routetarget.ProxyProtocol{rpmgrv1.ProxyProtocol_PROXY_PROTOCOL_V1: routetarget.ProxyProtocolV1,
		rpmgrv1.ProxyProtocol_PROXY_PROTOCOL_V2: routetarget.ProxyProtocolV2}
)

// CreateRouteTarget implements RouteService.
func (r *Routes) CreateRouteTarget(ctx context.Context, req *connect.Request[rpmgrv1.CreateRouteTargetRequest]) (
	*connect.Response[rpmgrv1.CreateRouteTargetResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, r.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateRouteTargetResponse, error) {
		in := proto.Clone(m.GetTarget()).(*rpmgrv1.RouteTarget)
		in.Enabled = true
		var out *rpmgrv1.RouteTarget
		rev, err := store.ConfigTx(ctx, r.DB, func(tx *ent.Tx) ([]string, error) {
			rt, err := tx.Route.Get(ctx, m.GetRouteId())
			if err != nil {
				return nil, err
			}
			con, err := tx.Connector.Get(ctx, in.GetConnectorId())
			if err != nil {
				return nil, err
			}
			if con.DecommissionedAt != nil {
				return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: the connector is decommissioned"))
			}
			if err := checkTarget(ctx, tx, rt, in, ""); err != nil {
				return nil, err
			}
			c := tx.RouteTarget.Create().SetOrgID(rt.OrgID).SetRouteID(rt.ID).SetConnectorID(con.ID)
			setTarget(c.Mutation(), rt, in)
			row, err := c.Save(ctx)
			if err != nil {
				return nil, err
			}
			out = targetOf(row)
			return []string{rt.ID}, nil
		})
		if err != nil {
			return nil, storeError(err)
		}
		return &rpmgrv1.CreateRouteTargetResponse{Target: out, Revision: revisionOf(rev)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// UpdateRouteTarget implements RouteService.
func (r *Routes) UpdateRouteTarget(ctx context.Context, req *connect.Request[rpmgrv1.UpdateRouteTargetRequest]) (
	*connect.Response[rpmgrv1.UpdateRouteTargetResponse], error) {
	m := req.Msg
	var out *rpmgrv1.RouteTarget
	rev, err := store.ConfigTx(ctx, r.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.RouteTarget.Get(ctx, m.GetTarget().GetId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(m.GetEtag(), cur.Version, targetOf(cur)); err != nil {
			return nil, err
		}
		next := proto.Clone(targetOf(cur)).(*rpmgrv1.RouteTarget)
		if err := api.ApplyMask(next, m.GetTarget(), m.GetUpdateMask(), targetFields...); err != nil {
			return nil, err
		}
		rt, err := tx.Route.Get(ctx, cur.RouteID)
		if err != nil {
			return nil, err
		}
		if err := checkTarget(ctx, tx, rt, next, cur.ID); err != nil {
			return nil, err
		}
		u := tx.RouteTarget.UpdateOneID(cur.ID).Where(routetarget.Version(cur.Version)).ClearTLSCaBundleID()
		setTarget(u.Mutation(), rt, next)
		row, err := u.Save(ctx)
		if err != nil {
			return nil, err
		}
		out = targetOf(row)
		return []string{rt.ID}, nil
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateRouteTargetResponse{Target: out, Revision: revisionOf(rev)}), nil
}

// DeleteRouteTarget implements RouteService.
func (r *Routes) DeleteRouteTarget(ctx context.Context, req *connect.Request[rpmgrv1.DeleteRouteTargetRequest]) (
	*connect.Response[rpmgrv1.DeleteRouteTargetResponse], error) {
	rev, err := store.ConfigTx(ctx, r.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.RouteTarget.Get(ctx, req.Msg.GetRouteTargetId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, targetOf(cur)); err != nil {
			return nil, err
		}
		return []string{cur.RouteID}, tx.RouteTarget.DeleteOneID(cur.ID).Where(routetarget.Version(cur.Version)).Exec(ctx)
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeleteRouteTargetResponse{Revision: revisionOf(rev)}), nil
}

// checkTarget checks a target against its route's type (docs/06-data-model.md, "Routing"): what
// it speaks, its PROXY header and its TLS settings; an http route's targets share one protocol,
// as its first target decides how the gateway speaks to them all. self is the target's own ID
// on an update.
func checkTarget(ctx context.Context, tx *ent.Tx, rt *ent.Route, t *rpmgrv1.RouteTarget, self string) error {
	invalid := func(format string, args ...any) error {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: "+format, args...))
	}
	up := upstreamOf(rt, t)
	switch {
	case t.GetHostPort() == nil && t.GetUnixPath() == "":
		return invalid("a target needs a host_port or a unix_path")
	case t.GetUnixPath() != "" && path.Clean(t.GetUnixPath()) != t.GetUnixPath():
		return invalid("unix_path %q is not a clean absolute path", t.GetUnixPath())
	case rt.Type == route.TypeUDP && t.GetUnixPath() != "":
		return invalid("a udp route's target is a host and port")
	case rt.Type == route.TypeHTTP && up == routetarget.UpstreamProtocolTCP:
		return invalid("an http route's target speaks HTTP, HTTPS or H2C")
	case rt.Type != route.TypeHTTP && up != routetarget.UpstreamProtocolTCP:
		return invalid("only an http route's target speaks HTTP")
	case storeProxies[t.GetProxyProtocol()] != "" && rt.Type != route.TypeTCP && rt.Type != route.TypeTLSPassthrough:
		return invalid("a PROXY header goes only to the target of a tcp or tls_passthrough route")
	case t.GetTls() != nil && up != routetarget.UpstreamProtocolHTTPS:
		return invalid("TLS settings are for an HTTPS target")
	case up == routetarget.UpstreamProtocolHTTPS && t.GetTls().GetServerName() == "" && t.GetUnixPath() != "":
		return invalid("an HTTPS target on a Unix socket needs a server_name")
	}
	if id := t.GetTls().GetCaBundleId(); id != "" {
		if _, err := tx.CABundle.Get(ctx, id); err != nil {
			return err
		}
	}
	if rt.Type == route.TypeHTTP && t.GetEnabled() {
		others, err := tx.RouteTarget.Query().Where(routetarget.RouteID(rt.ID), routetarget.IDNEQ(self), routetarget.Enabled(true),
			routetarget.UpstreamProtocolNEQ(up)).Count(ctx)
		if err != nil {
			return err
		}
		if others > 0 {
			return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("apisvc: the route's other targets speak another protocol than %s", up))
		}
	}
	return nil
}

// upstreamOf is the protocol a target speaks, by default its route type's.
func upstreamOf(rt *ent.Route, t *rpmgrv1.RouteTarget) routetarget.UpstreamProtocol {
	if up, ok := storeUpstreams[t.GetUpstreamProtocol()]; ok {
		return up
	}
	if rt.Type == route.TypeHTTP {
		return routetarget.UpstreamProtocolHTTP
	}
	return routetarget.UpstreamProtocolTCP
}

// setTarget sets a target's fields on a create or an update.
func setTarget(m *ent.RouteTargetMutation, rt *ent.Route, t *rpmgrv1.RouteTarget) {
	if hp := t.GetHostPort(); hp != nil {
		m.SetKind(routetarget.KindAddress)
		m.SetHost(hp.GetHost())
		m.SetPort(int(hp.GetPort()))
		m.SetUnixPath("")
	} else {
		m.SetKind(routetarget.KindUnix)
		m.SetUnixPath(t.GetUnixPath())
		m.SetHost("")
		m.SetPort(0)
	}
	m.SetUpstreamProtocol(upstreamOf(rt, t))
	m.SetTLSServerName(t.GetTls().GetServerName())
	m.SetTLSSpkiSha256(t.GetTls().GetSpkiSha256())
	if id := t.GetTls().GetCaBundleId(); id != "" {
		m.SetTLSCaBundleID(id)
	}
	m.SetProxyProtocol(routetarget.ProxyProtocolNone)
	if p, ok := storeProxies[t.GetProxyProtocol()]; ok {
		m.SetProxyProtocol(p)
	}
	m.SetWeight(max(int(t.GetWeight()), 1))
	m.SetPriority(int(t.GetPriority()))
	m.SetEnabled(t.GetEnabled())
}

func targetOf(r *ent.RouteTarget) *rpmgrv1.RouteTarget {
	out := &rpmgrv1.RouteTarget{Id: r.ID, ConnectorId: r.ConnectorID, Weight: uint32(r.Weight), Priority: uint32(r.Priority), //nolint:gosec // G115: bounded by the schema
		Enabled: r.Enabled, Etag: etagOf(r.Version), ProxyProtocol: rpmgrv1.ProxyProtocol_PROXY_PROTOCOL_NONE}
	if r.Kind == routetarget.KindUnix {
		out.Address = &rpmgrv1.RouteTarget_UnixPath{UnixPath: r.UnixPath}
	} else {
		out.Address = &rpmgrv1.RouteTarget_HostPort{HostPort: &rpmgrv1.HostPort{Host: r.Host, Port: uint32(r.Port)}} //nolint:gosec // G115: a port
	}
	for api, st := range storeUpstreams {
		if st == r.UpstreamProtocol {
			out.UpstreamProtocol = api
		}
	}
	for api, st := range storeProxies {
		if st == r.ProxyProtocol {
			out.ProxyProtocol = api
		}
	}
	if r.UpstreamProtocol == routetarget.UpstreamProtocolHTTPS {
		out.Tls = &rpmgrv1.UpstreamTLSSettings{ServerName: r.TLSServerName, SpkiSha256: r.TLSSpkiSha256}
		if r.TLSCaBundleID != nil {
			out.Tls.CaBundleId = *r.TLSCaBundleID
		}
	}
	return out
}

// targetsOf lists a route's targets by priority, for the route's view.
func targetsOf(ctx context.Context, c *ent.Client, routeID string) ([]*rpmgrv1.RouteTarget, error) {
	rows, err := c.RouteTarget.Query().Where(routetarget.RouteID(routeID)).
		Order(ent.Asc(routetarget.FieldPriority), ent.Asc(routetarget.FieldID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*rpmgrv1.RouteTarget, len(rows))
	for i, row := range rows {
		out[i] = targetOf(row)
	}
	return out, nil
}
