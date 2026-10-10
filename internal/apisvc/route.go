// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routepolicy"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routeudp"
)

// The reasons of refused routes.
const (
	// ReasonDomainNotVerified: a hostname lies under no verified domain of the org.
	ReasonDomainNotVerified = "DOMAIN_NOT_VERIFIED"
)

// Routes is RouteService. Its methods run in the org scope the interceptor gives them.
type Routes struct {
	rpmgrv1connect.UnimplementedRouteServiceHandler
	DB  *store.DB
	API *api.Server
	Now func() time.Time
}

// CreateRoute implements RouteService.
func (r *Routes) CreateRoute(ctx context.Context, req *connect.Request[rpmgrv1.CreateRouteRequest]) (
	*connect.Response[rpmgrv1.CreateRouteResponse], error) {
	m := req.Msg
	resp, err := api.Dedupe(ctx, r.API, m.GetRequestId(), m, func(ctx context.Context) (*rpmgrv1.CreateRouteResponse, error) {
		in := m.GetRoute()
		if err := checkSpec(in); err != nil {
			return nil, err
		}
		var out *rpmgrv1.Route
		rev, err := store.ConfigTx(ctx, r.DB, func(tx *ent.Tx) ([]string, error) {
			if _, err := tx.GatewayGroup.Get(ctx, in.GetGatewayGroupId()); err != nil {
				return nil, err
			}
			c := tx.Route.Create().SetOrgID(m.GetOrgId()).SetName(in.GetName()).SetGatewayGroupID(in.GetGatewayGroupId()).
				SetDescription(in.GetDescription()).SetLabels(in.GetLabels()).SetUpdatedBy(api.CallerFrom(ctx).UserID).SetCreatedAt(r.now()).
				SetUpdatedAt(r.now())
			if t, ok := storeRouteTransports[in.GetTransport()]; ok {
				c.SetTransport(t)
			}
			var hostnames []string
			if spec, ok := in.GetSpec().(*rpmgrv1.Route_TlsPassthrough); ok {
				c.SetType(route.TypeTLSPassthrough)
				hostnames = spec.TlsPassthrough.GetHostnames()
			}
			row, err := c.Save(ctx)
			if err != nil {
				return nil, err
			}
			for _, name := range hostnames {
				if _, err := routes.AddHostname(ctx, tx, row.ID, name, ""); err != nil {
					return nil, err
				}
			}
			out, err = routeOf(ctx, tx.Client(), row)
			return []string{row.ID}, err
		})
		if err != nil {
			return nil, routeError(err)
		}
		return &rpmgrv1.CreateRouteResponse{Route: out, Revision: revisionOf(rev)}, nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// checkSpec checks what the store cannot: a spec of a known type.
func checkSpec(in *rpmgrv1.Route) error {
	if in.GetSpec() == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("apisvc: a route needs a spec: tls_passthrough"))
	}
	return nil
}

// routeError gives the route rules' errors their API codes.
func routeError(err error) error {
	switch {
	case errors.Is(err, domains.ErrNotOwned):
		return withReason(connect.NewError(connect.CodeFailedPrecondition, err), ReasonDomainNotVerified)
	case errors.Is(err, routes.ErrHostnameTaken):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, domains.ErrInvalid), errors.Is(err, routes.ErrPathPrefix):
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return storeError(err)
}

// GetRoute implements RouteService.
func (r *Routes) GetRoute(ctx context.Context, req *connect.Request[rpmgrv1.GetRouteRequest]) (*connect.Response[rpmgrv1.GetRouteResponse], error) {
	c := r.DB.ReadClient()
	row, err := c.Route.Get(ctx, req.Msg.GetRouteId())
	if err != nil {
		return nil, storeError(err)
	}
	out, err := routeOf(ctx, c, row)
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetRouteResponse{Route: out}), nil
}

// ListRoutes implements RouteService.
func (r *Routes) ListRoutes(ctx context.Context, req *connect.Request[rpmgrv1.ListRoutesRequest]) (*connect.Response[rpmgrv1.ListRoutesResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := r.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	c := r.DB.ReadClient()
	q := c.Route.Query().Where(route.OrgID(m.GetOrgId()), route.TypeIn(route.TypeHTTP, route.TypeTLSPassthrough)).
		Order(ent.Asc(route.FieldID)).Limit(size + 1)
	if m.GetGatewayGroupId() != "" {
		q.Where(route.GatewayGroupID(m.GetGatewayGroupId()))
	}
	if after != "" {
		q.Where(route.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListRoutesResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = r.API.PageToken(rows[size-1].ID, m)
	}
	for _, row := range rows {
		rt, err := routeOf(ctx, c, row)
		if err != nil {
			return nil, storeError(err)
		}
		out.Routes = append(out.Routes, rt)
	}
	return connect.NewResponse(out), nil
}

// DeleteRoute implements RouteService: the route goes with everything of it, and its port is free
// again.
func (r *Routes) DeleteRoute(ctx context.Context, req *connect.Request[rpmgrv1.DeleteRouteRequest]) (*connect.Response[rpmgrv1.DeleteRouteResponse], error) {
	rev, err := store.ConfigTx(ctx, r.DB, func(tx *ent.Tx) ([]string, error) {
		cur, err := tx.Route.Get(ctx, req.Msg.GetRouteId())
		if err != nil {
			return nil, err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, &rpmgrv1.Route{Id: cur.ID, Etag: etagOf(cur.Version)}); err != nil {
			return nil, err
		}
		var ports []string
		if t, err := tx.RouteTCP.Query().Where(routetcp.RouteID(cur.ID)).Only(ctx); err == nil {
			ports = append(ports, t.PortAllocationID)
		}
		if u, err := tx.RouteUDP.Query().Where(routeudp.RouteID(cur.ID)).Only(ctx); err == nil {
			ports = append(ports, u.PortAllocationID)
		}
		for _, del := range []func() error{
			func() error {
				_, err := tx.RouteHostname.Delete().Where(routehostname.RouteID(cur.ID)).Exec(ctx)
				return err
			},
			func() error { _, err := tx.RouteHTTP.Delete().Where(routehttp.RouteID(cur.ID)).Exec(ctx); return err },
			func() error { _, err := tx.RouteTCP.Delete().Where(routetcp.RouteID(cur.ID)).Exec(ctx); return err },
			func() error { _, err := tx.RouteUDP.Delete().Where(routeudp.RouteID(cur.ID)).Exec(ctx); return err },
			func() error {
				_, err := tx.RouteTarget.Delete().Where(routetarget.RouteID(cur.ID)).Exec(ctx)
				return err
			},
			func() error {
				_, err := tx.RoutePolicy.Delete().Where(routepolicy.RouteID(cur.ID)).Exec(ctx)
				return err
			},
		} {
			if err := del(); err != nil {
				return nil, err
			}
		}
		for _, p := range ports {
			if err := routes.Release(ctx, tx, p); err != nil {
				return nil, err
			}
		}
		return []string{cur.ID}, tx.Route.DeleteOneID(cur.ID).Where(route.Version(cur.Version)).Exec(ctx)
	})
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.DeleteRouteResponse{Revision: revisionOf(rev)}), nil
}

func (r *Routes) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// storeRouteTransports are the store's transport policies by the API's; unspecified is none.
var storeRouteTransports = map[rpmgrv1.DataTransport]route.Transport{rpmgrv1.DataTransport_DATA_TRANSPORT_AUTO: route.TransportAuto,
	rpmgrv1.DataTransport_DATA_TRANSPORT_QUIC: route.TransportQuic, rpmgrv1.DataTransport_DATA_TRANSPORT_H2: route.TransportH2}

// routeOf is a route as the API shows it, with its spec and hostnames.
func routeOf(ctx context.Context, c *ent.Client, row *ent.Route) (*rpmgrv1.Route, error) {
	out := &rpmgrv1.Route{Id: row.ID, Name: row.Name, GatewayGroupId: row.GatewayGroupID, Enabled: row.Enabled, Labels: row.Labels,
		Description: row.Description, CreateTime: timestamppb.New(row.CreatedAt), UpdateTime: timestamppb.New(row.UpdatedAt), Etag: etagOf(row.Version)}
	if row.Transport != nil {
		for api, st := range storeRouteTransports {
			if st == *row.Transport {
				out.Transport = api
			}
		}
	}
	hs, err := c.RouteHostname.Query().Where(routehostname.RouteID(row.ID)).Order(ent.Asc(routehostname.FieldHostname)).All(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(hs))
	for i, h := range hs {
		names[i] = h.Hostname
	}
	if row.Type == route.TypeTLSPassthrough {
		out.Spec = &rpmgrv1.Route_TlsPassthrough{TlsPassthrough: &rpmgrv1.TLSPassthroughRouteSpec{Hostnames: names}}
	}
	return out, nil
}
