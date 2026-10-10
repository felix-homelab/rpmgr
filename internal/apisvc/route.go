// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"
	"net/textproto"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http/httpguts"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
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
	// ReasonWildcardACME: ACME cannot issue a wildcard certificate in Phase 1 (R42).
	ReasonWildcardACME = "WILDCARD_NEEDS_CERTIFICATE"
	// ReasonCertificateNotCovering: the uploaded certificate a route names does not cover each of
	// its hostnames.
	ReasonCertificateNotCovering = "CERTIFICATE_NOT_COVERING"
)

// maxHostnames is how many hostnames a route has at most.
const maxHostnames = 100

// Routes is RouteService. Its methods run in the org scope the interceptor gives them.
type Routes struct {
	rpmgrv1connect.UnimplementedRouteServiceHandler
	DB  *store.DB
	API *api.Server
	// Sys is the controller's system scope, for the revisions a route status reads.
	Sys context.Context
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
			row, err := r.createRouteTx(ctx, tx, m.GetOrgId(), in)
			if err != nil {
				return nil, err
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

// createHTTP stores an http route's settings.
func createHTTP(ctx context.Context, tx *ent.Tx, row *ent.Route, h *rpmgrv1.HTTPRouteSpec) error {
	port80 := routehttp.Port80Redirect
	switch h.GetPort80() {
	case rpmgrv1.Port80Mode_PORT80_MODE_SERVE:
		port80 = routehttp.Port80Serve
	case rpmgrv1.Port80Mode_PORT80_MODE_OFF:
		port80 = routehttp.Port80Off
	}
	c := tx.RouteHTTP.Create().SetOrgID(row.OrgID).SetRouteID(row.ID).SetPathPrefix(h.GetPathPrefix()).SetPort80(port80).
		SetHstsMaxAgeSeconds(int(h.GetHstsMaxAgeSeconds())).SetRequestHeadersSet(canonicalHeaders(h.GetRequestHeadersSet())).
		SetResponseHeadersSet(canonicalHeaders(h.GetResponseHeadersSet())).SetWebsocket(h.Websocket == nil || *h.Websocket).
		SetMaxBodyBytes(int64(min(h.GetMaxBodyBytes(), 1<<62))) //nolint:gosec // G115: bounded above
	if hh := h.GetHostHeader(); hh != "" {
		c.SetHostHeader(hh)
	}
	if h.GetTlsMode() == rpmgrv1.TLSMode_TLS_MODE_CERTIFICATE {
		crt, err := tx.Certificate.Get(ctx, h.GetCertificateId())
		if err != nil {
			return err
		}
		if err := checkCovers(crt, h.GetHostnames()); err != nil {
			return err
		}
		c.SetTLSMode(routehttp.TLSModeCertificate).SetCertificateID(h.GetCertificateId())
	}
	return c.Exec(ctx)
}

// checkCovers refuses a certificate for a route that is not an uploaded one or does not cover
// each of its hostnames, which a gateway would then serve with its default certificate.
func checkCovers(crt *ent.Certificate, hostnames []string) error {
	refuse := func(format string, args ...any) error {
		return withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("apisvc: "+format, args...)), ReasonCertificateNotCovering)
	}
	if crt.Source != certificate.SourceUploaded {
		return refuse("certificate %s is an ACME certificate; TLS_MODE_ACME uses those", crt.ID)
	}
	for _, name := range hostnames {
		n, err := domains.Normalize(name, true)
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
		if !slices.ContainsFunc(crt.Sans, func(san string) bool { return certs.Covers(san, n) }) {
			return refuse("certificate %s does not cover %s", crt.ID, n)
		}
	}
	return nil
}

// checkSpec checks what the store cannot: a spec of a known type, header names and values the
// gateway accepts, and no ACME certificate for a wildcard hostname (R42).
func checkSpec(in *rpmgrv1.Route) error {
	invalid := func(format string, args ...any) error {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: "+format, args...))
	}
	hostnames := append(in.GetHttp().GetHostnames(), in.GetTlsPassthrough().GetHostnames()...)
	switch {
	case in.GetSpec() == nil:
		return invalid("a route needs a spec: http, tcp, udp or tls_passthrough")
	case in.GetTcp() != nil || in.GetUdp() != nil:
		return nil
	case len(hostnames) == 0 || len(hostnames) > maxHostnames:
		// The request's validation sees an update's hostnames only if it names them.
		return invalid("a route needs 1 to %d hostnames", maxHostnames)
	case in.GetHttp() == nil:
		return nil
	}
	h := in.GetHttp()
	for _, hs := range []map[string]string{h.GetRequestHeadersSet(), h.GetResponseHeadersSet()} {
		for name, value := range hs {
			switch {
			case !httpguts.ValidHeaderFieldName(name):
				return invalid("header name %q", name)
			case !httpguts.ValidHeaderFieldValue(value):
				return invalid("the value of header %s is not a valid field value", name)
			case slices.Contains(gateway.ReservedHeaders, textproto.CanonicalMIMEHeaderKey(name)):
				return invalid("header %s is the gateway's own", name)
			}
		}
	}
	if hh := h.GetHostHeader(); hh != "" && hh != "preserve" && !httpguts.ValidHostHeader(hh) {
		return invalid("host header %q", hh)
	}
	switch h.GetTlsMode() {
	case rpmgrv1.TLSMode_TLS_MODE_CERTIFICATE:
		if h.GetCertificateId() == "" {
			return invalid("TLS_MODE_CERTIFICATE needs a certificate_id")
		}
	default:
		if h.GetCertificateId() != "" {
			return invalid("a certificate_id needs TLS_MODE_CERTIFICATE")
		}
		for _, name := range h.GetHostnames() {
			if strings.HasPrefix(name, "*.") {
				return withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
					"apisvc: ACME cannot issue a certificate for the wildcard %s; upload one (TLS_MODE_CERTIFICATE)", name)), ReasonWildcardACME)
			}
		}
	}
	return nil
}

// canonicalHeaders is headers with canonical names, as the gateway expects them.
func canonicalHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		out[textproto.CanonicalMIMEHeaderKey(name)] = value
	}
	return out
}

// routeError gives the route rules' errors their API codes.
func routeError(err error) error {
	if perr := portError(err); perr != nil {
		return perr
	}
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

// routeFields are the fields of a route of type t a client may change: never the type itself.
func routeFields(t route.Type) []string {
	fields := []string{"name", "enabled", "labels", "description", "transport", "policy_ids"}
	switch t {
	case route.TypeHTTP:
		for _, f := range []string{"hostnames", "path_prefix", "tls_mode", "certificate_id", "port80", "hsts_max_age_seconds", "host_header",
			"request_headers_set", "response_headers_set", "websocket", "max_body_bytes"} {
			fields = append(fields, "http."+f)
		}
	case route.TypeTLSPassthrough:
		fields = append(fields, "tls_passthrough.hostnames")
	case route.TypeTCP:
		fields = append(fields, "tcp.port", "tcp.idle_timeout_seconds")
	case route.TypeUDP:
		fields = append(fields, "udp.port", "udp.flow_idle_timeout_seconds")
	}
	return fields
}

// UpdateRoute implements RouteService. A change of the spec replaces the route's settings and
// hostnames in the same transaction, so every rule is checked again, verified domains included.
func (r *Routes) UpdateRoute(ctx context.Context, req *connect.Request[rpmgrv1.UpdateRouteRequest]) (
	*connect.Response[rpmgrv1.UpdateRouteResponse], error) {
	m := req.Msg
	var out *rpmgrv1.Route
	rev, err := store.ConfigTx(ctx, r.DB, func(tx *ent.Tx) ([]string, error) {
		row, err := r.updateRouteTx(ctx, tx, m)
		if err != nil {
			return nil, err
		}
		out, err = routeOf(ctx, tx.Client(), row)
		return []string{row.ID}, err
	})
	if err != nil {
		return nil, routeError(err)
	}
	return connect.NewResponse(&rpmgrv1.UpdateRouteResponse{Route: out, Revision: revisionOf(rev)}), nil
}

// createRouteTx creates a route in tx: the route, its settings, its port and its hostnames.
func (r *Routes) createRouteTx(ctx context.Context, tx *ent.Tx, org string, in *rpmgrv1.Route) (*ent.Route, error) {
	if _, err := tx.GatewayGroup.Get(ctx, in.GetGatewayGroupId()); err != nil {
		return nil, err
	}
	c := tx.Route.Create().SetOrgID(org).SetName(in.GetName()).SetGatewayGroupID(in.GetGatewayGroupId()).
		SetDescription(in.GetDescription()).SetLabels(in.GetLabels()).SetUpdatedBy(api.CallerFrom(ctx).UserID).SetCreatedAt(r.now()).
		SetUpdatedAt(r.now())
	if t, ok := storeRouteTransports[in.GetTransport()]; ok {
		c.SetTransport(t)
	}
	var hostnames []string
	prefix := ""
	switch spec := in.GetSpec().(type) {
	case *rpmgrv1.Route_Http:
		c.SetType(route.TypeHTTP)
		hostnames, prefix = spec.Http.GetHostnames(), spec.Http.GetPathPrefix()
	case *rpmgrv1.Route_TlsPassthrough:
		c.SetType(route.TypeTLSPassthrough)
		hostnames = spec.TlsPassthrough.GetHostnames()
	case *rpmgrv1.Route_Tcp:
		c.SetType(route.TypeTCP)
	case *rpmgrv1.Route_Udp:
		c.SetType(route.TypeUDP)
	}
	row, err := c.Save(ctx)
	if err != nil {
		return nil, err
	}
	if err := createPortRoute(ctx, tx, row, in); err != nil {
		return nil, err
	}
	if h := in.GetHttp(); h != nil {
		if err := createHTTP(ctx, tx, row, h); err != nil {
			return nil, err
		}
	}
	for _, name := range hostnames {
		if _, err := routes.AddHostname(ctx, tx, row.ID, name, prefix); err != nil {
			return nil, err
		}
	}
	return row, setRoutePolicies(ctx, tx, row, in.GetPolicyIds())
}

// setRoutePolicies makes a route apply policies, in order. Each must be a policy of the route's
// org, and one with a basic_auth rule needs an http route.
func setRoutePolicies(ctx context.Context, tx *ent.Tx, row *ent.Route, ids []string) error {
	if _, err := tx.RoutePolicy.Delete().Where(routepolicy.RouteID(row.ID)).Exec(ctx); err != nil {
		return err
	}
	for i, id := range ids {
		if _, err := tx.AccessPolicy.Get(ctx, id); err != nil {
			return err
		}
		if row.Type != route.TypeHTTP {
			n, err := tx.PolicyRule.Query().Where(policyrule.PolicyID(id), policyrule.KindEQ(policyrule.KindBasicAuth)).Count(ctx)
			if err != nil {
				return err
			}
			if n > 0 {
				return withReason(connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
					"apisvc: policy %s has a basic_auth rule, which no client could pass on a %s route", id, row.Type)), ReasonBasicAuthNotHTTP)
			}
		}
		if err := tx.RoutePolicy.Create().SetOrgID(row.OrgID).SetRouteID(row.ID).SetPolicyID(id).SetPosition(i).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// updateRouteTx applies an update of a route in tx.
func (r *Routes) updateRouteTx(ctx context.Context, tx *ent.Tx, m *rpmgrv1.UpdateRouteRequest) (*ent.Route, error) {
	cur, err := tx.Route.Get(ctx, m.GetRoute().GetId())
	if err != nil {
		return nil, err
	}
	was, err := routeOf(ctx, tx.Client(), cur)
	if err != nil {
		return nil, err
	}
	if err := api.CheckEtag(m.GetEtag(), cur.Version, was); err != nil {
		return nil, err
	}
	next := proto.Clone(was).(*rpmgrv1.Route)
	if err := api.ApplyMask(next, m.GetRoute(), m.GetUpdateMask(), routeFields(cur.Type)...); err != nil {
		return nil, err
	}
	if err := checkSpec(next); err != nil {
		return nil, err
	}
	u := tx.Route.UpdateOneID(cur.ID).Where(route.Version(cur.Version)).SetName(next.GetName()).SetEnabled(next.GetEnabled()).
		SetLabels(next.GetLabels()).SetDescription(next.GetDescription()).SetUpdatedAt(r.now()).SetUpdatedBy(api.CallerFrom(ctx).UserID)
	if t, ok := storeRouteTransports[next.GetTransport()]; ok {
		u.SetTransport(t)
	} else {
		u.ClearTransport()
	}
	row, err := u.Save(ctx)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(was.GetPolicyIds(), next.GetPolicyIds()) {
		if err := setRoutePolicies(ctx, tx, row, next.GetPolicyIds()); err != nil {
			return nil, err
		}
	}
	if row.Type == route.TypeTCP || row.Type == route.TypeUDP {
		if err := updatePortRoute(ctx, tx, row, was, next); err != nil {
			return nil, err
		}
	} else if !proto.Equal(specOf(was), specOf(next)) {
		if err := routes.RemoveHostnames(ctx, tx, row.ID); err != nil {
			return nil, err
		}
		hostnames, prefix := next.GetTlsPassthrough().GetHostnames(), ""
		if h := next.GetHttp(); h != nil {
			if _, err := tx.RouteHTTP.Delete().Where(routehttp.RouteID(row.ID)).Exec(ctx); err != nil {
				return nil, err
			}
			if err := createHTTP(ctx, tx, row, h); err != nil {
				return nil, err
			}
			hostnames, prefix = h.GetHostnames(), h.GetPathPrefix()
		}
		for _, name := range hostnames {
			if _, err := routes.AddHostname(ctx, tx, row.ID, name, prefix); err != nil {
				return nil, err
			}
		}
	}
	return row, nil
}

// specOf is a route's spec as a message, for comparing two versions of it.
func specOf(r *rpmgrv1.Route) proto.Message {
	if h := r.GetHttp(); h != nil {
		return h
	}
	return r.GetTlsPassthrough()
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
	st, err := newRouteStatuses(ctx, r.Sys, c, row.OrgID, []*ent.Route{row}, r.now())
	if err != nil {
		return nil, storeError(err)
	}
	out.Status = st.of(row)
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
	q := c.Route.Query().Where(route.OrgID(m.GetOrgId())).Order(ent.Asc(route.FieldID)).Limit(size + 1)
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
	st, err := newRouteStatuses(ctx, r.Sys, c, m.GetOrgId(), rows, r.now())
	if err != nil {
		return nil, storeError(err)
	}
	for _, row := range rows {
		rt, err := routeOf(ctx, c, row)
		if err != nil {
			return nil, storeError(err)
		}
		rt.Status = st.of(row)
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
		Description: row.Description, CreateTime: timestamppb.New(row.CreatedAt), UpdateTime: timestamppb.New(row.UpdatedAt), UpdateUserId: row.UpdatedBy, Etag: etagOf(row.Version)}
	if row.Transport != nil {
		for api, st := range storeRouteTransports {
			if st == *row.Transport {
				out.Transport = api
			}
		}
	}
	targets, err := targetsOf(ctx, c, row.ID)
	if err != nil {
		return nil, err
	}
	out.Targets = targets
	if out.PolicyIds, err = c.RoutePolicy.Query().Where(routepolicy.RouteID(row.ID)).Order(ent.Asc(routepolicy.FieldPosition)).
		Select(routepolicy.FieldPolicyID).Strings(ctx); err != nil {
		return nil, err
	}
	hs, err := c.RouteHostname.Query().Where(routehostname.RouteID(row.ID)).Order(ent.Asc(routehostname.FieldHostname)).All(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(hs))
	for i, h := range hs {
		names[i] = h.Hostname
	}
	switch row.Type {
	case route.TypeTCP, route.TypeUDP:
		if err := setPortSpec(ctx, c, row, out); err != nil {
			return nil, err
		}
	case route.TypeTLSPassthrough:
		out.Spec = &rpmgrv1.Route_TlsPassthrough{TlsPassthrough: &rpmgrv1.TLSPassthroughRouteSpec{Hostnames: names}}
	case route.TypeHTTP:
		h, err := c.RouteHTTP.Query().Where(routehttp.RouteID(row.ID)).Only(ctx)
		if err != nil {
			return nil, err
		}
		spec := &rpmgrv1.HTTPRouteSpec{Hostnames: names, PathPrefix: h.PathPrefix, TlsMode: rpmgrv1.TLSMode_TLS_MODE_ACME,
			Port80: map[routehttp.Port80]rpmgrv1.Port80Mode{routehttp.Port80Redirect: rpmgrv1.Port80Mode_PORT80_MODE_REDIRECT,
				routehttp.Port80Serve: rpmgrv1.Port80Mode_PORT80_MODE_SERVE, routehttp.Port80Off: rpmgrv1.Port80Mode_PORT80_MODE_OFF}[h.Port80],
			HstsMaxAgeSeconds: uint32(h.HstsMaxAgeSeconds), HostHeader: h.HostHeader, RequestHeadersSet: h.RequestHeadersSet, //nolint:gosec // G115: bounded
			ResponseHeadersSet: h.ResponseHeadersSet, Websocket: &h.Websocket, MaxBodyBytes: uint64(h.MaxBodyBytes)} //nolint:gosec // G115: non-negative
		if h.TLSMode == routehttp.TLSModeCertificate {
			spec.TlsMode = rpmgrv1.TLSMode_TLS_MODE_CERTIFICATE
			if h.CertificateID != nil {
				spec.CertificateId = *h.CertificateID
			}
		}
		out.Spec = &rpmgrv1.Route_Http{Http: spec}
	}
	return out, nil
}
