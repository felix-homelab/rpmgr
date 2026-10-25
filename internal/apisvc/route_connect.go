// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connectauthority"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connectlistener"
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
)

// The reasons of refused CONNECT routes (docs/03-connections.md, "HTTP CONNECT routes", D130).
const (
	// ReasonConnectModeMismatch: the named port is a CONNECT listener with another mode or
	// hostname.
	ReasonConnectModeMismatch = "CONNECT_MODE_MISMATCH"
	// ReasonListenerModeChange: a tcp route's listener mode cannot change.
	ReasonListenerModeChange = "LISTENER_MODE_CHANGE"
)

// plainBasicWarning is the warning of every write and preview of a route whose CONNECT listener
// takes passwords in the clear (D130).
const plainBasicWarning = "the route's CONNECT listener takes proxy passwords in the clear: anyone on the network path " +
	"between client and gateway can read and use them; prefer CONNECT_AUTH_MODE_TLS_BASIC"

// noUsersWarning is the warning of a route on a CONNECT listener of a basic mode that applies no
// basic-auth rule: no client passes.
const noUsersWarning = "the route's CONNECT listener asks for proxy credentials, and the route applies no access policy " +
	"with a basic-auth rule, so every client gets 407"

// connectWarnings are the warnings of a route as it is now, in tx.
func connectWarnings(ctx context.Context, tx *ent.Tx, r *rpmgrv1.Route) ([]string, error) {
	c := r.GetTcp().GetConnect()
	if r.GetTcp().GetListenerMode() != rpmgrv1.ListenerMode_LISTENER_MODE_HTTP_CONNECT {
		return nil, nil
	}
	var out []string
	if c.GetAuthMode() == rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_PLAIN_BASIC {
		out = append(out, plainBasicWarning)
	}
	if c.GetAuthMode() == rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_PLAIN_BASIC || c.GetAuthMode() == rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_TLS_BASIC {
		n, err := tx.PolicyRule.Query().Where(policyrule.PolicyIDIn(r.GetPolicyIds()...), policyrule.KindEQ(policyrule.KindBasicAuth)).Count(ctx)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			out = append(out, noUsersWarning)
		}
	}
	return out, nil
}

// checkConnect checks what the request's rules cannot of a tcp route's listener mode and CONNECT
// spec: a spec exactly with http_connect, and a hostname and certificate exactly with tls_basic.
func checkConnect(t *rpmgrv1.TCPRouteSpec) error {
	invalid := func(format string, args ...any) error {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("apisvc: "+format, args...))
	}
	c := t.GetConnect()
	switch {
	case t.GetListenerMode() != rpmgrv1.ListenerMode_LISTENER_MODE_HTTP_CONNECT:
		if c != nil {
			return invalid("a CONNECT spec needs LISTENER_MODE_HTTP_CONNECT")
		}
		return nil
	case c == nil:
		return invalid("LISTENER_MODE_HTTP_CONNECT needs a CONNECT spec with authorities")
	case c.GetAuthMode() == rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_TLS_BASIC && (c.GetHostname() == "" || c.GetCertificateId() == ""):
		return invalid("CONNECT_AUTH_MODE_TLS_BASIC needs the listener's hostname and an uploaded certificate that covers it")
	case c.GetAuthMode() != rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_TLS_BASIC && (c.GetHostname() != "" || c.GetCertificateId() != ""):
		return invalid("a CONNECT hostname and certificate go with CONNECT_AUTH_MODE_TLS_BASIC only")
	}
	for _, a := range c.GetAuthorities() {
		if _, err := routes.NormalizeAuthority(a); err != nil {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	return nil
}

// listenerOf is the CONNECT listener a route's spec asks for, with its TLS hostname checked
// against the org's verified domains and its certificate against the hostname.
func listenerOf(ctx context.Context, tx *ent.Tx, org string, c *rpmgrv1.ConnectSpec) (routes.Listener, error) {
	l := routes.Listener{Mode: map[rpmgrv1.ConnectAuthMode]connectlistener.AuthMode{
		rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_UNSPECIFIED: connectlistener.AuthModeNone,
		rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_NONE:        connectlistener.AuthModeNone,
		rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_TLS_BASIC:   connectlistener.AuthModeTLSBasic,
		rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_PLAIN_BASIC: connectlistener.AuthModePlainBasic}[c.GetAuthMode()]}
	if l.Mode != connectlistener.AuthModeTLSBasic {
		return l, nil
	}
	name, err := domains.Normalize(c.GetHostname(), false)
	if err != nil {
		return l, err
	}
	d, err := domains.Covering(ctx, tx, org, name)
	if err != nil {
		return l, err
	}
	crt, err := tx.Certificate.Get(ctx, c.GetCertificateId())
	if err != nil {
		return l, err
	}
	if err := checkCovers(crt, []string{name}); err != nil {
		return l, err
	}
	l.Hostname, l.DomainID, l.CertificateID = name, d.ID, crt.ID
	return l, nil
}

// createConnectRoute stores a tcp route in http_connect mode on its CONNECT listener.
func createConnectRoute(ctx context.Context, tx *ent.Tx, row *ent.Route, t *rpmgrv1.TCPRouteSpec) error {
	if err := tx.RouteTCP.Create().SetOrgID(row.OrgID).SetRouteID(row.ID).SetListenerMode(routetcp.ListenerModeHTTPConnect).
		SetIdleTimeoutSeconds(idleTimeout(t.IdleTimeoutSeconds)).Exec(ctx); err != nil {
		return err
	}
	return joinListener(ctx, tx, row, t, t.GetPort())
}

// joinListener puts a route on the listener its spec asks for, on port or, with 0, on the org's
// listener of the mode or a new one.
func joinListener(ctx context.Context, tx *ent.Tx, row *ent.Route, t *rpmgrv1.TCPRouteSpec, port uint32) error {
	want, err := listenerOf(ctx, tx, row.OrgID, t.GetConnect())
	if err != nil {
		return err
	}
	l, err := routes.JoinListener(ctx, tx, row, want, int(port), t.GetConnect().GetAuthorities())
	if err != nil {
		return err
	}
	return tx.RouteTCP.Update().Where(routetcp.RouteID(row.ID)).SetConnectListenerID(l.ID).Exec(ctx)
}

// updateConnectRoute changes a tcp route in http_connect mode. Another port, mode or hostname
// moves it off its listener and onto the one asked for; its old listener closes if it was the
// last route there. A changed mode or hostname without a changed port moves it to the org's
// listener of the new mode, or a new one, as the old port's listener keeps its mode. New
// authorities or a new certificate keep it on its listener: a route's certificate becomes the
// listener's for all its routes, so a certificate is replaced without moving the port. An update
// that leaves the mode unset while the route's is not none is refused rather than read as none,
// which would drop the route's proxy credentials.
func updateConnectRoute(ctx context.Context, tx *ent.Tx, row *ent.Route, was, next *rpmgrv1.TCPRouteSpec) error {
	if next.GetConnect().GetAuthMode() == rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_UNSPECIFIED &&
		was.GetConnect().GetAuthMode() != rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_NONE {
		return connect.NewError(connect.CodeInvalidArgument, errors.New(
			"apisvc: name the CONNECT auth_mode in an update; not set would be none and drop the route's proxy credentials"))
	}
	if err := tx.RouteTCP.Update().Where(routetcp.RouteID(row.ID)).SetIdleTimeoutSeconds(idleTimeout(next.IdleTimeoutSeconds)).
		Exec(ctx); err != nil {
		return err
	}
	if was.GetPort() == next.GetPort() && proto.Equal(was.GetConnect(), next.GetConnect()) {
		return nil
	}
	if next.GetPort() == was.GetPort() && !connectModeChanged(was.GetConnect(), next.GetConnect()) {
		// The same listener: its authorities and certificate change in place.
		t, err := tx.RouteTCP.Query().Where(routetcp.RouteID(row.ID)).WithListener().Only(ctx)
		if err != nil {
			return err
		}
		want, err := listenerOf(ctx, tx, row.OrgID, next.GetConnect())
		if err != nil {
			return err
		}
		if err := routes.SetListenerCertificate(ctx, tx, t.Edges.Listener, want.CertificateID); err != nil {
			return err
		}
		return routes.SetAuthorities(ctx, tx, row, t.Edges.Listener.ID, next.GetConnect().GetAuthorities())
	}
	if err := routes.LeaveListener(ctx, tx, row.ID); err != nil {
		return err
	}
	port := next.GetPort()
	if port == was.GetPort() {
		port = 0
	}
	return joinListener(ctx, tx, row, next, port)
}

// connectModeChanged reports whether a route asks for another listener mode or hostname; not
// set is none.
func connectModeChanged(a, b *rpmgrv1.ConnectSpec) bool {
	mode := func(c *rpmgrv1.ConnectSpec) rpmgrv1.ConnectAuthMode {
		if c.GetAuthMode() == rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_UNSPECIFIED {
			return rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_NONE
		}
		return c.GetAuthMode()
	}
	return mode(a) != mode(b) || a.GetHostname() != b.GetHostname()
}

// setConnectSpec sets out's spec to a tcp route's in http_connect mode.
func setConnectSpec(ctx context.Context, c *ent.Client, t *ent.RouteTCP, out *rpmgrv1.Route) error {
	idle := uint32(t.IdleTimeoutSeconds) //nolint:gosec // G115: non-negative, bounded by the API
	spec := &rpmgrv1.TCPRouteSpec{IdleTimeoutSeconds: &idle, ListenerMode: rpmgrv1.ListenerMode_LISTENER_MODE_HTTP_CONNECT,
		Connect: &rpmgrv1.ConnectSpec{}}
	out.Spec = &rpmgrv1.Route_Tcp{Tcp: spec}
	if t.ConnectListenerID == nil {
		return nil
	}
	l, err := c.ConnectListener.Query().Where(connectlistener.ID(*t.ConnectListenerID)).WithPort().Only(ctx)
	if err != nil {
		return err
	}
	spec.Port = uint32(l.Edges.Port.Port) //nolint:gosec // G115: a port
	spec.Connect.AuthMode = map[connectlistener.AuthMode]rpmgrv1.ConnectAuthMode{
		connectlistener.AuthModeNone:       rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_NONE,
		connectlistener.AuthModeTLSBasic:   rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_TLS_BASIC,
		connectlistener.AuthModePlainBasic: rpmgrv1.ConnectAuthMode_CONNECT_AUTH_MODE_PLAIN_BASIC}[l.AuthMode]
	spec.Connect.Hostname = l.Hostname
	if l.CertificateID != nil {
		spec.Connect.CertificateId = *l.CertificateID
	}
	spec.Connect.Authorities, err = c.ConnectAuthority.Query().Where(connectauthority.RouteID(t.RouteID)).
		Order(ent.Asc(connectauthority.FieldAuthority)).Select(connectauthority.FieldAuthority).Strings(ctx)
	return err
}

// connectError gives the CONNECT rules' errors their API codes; it returns nil for other errors.
func connectError(err error) error {
	switch {
	case errors.Is(err, routes.ErrConnectModeMismatch):
		return withReason(connect.NewError(connect.CodeFailedPrecondition, err), ReasonConnectModeMismatch)
	case errors.Is(err, routes.ErrAuthorityTaken):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, routes.ErrAuthority):
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return nil
}
