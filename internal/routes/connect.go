// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connectauthority"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connectlistener"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portallocation"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
)

// The errors of CONNECT listeners (docs/03-connections.md, "HTTP CONNECT routes", D130).
var (
	ErrConnectModeMismatch = errors.New("routes: the port is a CONNECT listener with another authentication mode, hostname or certificate")
	ErrAuthorityTaken      = errors.New("routes: the authority is a route's of the CONNECT listener already")
	ErrAuthority           = errors.New("routes: a CONNECT authority is a host name of letters, digits, dots, dashes and underscores")
)

// Listener is what a tcp route in http_connect mode asks of its CONNECT listener.
type Listener struct {
	Mode          connectlistener.AuthMode
	Hostname      string // tls_basic
	CertificateID string // tls_basic: an uploaded certificate that covers Hostname
}

var authorityRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$`)

// NormalizeAuthority returns a CONNECT authority in the form the gateway compares: lower case,
// without a trailing dot, or ErrAuthority.
func NormalizeAuthority(a string) (string, error) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
	if !authorityRe.MatchString(n) {
		return "", fmt.Errorf("%w: %q", ErrAuthority, a)
	}
	return n, nil
}

// JoinListener puts tcp route r, in http_connect mode, on a CONNECT listener of its org and
// gateway group with the authorities, in tx, and returns the listener. A named port that is such a
// listener takes the route only if want is the listener's, else ErrConnectModeMismatch; a named
// port that is free becomes a new listener, from the org's pools and within its quota, as a tcp
// route's port would; a port held by a route is ErrPortTaken. Without a port, the route joins the
// org's listener of want in the group, or a new one opens on a random free port.
func JoinListener(ctx context.Context, tx *ent.Tx, r *ent.Route, want Listener, port int, authorities []string) (*ent.ConnectListener, error) {
	l, err := findListener(ctx, tx, r, want, port)
	if err != nil {
		return nil, err
	}
	if l == nil {
		a, err := Allocate(ctx, tx, r.OrgID, r.GatewayGroupID, TCP, port)
		if err != nil {
			return nil, err
		}
		c := tx.ConnectListener.Create().SetOrgID(r.OrgID).SetGatewayGroupID(r.GatewayGroupID).SetPortAllocationID(a.ID).
			SetAuthMode(want.Mode).SetHostname(want.Hostname)
		if want.CertificateID != "" {
			c.SetCertificateID(want.CertificateID)
		}
		if l, err = c.Save(ctx); err != nil {
			return nil, err
		}
	}
	seen := map[string]bool{}
	for _, raw := range authorities {
		a, err := NormalizeAuthority(raw)
		if err != nil {
			return nil, err
		}
		if seen[a] {
			continue
		}
		seen[a] = true
		err = tx.ConnectAuthority.Create().SetOrgID(r.OrgID).SetConnectListenerID(l.ID).SetRouteID(r.ID).SetAuthority(a).Exec(ctx)
		if ent.IsConstraintError(err) {
			return nil, fmt.Errorf("%w: %s", ErrAuthorityTaken, a)
		}
		if err != nil {
			return nil, err
		}
	}
	return l, nil
}

// findListener returns the listener a route joins, or nil for a new one on port.
func findListener(ctx context.Context, tx *ent.Tx, r *ent.Route, want Listener, port int) (*ent.ConnectListener, error) {
	if port == 0 {
		l, err := tx.ConnectListener.Query().Where(connectlistener.GatewayGroupID(r.GatewayGroupID), connectlistener.AuthModeEQ(want.Mode),
			connectlistener.Hostname(want.Hostname)).Order(ent.Asc(connectlistener.FieldID)).All(ctx)
		if err != nil {
			return nil, err
		}
		for _, x := range l {
			if same(x, want) {
				return x, nil
			}
		}
		return nil, nil
	}
	a, err := tx.PortAllocation.Query().Where(portallocation.GatewayGroupID(r.GatewayGroupID), portallocation.ProtocolEQ(portallocation.ProtocolTCP),
		portallocation.Port(port)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil // a new listener; Allocate checks the pools, the quota and the group
	}
	if err != nil {
		return nil, err
	}
	l, err := tx.ConnectListener.Query().Where(connectlistener.PortAllocationID(a.ID)).Only(ctx)
	switch {
	case ent.IsNotFound(err): // a tcp or tcp_udp route's port, or another org's: the org scope hides its listener
		return nil, holder(ctx, tx, r.GatewayGroupID, portallocation.ProtocolTCP, port)
	case err != nil:
		return nil, err
	case !same(l, want):
		return nil, ErrConnectModeMismatch
	}
	return l, nil
}

func same(l *ent.ConnectListener, want Listener) bool {
	cert := ""
	if l.CertificateID != nil {
		cert = *l.CertificateID
	}
	return l.AuthMode == want.Mode && l.Hostname == want.Hostname && cert == want.CertificateID
}

// LeaveListener takes tcp route routeID off its CONNECT listener, in tx: its authorities go, and a
// listener left without routes closes and frees its port.
func LeaveListener(ctx context.Context, tx *ent.Tx, routeID string) error {
	t, err := tx.RouteTCP.Query().Where(routetcp.RouteID(routeID)).Only(ctx)
	if ent.IsNotFound(err) || err == nil && t.ConnectListenerID == nil {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := tx.ConnectAuthority.Delete().Where(connectauthority.RouteID(routeID)).Exec(ctx); err != nil {
		return err
	}
	if err := tx.RouteTCP.UpdateOne(t).ClearConnectListenerID().Exec(ctx); err != nil {
		return err
	}
	others, err := tx.RouteTCP.Query().Where(routetcp.ConnectListenerID(*t.ConnectListenerID)).Exist(ctx)
	if err != nil || others {
		return err
	}
	l, err := tx.ConnectListener.Get(ctx, *t.ConnectListenerID)
	if err != nil {
		return err
	}
	if err := tx.ConnectListener.DeleteOne(l).Exec(ctx); err != nil {
		return err
	}
	return Release(ctx, tx, l.PortAllocationID)
}

// BasicAuthAllowed reports whether basic auth applies to route r: an http route, or a tcp route on
// a CONNECT listener of a basic mode.
func BasicAuthAllowed(ctx context.Context, tx *ent.Tx, r *ent.Route) (bool, error) {
	switch r.Type {
	case route.TypeHTTP:
		return true, nil
	case route.TypeTCP:
		return tx.RouteTCP.Query().Where(routetcp.RouteID(r.ID), routetcp.HasListenerWith(connectlistener.AuthModeIn(
			connectlistener.AuthModeTLSBasic, connectlistener.AuthModePlainBasic))).Exist(ctx)
	}
	return false, nil
}
