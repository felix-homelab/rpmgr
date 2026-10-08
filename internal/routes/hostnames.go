// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
)

// Errors of the hostname functions.
var (
	ErrHostnameTaken = errors.New("routes: the hostname is served by another route of the gateway group")
	ErrNoHostnames   = errors.New("routes: only http and tls_passthrough routes have hostnames")
	ErrPathPrefix    = errors.New("routes: a path prefix starts with / and only http routes have one")
)

// AddHostname adds a hostname, and for an http route a path prefix, to a route. The hostname must
// fall under a verified domain of the route's org. Within the route's gateway group a hostname is
// either one tls_passthrough route or any number of http routes with distinct path prefixes, so the
// gateway's SNI decision is never ambiguous (docs/06-data-model.md, "Routes"). It must run in a
// configuration transaction, which serialises the check with every other configuration write.
func AddHostname(ctx context.Context, tx *ent.Tx, routeID, hostname, pathPrefix string) (*ent.RouteHostname, error) {
	r, err := tx.Route.Get(ctx, routeID)
	if err != nil {
		return nil, err
	}
	var rtype routehostname.RouteType
	switch r.Type {
	case route.TypeHTTP:
		rtype = routehostname.RouteTypeHTTP
		if pathPrefix != "" && !strings.HasPrefix(pathPrefix, "/") {
			return nil, ErrPathPrefix
		}
	case route.TypeTLSPassthrough:
		rtype = routehostname.RouteTypeTLSPassthrough
		if pathPrefix != "" {
			return nil, ErrPathPrefix
		}
	default:
		return nil, ErrNoHostnames
	}
	name, err := domains.Normalize(hostname, true)
	if err != nil {
		return nil, err
	}
	d, err := domains.Covering(ctx, tx, r.OrgID, name)
	if err != nil {
		return nil, err
	}
	others, err := tx.RouteHostname.Query().Where(routehostname.GatewayGroupID(r.GatewayGroupID), routehostname.Hostname(name)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, o := range others {
		if rtype == routehostname.RouteTypeTLSPassthrough || o.RouteType == routehostname.RouteTypeTLSPassthrough {
			return nil, fmt.Errorf("%w: %s (route %s)", ErrHostnameTaken, name, o.RouteID)
		}
	}
	h, err := tx.RouteHostname.Create().SetOrgID(r.OrgID).SetRouteID(r.ID).SetGatewayGroupID(r.GatewayGroupID).SetRouteType(rtype).
		SetHostname(name).SetPathPrefix(pathPrefix).SetDomainID(d.ID).Save(ctx)
	if store.IsUniqueViolation(err) {
		return nil, fmt.Errorf("%w: %s%s", ErrHostnameTaken, name, pathPrefix)
	}
	return h, err
}

// RemoveHostnames removes every hostname of a route.
func RemoveHostnames(ctx context.Context, tx *ent.Tx, routeID string) error {
	_, err := tx.RouteHostname.Delete().Where(routehostname.RouteID(routeID)).Exec(ctx)
	return err
}
