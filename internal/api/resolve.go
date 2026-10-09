// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/accesspolicy"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cabundle"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portpool"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portquota"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
)

// Resolver returns the org that owns the resource with an ID, or ErrNotFound.
type Resolver func(ctx context.Context, id string) (orgID string, err error)

// ErrNotFound is returned by a Resolver for an ID no resource has.
var ErrNotFound = errors.New("api: no such resource")

type ownerFunc func(ctx context.Context, c *ent.Client, id string) (string, error)

// owners finds the org of each kind of org-owned resource the API names by ID.
var owners = map[string]ownerFunc{
	"ap": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.AccessPolicy.Query().Where(accesspolicy.ID(id)).Select(accesspolicy.FieldOrgID).String(ctx)
	},
	"cab": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.CABundle.Query().Where(cabundle.ID(id)).Select(cabundle.FieldOrgID).String(ctx)
	},
	"con": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.Connector.Query().Where(connector.ID(id)).Select(connector.FieldOrgID).String(ctx)
	},
	"crt": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.Certificate.Query().Where(certificate.ID(id)).Select(certificate.FieldOrgID).String(ctx)
	},
	"dom": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.Domain.Query().Where(domain.ID(id)).Select(domain.FieldOrgID).String(ctx)
	},
	"enr": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.EnrollmentToken.Query().Where(enrollmenttoken.ID(id)).Select(enrollmenttoken.FieldOrgID).String(ctx)
	},
	"gw": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.Gateway.Query().Where(gateway.ID(id)).Select(gateway.FieldOrgID).String(ctx)
	},
	"gwg": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.GatewayGroup.Query().Where(gatewaygroup.ID(id)).Select(gatewaygroup.FieldOrgID).String(ctx)
	},
	"pp": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.PortPool.Query().Where(portpool.ID(id)).Select(portpool.FieldOrgID).String(ctx)
	},
	"pq": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.PortQuota.Query().Where(portquota.ID(id)).Select(portquota.FieldOrgID).String(ctx)
	},
	"pr": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.PolicyRule.Query().Where(policyrule.ID(id)).Select(policyrule.FieldOrgID).String(ctx)
	},
	"rt": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.Route.Query().Where(route.ID(id)).Select(route.FieldOrgID).String(ctx)
	},
	"tg": func(ctx context.Context, c *ent.Client, id string) (string, error) {
		return c.RouteTarget.Query().Where(routetarget.ID(id)).Select(routetarget.FieldOrgID).String(ctx)
	},
}

// StoreResolver resolves resource IDs in the store, under sys, the controller's system scope, as
// the owner of a resource must be found before the caller's org scope exists.
func StoreResolver(db *store.DB, sys context.Context) Resolver {
	return func(_ context.Context, id string) (string, error) {
		prefix, _, _ := strings.Cut(id, "_")
		owner, ok := owners[prefix]
		if !ok || !ids.Valid(prefix, id) {
			return "", ErrNotFound
		}
		org, err := owner(sys, db.ReadClient(), id)
		if ent.IsNotFound(err) {
			return "", ErrNotFound
		}
		return org, err
	}
}

// StoreOperatorsMayEnroll reads an org's setting that gives Operators connectors.write from the
// store, under sys.
func StoreOperatorsMayEnroll(db *store.DB, sys context.Context) func(context.Context, string) (bool, error) {
	return func(_ context.Context, orgID string) (bool, error) {
		s, _, err := settings.Org(sys, db.ReadClient(), orgID)
		if err != nil {
			return false, err
		}
		return s.GetOperatorsMayEnroll(), nil
	}
}
