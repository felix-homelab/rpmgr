// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

// Package testseed writes the configuration end-to-end tests need into a controller's database
// before the public API exists (docs/12-testing-and-quality.md, "Where the cells run"; D60). It
// exists only in the rpmgrtest build, which release builds refuse. It writes as admin commands
// may, next to the running controller, through configuration transactions, so the controller
// pushes the changes as new revisions.
package testseed

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/ent/instance"
	"github.com/felix-homelab/rpmgr/internal/store/ent/org"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portpool"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetcp"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// OrgSlug is the organisation the seeded configuration belongs to.
const OrgSlug = "e2e"

// Seeder writes into one controller database.
type Seeder struct {
	db  *store.DB
	sys context.Context
	// RevLog is the controller's revocation log, which Revoke appends to.
	RevLog string
	sealer *secret.Sealer // set by UseKEK
}

// Open opens the database at dsn, without the controller's lock.
func Open(ctx context.Context, dsn, revLog string) (*Seeder, error) {
	db, err := store.OpenSQLite(ctx, dsn, store.SQLiteOptions{})
	if err != nil {
		return nil, err
	}
	sys, err := authz.System(ctx, "rpmgr-testseed", "end-to-end test seeding", audit.SystemScopes(db))
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Seeder{db: db, sys: sys, RevLog: revLog}, nil
}

// Close closes the database.
func (s *Seeder) Close() error { return s.db.Close() }

// tx runs fn in a configuration transaction in the seeding organisation.
func (s *Seeder) tx(fn func(tx *ent.Tx, org string) ([]string, error)) error {
	_, err := store.ConfigTx(s.sys, s.db, func(tx *ent.Tx) ([]string, error) {
		o, err := tx.Org.Query().Where(org.Slug(OrgSlug)).Only(s.sys)
		if ent.IsNotFound(err) {
			o, err = tx.Org.Create().SetName("End to end").SetSlug(OrgSlug).Save(s.sys)
		}
		if err != nil {
			return nil, err
		}
		ids, err := fn(tx, o.ID)
		return append(ids, o.ID), err
	})
	return err
}

func (s *Seeder) mint(tx *ent.Tx, org string, set func(*ent.EnrollmentTokenCreate)) (string, error) {
	tok, err := token.New(token.Enrollment)
	if err != nil {
		return "", err
	}
	c := tx.EnrollmentToken.Create().SetOrgID(org).SetTokenHash(token.Hash(tok)).SetExpiresAt(time.Now().Add(time.Hour)).
		SetCreatedBy("rpmgr-testseed")
	set(c)
	return tok, c.Exec(s.sys)
}

// Gateway creates the gateway name in group, which it creates if needed, with its tunnel
// endpoints, and returns a token that enrolls it.
func (s *Seeder) Gateway(group, name string, endpoints []string) (string, error) {
	var tok string
	err := s.tx(func(tx *ent.Tx, org string) ([]string, error) {
		g, err := tx.GatewayGroup.Query().Where(gatewaygroup.OrgID(org), gatewaygroup.Name(group)).Only(s.sys)
		if ent.IsNotFound(err) {
			g, err = tx.GatewayGroup.Create().SetOrgID(org).SetName(group).Save(s.sys)
		}
		if err != nil {
			return nil, err
		}
		gw, err := tx.Gateway.Create().SetOrgID(org).SetGatewayGroupID(g.ID).SetName(name).SetTunnelEndpoints(endpoints).Save(s.sys)
		if err != nil {
			return nil, err
		}
		tok, err = s.mint(tx, org, func(c *ent.EnrollmentTokenCreate) { c.SetRole("gateway").SetGatewayID(gw.ID).SetMaxUses(1) })
		return []string{g.ID, gw.ID}, err
	})
	return tok, err
}

// ConnectorToken returns a token that enrolls up to uses connectors.
func (s *Seeder) ConnectorToken(uses int) (string, error) {
	var tok string
	err := s.tx(func(tx *ent.Tx, org string) ([]string, error) {
		var err error
		tok, err = s.mint(tx, org, func(c *ent.EnrollmentTokenCreate) { c.SetRole("connector").SetMaxUses(uses) })
		return nil, err
	})
	return tok, err
}

// Route is a tcp route to seed.
type Route struct {
	Name, Group string
	Port        int
	// Connectors serve the route at Target, host:port; each is a connector's name.
	Connectors []string
	Target     string
	Transport  string // "" leaves the connector's and the instance's
	Idle       time.Duration
}

// AddRoute creates a tcp route on its group's port, with a port pool of that one port if no pool
// covers it.
func (s *Seeder) AddRoute(r Route) error {
	host, portStr, err := net.SplitHostPort(r.Target)
	if err != nil {
		return err
	}
	tport, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	return s.tx(func(tx *ent.Tx, org string) ([]string, error) {
		g, err := tx.GatewayGroup.Query().Where(gatewaygroup.OrgID(org), gatewaygroup.Name(r.Group)).Only(s.sys)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", r.Group, err)
		}
		covered, err := tx.PortPool.Query().Where(portpool.GatewayGroupID(g.ID), portpool.PortFromLTE(r.Port), portpool.PortToGTE(r.Port)).Exist(s.sys)
		if err != nil {
			return nil, err
		}
		if !covered {
			if _, err := routes.AddPool(s.sys, tx, org, g.ID, routes.TCP, r.Port, r.Port); err != nil {
				return nil, err
			}
		}
		alloc, err := routes.Allocate(s.sys, tx, org, g.ID, routes.TCP, r.Port)
		if err != nil {
			return nil, err
		}
		c := tx.Route.Create().SetOrgID(org).SetName(r.Name).SetType("tcp").SetGatewayGroupID(g.ID)
		if r.Transport != "" {
			c.SetTransport(route.Transport(r.Transport))
		}
		rt, err := c.Save(s.sys)
		if err != nil {
			return nil, err
		}
		tc := tx.RouteTCP.Create().SetOrgID(org).SetRouteID(rt.ID).SetPortAllocationID(alloc.ID)
		if r.Idle > 0 {
			tc.SetIdleTimeoutSeconds(int(r.Idle / time.Second))
		}
		if err := tc.Exec(s.sys); err != nil {
			return nil, err
		}
		for _, name := range r.Connectors {
			con, err := tx.Connector.Query().Where(connector.OrgID(org), connector.Name(name)).Only(s.sys)
			if err != nil {
				return nil, fmt.Errorf("connector %s: %w", name, err)
			}
			if err := tx.RouteTarget.Create().SetOrgID(org).SetRouteID(rt.ID).SetConnectorID(con.ID).SetKind("address").
				SetHost(host).SetPort(tport).Exec(s.sys); err != nil {
				return nil, err
			}
		}
		return []string{rt.ID}, nil
	})
}

// UpdateRoute changes a route: its idle timeout if idle > 0, its transport if transport is set,
// and whether it is enabled if enabled is set.
func (s *Seeder) UpdateRoute(name string, idle time.Duration, transport string, enabled *bool) error {
	return s.tx(func(tx *ent.Tx, org string) ([]string, error) {
		rt, err := tx.Route.Query().Where(route.OrgID(org), route.Name(name)).Only(s.sys)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", name, err)
		}
		u := tx.Route.UpdateOne(rt)
		if transport != "" {
			u.SetTransport(route.Transport(transport))
		}
		if enabled != nil {
			u.SetEnabled(*enabled)
		}
		if err := u.Exec(s.sys); err != nil {
			return nil, err
		}
		if idle > 0 {
			if err := tx.RouteTCP.Update().Where(routetcp.RouteID(rt.ID)).SetIdleTimeoutSeconds(int(idle / time.Second)).Exec(s.sys); err != nil {
				return nil, err
			}
		}
		return []string{rt.ID}, nil
	})
}

// Revoke revokes the identity of the connector or gateway called name, as an Admin would: in the
// database, which every controller replica reads within a second, and in the revocation log.
func (s *Seeder) Revoke(kind pki.Kind, name string) error {
	inst, err := s.db.ReadClient().Instance.Query().Where(instance.ID(1)).Only(s.sys)
	if err != nil {
		return err
	}
	var id pki.Identity
	switch kind {
	case pki.KindConnector:
		c, err := s.db.ReadClient().Connector.Query().Where(connector.Name(name)).Only(s.sys)
		if err != nil {
			return err
		}
		id = pki.Identity{TrustDomain: inst.TrustDomain, Org: c.OrgID, Kind: kind, ID: c.ID}
	case pki.KindGateway:
		g, err := s.db.ReadClient().Gateway.Query().Where(gateway.Name(name)).Only(s.sys)
		if err != nil {
			return err
		}
		id = pki.Identity{TrustDomain: inst.TrustDomain, Org: g.OrgID, Kind: kind, ID: g.ID}
	default:
		return errors.New("testseed: revoke a connector or a gateway")
	}
	log, err := revlog.Open(s.RevLog, nil)
	if err != nil {
		return err
	}
	return store.WriteTx(s.sys, s.db, func(tx *ent.Tx) error {
		row, changed, err := pki.RevokeIdentity(s.sys, tx, id, "end-to-end test", time.Now())
		if err != nil || !changed {
			return err
		}
		if _, err := log.Append(revlog.Entry{Kind: revlog.IdentityRevoked, Org: id.Org, Subject: id.String(), Detail: "end-to-end test",
			NotAfter: &row.NotAfter, Actor: "rpmgr-testseed"}); err != nil {
			return err
		}
		_, err = audit.Append(s.sys, tx, audit.Entry{OrgID: id.Org, ActorType: audit.ActorSystem, ActorID: "rpmgr-testseed",
			Action: "identity.revoke", TargetType: string(id.Kind), TargetID: id.ID, Result: audit.Success, Reason: "end-to-end test"})
		return err
	})
}
