// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package testseed

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/accesspolicy"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/ent/policyrule"
	"github.com/felix-homelab/rpmgr/internal/store/ent/portpool"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
)

// UseKEK lets the seeder store secrets, the keys of uploaded certificates, under the
// controller's KEK.
func (s *Seeder) UseKEK(k secret.KEK) error {
	sealer, err := secret.NewSealer(k)
	if err == nil {
		s.sealer = sealer
	}
	return err
}

// group returns the ID of the seeding organisation's gateway group name.
func (s *Seeder) group(tx *ent.Tx, org, name string) (string, error) {
	g, err := tx.GatewayGroup.Query().Where(gatewaygroup.OrgID(org), gatewaygroup.Name(name)).Only(s.sys)
	if err != nil {
		return "", fmt.Errorf("group %s: %w", name, err)
	}
	return g.ID, nil
}

// target is where a route's connectors deliver it.
type target struct {
	host string
	port int
}

func parseTarget(hostport string) (target, error) {
	host, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return target{}, err
	}
	port, err := strconv.Atoi(p)
	return target{host: host, port: port}, err
}

// newRoute creates a route of typ in group with targets on the named connectors; set adjusts
// each target.
func (s *Seeder) newRoute(tx *ent.Tx, org, name, group, typ, transport string, connectors []string, to target,
	set func(*ent.RouteTargetCreate)) (*ent.Route, error) {
	g, err := s.group(tx, org, group)
	if err != nil {
		return nil, err
	}
	c := tx.Route.Create().SetOrgID(org).SetName(name).SetType(route.Type(typ)).SetGatewayGroupID(g)
	if transport != "" {
		c.SetTransport(route.Transport(transport))
	}
	rt, err := c.Save(s.sys)
	if err != nil {
		return nil, err
	}
	for _, cn := range connectors {
		con, err := tx.Connector.Query().Where(connector.OrgID(org), connector.Name(cn)).Only(s.sys)
		if err != nil {
			return nil, fmt.Errorf("connector %s: %w", cn, err)
		}
		tc := tx.RouteTarget.Create().SetOrgID(org).SetRouteID(rt.ID).SetConnectorID(con.ID).SetKind("address").
			SetHost(to.host).SetPort(to.port)
		if set != nil {
			set(tc)
		}
		if err := tc.Exec(s.sys); err != nil {
			return nil, err
		}
	}
	return rt, nil
}

// AddUDPRoute creates a udp route on its group's port, with a UDP port pool of that one port if
// none covers it; Idle is its flow idle timeout.
func (s *Seeder) AddUDPRoute(r Route) error {
	to, err := parseTarget(r.Target)
	if err != nil {
		return err
	}
	return s.tx(func(tx *ent.Tx, org string) ([]string, error) {
		g, err := s.group(tx, org, r.Group)
		if err != nil {
			return nil, err
		}
		covered, err := tx.PortPool.Query().Where(portpool.GatewayGroupID(g), portpool.ProtocolEQ(portpool.ProtocolUDP),
			portpool.PortFromLTE(r.Port), portpool.PortToGTE(r.Port)).Exist(s.sys)
		if err != nil {
			return nil, err
		}
		if !covered {
			if _, err := routes.AddPool(s.sys, tx, org, g, routes.UDP, r.Port, r.Port); err != nil {
				return nil, err
			}
		}
		alloc, err := routes.Allocate(s.sys, tx, org, g, routes.UDP, r.Port)
		if err != nil {
			return nil, err
		}
		rt, err := s.newRoute(tx, org, r.Name, r.Group, "udp", r.Transport, r.Connectors, to, nil)
		if err != nil {
			return nil, err
		}
		uc := tx.RouteUDP.Create().SetOrgID(org).SetRouteID(rt.ID).SetPortAllocationID(alloc.ID)
		if r.Idle > 0 {
			uc.SetFlowIdleTimeoutSeconds(int(r.Idle / time.Second))
		}
		return []string{rt.ID}, uc.Exec(s.sys)
	})
}

// HTTPRoute is an http route to seed.
type HTTPRoute struct {
	Name, Group string
	Hostnames   []string
	Connectors  []string
	Target      string
	Transport   string
	// Upstream is http, h2c or https; for https, ServerName and CABundle (PEM) verify it.
	Upstream, ServerName string
	CABundle             []byte
	// CertPEM and KeyPEM are the route's certificate, uploaded and named by the route.
	CertPEM, KeyPEM []byte
}

// verified claims the parent domain of each hostname for the seeding organisation, with its
// subdomains, and marks it verified, as domain verification would.
func (s *Seeder) verified(tx *ent.Tx, org string, hostnames []string) error {
	for _, h := range hostnames {
		_, parent, ok := strings.Cut(strings.TrimPrefix(h, "*."), ".")
		if !ok {
			return fmt.Errorf("hostname %s has no parent domain", h)
		}
		d, err := tx.Domain.Query().Where(domain.Fqdn(parent)).Only(s.sys)
		if ent.IsNotFound(err) {
			d, err = domains.Claim(s.sys, tx, org, parent, true)
		}
		if err != nil {
			return err
		}
		if err := tx.Domain.UpdateOne(d).SetStatus(domain.StatusVerified).Exec(s.sys); err != nil {
			return err
		}
	}
	return nil
}

// AddHTTPRoute creates an http route with its hostnames under verified domains and its uploaded
// certificate in certificate mode.
func (s *Seeder) AddHTTPRoute(r HTTPRoute) error {
	if s.sealer == nil {
		return errors.New("testseed: an http route's certificate needs the controller's KEK")
	}
	to, err := parseTarget(r.Target)
	if err != nil {
		return err
	}
	return s.tx(func(tx *ent.Tx, org string) ([]string, error) {
		if err := s.verified(tx, org, r.Hostnames); err != nil {
			return nil, err
		}
		crt, err := certs.Upload(s.sys, tx, s.sealer, org, r.CertPEM, r.KeyPEM, time.Now())
		if err != nil {
			return nil, err
		}
		var bundle string
		if len(r.CABundle) > 0 {
			b, err := tx.CABundle.Create().SetOrgID(org).SetName(r.Name).SetPem(r.CABundle).Save(s.sys)
			if err != nil {
				return nil, err
			}
			bundle = b.ID
		}
		rt, err := s.newRoute(tx, org, r.Name, r.Group, "http", r.Transport, r.Connectors, to, func(c *ent.RouteTargetCreate) {
			c.SetUpstreamProtocol(routetarget.UpstreamProtocol(r.Upstream)).SetTLSServerName(r.ServerName)
			if bundle != "" {
				c.SetCaBundleID(bundle)
			}
		})
		if err != nil {
			return nil, err
		}
		if err := tx.RouteHTTP.Create().SetOrgID(org).SetRouteID(rt.ID).SetTLSMode("certificate").SetCertificateID(crt.ID).
			Exec(s.sys); err != nil {
			return nil, err
		}
		for _, h := range r.Hostnames {
			if _, err := routes.AddHostname(s.sys, tx, rt.ID, h, ""); err != nil {
				return nil, err
			}
		}
		return []string{rt.ID, crt.ID}, nil
	})
}

// AddPassthroughRoute creates a tls_passthrough route with its hostnames under verified domains.
func (s *Seeder) AddPassthroughRoute(name, group string, hostnames, connectors []string, targetAddr, transport string) error {
	to, err := parseTarget(targetAddr)
	if err != nil {
		return err
	}
	return s.tx(func(tx *ent.Tx, org string) ([]string, error) {
		if err := s.verified(tx, org, hostnames); err != nil {
			return nil, err
		}
		rt, err := s.newRoute(tx, org, name, group, "tls_passthrough", transport, connectors, to, nil)
		if err != nil {
			return nil, err
		}
		for _, h := range hostnames {
			if _, err := routes.AddHostname(s.sys, tx, rt.ID, h, ""); err != nil {
				return nil, err
			}
		}
		return []string{rt.ID}, nil
	})
}

// IPRule is an access rule to seed: Allow, or deny, for CIDRs.
type IPRule struct {
	Allow bool
	CIDRs []string
}

// SetAccess makes rules, in order, the IP rules of the route's own access policy, which it
// creates and applies to the route if needed; no rules leave the policy empty.
func (s *Seeder) SetAccess(routeName string, rules []IPRule) error {
	return s.tx(func(tx *ent.Tx, org string) ([]string, error) {
		rt, err := tx.Route.Query().Where(route.OrgID(org), route.Name(routeName)).Only(s.sys)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", routeName, err)
		}
		name := routeName + "-access"
		p, err := tx.AccessPolicy.Query().Where(accesspolicy.OrgID(org), accesspolicy.Name(name)).Only(s.sys)
		if ent.IsNotFound(err) {
			if p, err = tx.AccessPolicy.Create().SetOrgID(org).SetName(name).Save(s.sys); err == nil {
				err = tx.RoutePolicy.Create().SetOrgID(org).SetRouteID(rt.ID).SetPolicyID(p.ID).SetPosition(0).Exec(s.sys)
			}
		}
		if err != nil {
			return nil, err
		}
		if _, err := tx.PolicyRule.Delete().Where(policyrule.PolicyID(p.ID)).Exec(s.sys); err != nil {
			return nil, err
		}
		for i, r := range rules {
			params, err := proto.Marshal(&rpmgrv1.PolicyRuleParams{Params: &rpmgrv1.PolicyRuleParams_Ip{Ip: &rpmgrv1.IPRuleParams{Cidrs: r.CIDRs}}})
			if err != nil {
				return nil, err
			}
			kind := policyrule.KindIPDeny
			if r.Allow {
				kind = policyrule.KindIPAllow
			}
			if err := tx.PolicyRule.Create().SetOrgID(org).SetPolicyID(p.ID).SetPosition(i).SetKind(kind).SetParams(params).
				Exec(s.sys); err != nil {
				return nil, err
			}
		}
		return []string{rt.ID, p.ID}, nil
	})
}
