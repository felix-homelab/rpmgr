// SPDX-License-Identifier: Apache-2.0

package allinone

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/revokedidentity"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// ConnectorName is the host name all-in-one's own connector enrolls with, which becomes its name.
const ConnectorName = "local"

// tokenTTL bounds the tokens all-in-one makes for its own agents, which it redeems at once.
const tokenTTL = 10 * time.Minute

// ownToken saves c, a single-use token for one of all-in-one's own agents in org, with its audit
// entry. It is built in, so the API neither lists nor revokes it (ADR-0019). why, if set, says why
// the agent enrolls again.
func ownToken(ctx context.Context, tx *ent.Tx, c *ent.EnrollmentTokenCreate, org, actor, role, why string) (string, error) {
	tok, err := token.New(token.Enrollment)
	if err != nil {
		return "", err
	}
	row, err := c.SetOrgID(org).SetTokenHash(token.Hash(tok)).SetMaxUses(1).SetExpiresAt(time.Now().Add(tokenTTL)).
		SetCreatedBy(actor).SetBuiltIn(true).Save(ctx)
	if err != nil {
		return "", err
	}
	reason := "all-in-one's own " + role
	if why != "" {
		reason += ": " + why
	}
	_, err = audit.Append(ctx, tx, audit.Entry{OrgID: org, ActorType: audit.ActorSystem, ActorID: actor, Action: "enrollment_token.create",
		TargetType: "enrollment_token", TargetID: row.ID, Result: audit.Success, Reason: reason})
	return tok, err
}

// connectorToken adds to tx a single-use token for all-in-one's own connector in org: bound to
// the built-in connector id for a new identity, or, without one, a token that enrolls a new
// built-in connector.
func connectorToken(ctx context.Context, tx *ent.Tx, org, id, actor, why string) (string, error) {
	c := tx.EnrollmentToken.Create().SetRole(enrollmenttoken.RoleConnector)
	if id != "" {
		c.SetConnectorID(id)
	}
	return ownToken(ctx, tx, c, org, actor, "connector", why)
}

// gatewayToken adds to tx a single-use token bound to all-in-one's own gateway gw, for a new
// identity of it. Only all-in-one makes one: the API refuses (enroll.ErrBuiltIn).
func gatewayToken(ctx context.Context, tx *ent.Tx, gw *ent.Gateway, actor, why string) (string, error) {
	c := tx.EnrollmentToken.Create().SetRole(enrollmenttoken.RoleGateway).SetGatewayID(gw.ID).SetGatewayGroupID(gw.GatewayGroupID)
	return ownToken(ctx, tx, c, gw.OrgID, actor, "gateway", why)
}

// builtIn is one of all-in-one's own agents.
type builtIn struct {
	role, dir, host string // host is the host name it enrolls with
	leaf            *x509.Certificate
	chain           []*x509.Certificate // the intermediates that came with leaf
	// why, once prepare has run, says why it enrolls again, and token enrolls it; both are "" when
	// it runs with the identity it has.
	why, token string
}

// local is what Run needs to know of its own agents.
type local struct {
	gateway, connector builtIn
	gatewayID          string            // the built-in gateway's
	root               *x509.Certificate // the root an enrollment trusts
	// names are the gateway group's public hostnames.
	names []string
}

func newLocal(cfg config.AllInOne) local {
	return local{gateway: builtIn{role: "gateway", dir: cfg.Gateway().IdentityDir, host: "all-in-one"},
		connector: builtIn{role: "connector", dir: cfg.Connector().IdentityDir, host: ConnectorName}}
}

// readLocal reads the agents' identities. One that is missing is enrolled once the controller
// runs; one that cannot be read stops the start.
func readLocal(cfg config.AllInOne) (local, error) {
	l := newLocal(cfg)
	for _, a := range []*builtIn{&l.gateway, &l.connector} {
		if _, err := agent.ReadIdentity(a.dir); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		id, err := agent.Load(a.dir)
		if err != nil {
			return local{}, fmt.Errorf("allinone: the %s's identity; delete %s to enroll it again: %w", a.role, a.dir, err)
		}
		a.leaf = id.Certificate.Leaf
		for _, der := range id.Certificate.Certificate[1:] {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return local{}, fmt.Errorf("allinone: the %s's identity; delete %s to enroll it again: %w", a.role, a.dir, err)
			}
			a.chain = append(a.chain, c)
		}
	}
	return l, nil
}

// claimedGateway returns the ID of the gateway the gateway's identity names, or "": only a
// certificate that chains to this database's active root and names its trust domain names one. An
// identity file proves nothing by itself: agent.Load checks no chain, so a certificate planted there,
// or one of another installation, names no gateway and is never adopted (builtInGateway). The
// certificate is checked as of its own start of validity, so an expired one still names its gateway.
func (a *builtIn) claimedGateway(ctx context.Context, c *ent.Client) (string, error) {
	if a.leaf == nil || len(a.leaf.URIs) != 1 {
		return "", nil
	}
	ca, err := c.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).Only(ctx)
	if err != nil {
		return "", err
	}
	root, err := x509.ParseCertificate(ca.Certificate)
	if err != nil {
		return "", err
	}
	td, err := pki.TrustDomainOf(root)
	if err != nil {
		return "", err
	}
	id, err := pki.ParseSPIFFE(a.leaf.URIs[0], td)
	if err != nil || id.Kind != pki.KindGateway {
		return "", nil //nolint:nilerr // another trust domain or kind names no gateway of this database
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, c := range a.chain {
		inter.AddCert(c)
	}
	if _, err := a.leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: a.leaf.NotBefore,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return "", nil //nolint:nilerr // not issued by this database's CA: foreign, never adopted
	}
	return id.ID, nil
}

// unusable says why the agent must enroll again, or "" if it runs with the identity it has, which
// must name want, the built-in gateway or connector this database holds (an ID of "" names none):
// it has no identity, or one that names another agent, as a copy from another installation, or the
// controller cannot renew its certificate, as after a restore of a backup older than the
// certificate, or the certificate expired longer ago than Reauth's grace period. An identity that
// names want but is revoked is an error: prepare has replaced such an agent by then (replaceRevoked).
func (a *builtIn) unusable(ctx context.Context, c *ent.Client, td string, want pki.Identity, now time.Time, grace time.Duration) (string, error) {
	if a.leaf == nil {
		return "its identity is missing", nil
	}
	if len(a.leaf.URIs) != 1 {
		return "its identity names another agent", nil
	}
	if id, err := pki.ParseSPIFFE(a.leaf.URIs[0], td); err != nil || id.Kind != want.Kind || id.Org != want.Org || id.ID != want.ID {
		return "its identity names another agent", nil
	}
	switch err := pki.CheckRenewable(ctx, c, a.leaf); {
	case errors.Is(err, pki.ErrNotIssued), errors.Is(err, pki.ErrCertRevoked), errors.Is(err, pki.ErrSuperseded):
		return "its certificate cannot be renewed: " + err.Error(), nil
	case errors.Is(err, pki.ErrIdentityRevoked):
		return "", fmt.Errorf("allinone: the %s's identity %s is revoked, and enrolling again as the same %s cannot lift that", a.role, want.ID, a.role)
	case err != nil:
		return "", err
	}
	if now.After(a.leaf.NotAfter.Add(grace)) {
		return "its certificate expired at " + a.leaf.NotAfter.UTC().Format(time.RFC3339), nil
	}
	return "", nil
}

// enroll enrolls the agent with a.token through dial, the in-process controller, trusting root;
// replace replaces an identity it has.
func (a *builtIn) enroll(ctx context.Context, publicURL string, root *x509.Certificate, dial func(context.Context, string) (net.Conn, error),
	now func() time.Time, replace bool) error {
	_, err := agent.Enroll(ctx, agent.EnrollOptions{Controller: publicURL, Pin: pki.RootPin(root), Token: a.token, IdentityDir: a.dir,
		Replace: replace, Bundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), Dial: dial,
		Host: &agentv1.HostFacts{Hostname: a.host}, Now: now})
	if err != nil {
		return fmt.Errorf("allinone: enroll the %s: %w", a.role, err)
	}
	return nil
}

// prepare runs once the controller has migrated the database, which it may write beside the
// controller. It finds the built-in gateway: the one marked built in, or, on an installation
// initialised before ADR-0019, which marks none, the one the gateway's identity names if this
// database's CA issued it (claimedGateway), which it marks built in. It reads the group's public hostnames and makes the token of each agent that
// must enroll again (unusable, at now): the gateway's bound to it, and the connector's bound to the
// org's built-in connector if there is one, so that each keeps its ID, routes and name, or else one
// that creates the connector. An agent whose identity is revoked as a whole is replaced first
// (replaceRevoked). The enrollment revokes, by serial, the certificates the database records for
// the identity it replaces; one it does not record, as one issued after a restored backup, stays
// valid until it expires, as any agent's does.
func (l *local) prepare(ctx context.Context, cfg config.AllInOne, now time.Time) error {
	db, err := store.OpenSQLite(ctx, cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	const actor = "all-in-one"
	sys, err := authz.System(ctx, actor, "rpmgr all-in-one: its own agents", audit.SystemScopes(db))
	if err != nil {
		return err
	}
	if err := l.replaceRevoked(sys, db, actor, now); err != nil {
		return err
	}
	// Neither the built-in flag nor a token is configuration that agents get: no revision.
	return store.WriteTx(sys, db, func(tx *ent.Tx) error {
		row, err := builtInGateway(sys, tx.Client(), &l.gateway)
		if err != nil {
			return err
		}
		if !row.BuiltIn {
			if err := tx.Gateway.UpdateOne(row).SetBuiltIn(true).Exec(sys); err != nil {
				return err
			}
		}
		l.gatewayID = row.ID
		group, err := tx.GatewayGroup.Get(sys, row.GatewayGroupID)
		if err != nil {
			return err
		}
		l.names = group.PublicHostnames
		ca, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).Only(sys)
		if err != nil {
			return err
		}
		if l.root, err = x509.ParseCertificate(ca.Certificate); err != nil {
			return err
		}
		td, err := pki.TrustDomainOf(l.root)
		if err != nil {
			return err
		}
		conID := ""
		if con, err := tx.Connector.Query().Where(connector.OrgID(row.OrgID), connector.BuiltIn(true), connector.DecommissionedAtIsNil()).
			First(sys); err == nil {
			conID = con.ID
		} else if !ent.IsNotFound(err) {
			return err
		}
		inst, _, err := settings.Instance(sys, tx.Client())
		if err != nil {
			return err
		}
		grace := inst.GetExpiredCertificateGrace().AsDuration()
		for _, c := range []struct {
			a    *builtIn
			want pki.Identity
		}{
			{&l.gateway, pki.Identity{TrustDomain: td, Org: row.OrgID, Kind: pki.KindGateway, ID: row.ID}},
			{&l.connector, pki.Identity{TrustDomain: td, Org: row.OrgID, Kind: pki.KindConnector, ID: conID}},
		} {
			if c.a.why != "" { // replaced: it enrolls as the new agent
				continue
			}
			if c.a.why, err = c.a.unusable(sys, tx.Client(), td, c.want, now, grace); err != nil {
				return err
			}
		}
		if l.gateway.why != "" {
			if l.gateway.token, err = gatewayToken(sys, tx, row, actor, l.gateway.why); err != nil {
				return err
			}
		}
		if l.connector.why != "" {
			l.connector.token, err = connectorToken(sys, tx, row.OrgID, conID, actor, l.connector.why)
		}
		return err
	})
}

// builtInGateway returns the gateway marked built in while it is in service, or, where none is
// marked, as on an installation initialised before ADR-0019, the gateway that gw's identity names,
// while it is in service, if that identity was issued by this database's CA (claimedGateway).
func builtInGateway(ctx context.Context, c *ent.Client, gw *builtIn) (*ent.Gateway, error) {
	row, err := c.Gateway.Query().Where(gateway.BuiltIn(true), gateway.DecommissionedAtIsNil()).Only(ctx)
	if err == nil || !ent.IsNotFound(err) {
		return row, err
	}
	if marked, err := c.Gateway.Query().Where(gateway.BuiltIn(true)).Exist(ctx); err != nil || marked {
		return nil, errors.Join(err, errIf(marked, errNoGateway))
	}
	id, err := gw.claimedGateway(ctx, c)
	if err != nil {
		return nil, err
	}
	if id != "" {
		row, err := c.Gateway.Get(ctx, id)
		switch {
		case err == nil && row.DecommissionedAt == nil:
			return row, nil
		case err != nil && !ent.IsNotFound(err):
			return nil, err
		}
	}
	return nil, errNoGateway
}

// errNoGateway stops the start of a database without a built-in gateway in service.
var errNoGateway = errors.New("allinone: the database has no built-in gateway in service; restore a backup that has one")

func errIf(cond bool, err error) error {
	if cond {
		return err
	}
	return nil
}

// awaitingKey stands for the key of a connector replaceRevoked creates, until its enrollment, bound
// to it, records the key the connector holds.
const awaitingKey = "awaiting-enrollment"

// replaceRevoked replaces each built-in agent whose identity is revoked as a whole by a new one: a
// revocation stays, so enrolling again under the same ID cannot lift it. A restore leaves such an
// agent when its revocation log revokes one the backup still has in service. In one configuration
// transaction, so that agents learn of it, the old agent is decommissioned, its identity staying
// revoked, and the new one takes its place: a gateway the old one's group, name, tunnel endpoints
// and switch, with the lowest free slot; a connector the old one's name, labels, transport, switch
// and route targets, so that no route changes. Both are audited, and why of a replaced agent says
// so; prepare then makes its token, bound to the new agent. A revoked identity is never lifted, and
// no identity other than the database's built-in agents' is ever looked at.
func (l *local) replaceRevoked(ctx context.Context, db *store.DB, actor string, now time.Time) error {
	gw, con, err := revokedBuiltIns(ctx, db.Client(), &l.gateway)
	if err != nil || (gw == nil && con == nil) {
		return err
	}
	org := ""
	if gw != nil {
		org = gw.OrgID
	} else {
		org = con.OrgID
	}
	_, err = store.ConfigTx(store.RevisionOrg(ctx, org), db, func(tx *ent.Tx) ([]string, error) {
		gw, con, err := revokedBuiltIns(ctx, tx.Client(), &l.gateway)
		if err != nil {
			return nil, err
		}
		var changed []string
		if gw != nil {
			row, err := replaceGateway(ctx, tx, gw, actor, now)
			if err != nil {
				return nil, err
			}
			l.gateway.why = "the identity of gateway " + gw.ID + " is revoked; it is replaced by gateway " + row.ID
			changed = append(changed, gw.ID, row.ID)
		}
		if con != nil {
			id, routes, err := replaceConnector(ctx, tx, con, actor, now)
			if err != nil {
				return nil, err
			}
			l.connector.why = "the identity of connector " + con.ID + " is revoked; it is replaced by connector " + id
			changed = append(append(changed, con.ID, id), routes...)
		}
		return changed, nil
	})
	return err
}

// revokedBuiltIns returns the built-in gateway and connector in service whose identities are
// revoked as a whole, each nil if not. a is the built-in gateway's identity (builtInGateway).
func revokedBuiltIns(ctx context.Context, c *ent.Client, a *builtIn) (*ent.Gateway, *ent.Connector, error) {
	gw, err := builtInGateway(ctx, c, a)
	if err != nil {
		return nil, nil, err
	}
	con, err := c.Connector.Query().Where(connector.OrgID(gw.OrgID), connector.BuiltIn(true), connector.DecommissionedAtIsNil()).First(ctx)
	if ent.IsNotFound(err) {
		con, err = nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if revoked, err := identityRevoked(ctx, c, gw.SpiffeID); err != nil || !revoked {
		gw = nil
		if err != nil {
			return nil, nil, err
		}
	}
	if con != nil {
		if revoked, err := identityRevoked(ctx, c, con.SpiffeID); err != nil || !revoked {
			con = nil
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return gw, con, nil
}

// identityRevoked reports whether the identity with SPIFFE ID spiffe is revoked as a whole; ""
// names none.
func identityRevoked(ctx context.Context, c *ent.Client, spiffe string) (bool, error) {
	if spiffe == "" {
		return false, nil
	}
	return c.RevokedIdentity.Query().Where(revokedidentity.ID(spiffe)).Exist(ctx)
}

// replaceGateway decommissions old, whose identity is revoked, and creates the built-in gateway that
// takes its place, which it returns.
func replaceGateway(ctx context.Context, tx *ent.Tx, old *ent.Gateway, actor string, now time.Time) (*ent.Gateway, error) {
	if err := tx.Gateway.UpdateOne(old).SetDecommissionedAt(now).SetEnabled(false).Exec(ctx); err != nil {
		return nil, err
	}
	row, err := tx.Gateway.Create().SetOrgID(old.OrgID).SetGatewayGroupID(old.GatewayGroupID).SetName(old.Name).
		SetTunnelEndpoints(old.TunnelEndpoints).SetEnabled(old.Enabled).SetDesiredVersion(old.DesiredVersion).SetBuiltIn(true).Save(ctx)
	if err != nil {
		return nil, err
	}
	return row, replaced(ctx, tx, old.OrgID, "gateway", old.ID, row.ID, actor)
}

// replaceConnector decommissions old, whose identity is revoked, creates the built-in connector
// that takes its place and moves old's route targets to it, each route's move audited. It returns
// the new connector's ID and the routes whose targets moved.
func replaceConnector(ctx context.Context, tx *ent.Tx, old *ent.Connector, actor string, now time.Time) (string, []string, error) {
	inst, err := tx.Instance.Get(ctx, 1)
	if err != nil {
		return "", nil, err
	}
	if err := tx.Connector.UpdateOne(old).SetDecommissionedAt(now).SetEnabled(false).Exec(ctx); err != nil {
		return "", nil, err
	}
	id := pki.Identity{TrustDomain: inst.TrustDomain, Org: old.OrgID, Kind: pki.KindConnector, ID: ids.New("con")}
	c := tx.Connector.Create().SetID(id.ID).SetOrgID(old.OrgID).SetName(old.Name).SetLabels(old.Labels).SetSpiffeID(id.String()).
		SetPubkeySha256(awaitingKey).SetEnabled(old.Enabled).SetDesiredVersion(old.DesiredVersion).SetBuiltIn(true)
	if old.Transport != nil {
		c.SetTransport(*old.Transport)
	}
	if err := c.Exec(ctx); err != nil {
		return "", nil, err
	}
	moved, err := tx.RouteTarget.Query().Where(routetarget.ConnectorID(old.ID)).Select(routetarget.FieldRouteID).Strings(ctx)
	if err != nil {
		return "", nil, err
	}
	if _, err := tx.RouteTarget.Update().Where(routetarget.ConnectorID(old.ID)).SetConnectorID(id.ID).Save(ctx); err != nil {
		return "", nil, err
	}
	moved = slices.Compact(slices.Sorted(slices.Values(moved)))
	for _, route := range moved {
		if _, err := audit.Append(ctx, tx, audit.Entry{OrgID: old.OrgID, ActorType: audit.ActorSystem, ActorID: actor, Action: "route.update",
			TargetType: "route", TargetID: route, Result: audit.Success,
			Reason: "its targets on connector " + old.ID + ", whose identity is revoked, moved to connector " + id.ID + ", which replaces it"}); err != nil {
			return "", nil, err
		}
	}
	return id.ID, moved, replaced(ctx, tx, old.OrgID, "connector", old.ID, id.ID, actor)
}

// replaced audits that the built-in agent of kind old was decommissioned and replaced by new.
func replaced(ctx context.Context, tx *ent.Tx, org, kind, old, new, actor string) error {
	for _, e := range []audit.Entry{
		{Action: kind + ".decommission", TargetID: old, Reason: "all-in-one's own " + kind + ": its identity is revoked; replaced by " + kind + " " + new},
		{Action: kind + ".create", TargetID: new, Reason: "all-in-one's own " + kind + ": replaces " + kind + " " + old + ", whose identity is revoked"},
	} {
		e.OrgID, e.ActorType, e.ActorID, e.TargetType, e.Result = org, audit.ActorSystem, actor, kind, audit.Success
		if _, err := audit.Append(ctx, tx, e); err != nil {
			return err
		}
	}
	return nil
}

// ownPorts reports the addresses and ports all-in-one's connector never dials, whatever its local
// policy allows (ADR-0019): the ports the process listens on, which are the admin listener, 80,
// 443, tunnel UDP and every route port its gateway has bound, on any address of this host. Those
// are loopback, the unspecified addresses, the addresses of its interfaces, and those its public
// names resolve to, for a host that reaches its public address through its router (hairpin NAT).
// It looks the addresses up again at most every addrsTTL; after a failed interface lookup at the
// next dial, after a failed name lookup a second later, keeping the addresses it had.
type ownPorts struct {
	fixed      map[uint16]bool
	routes     atomic.Pointer[func(uint16) bool]
	names      atomic.Pointer[[]string]
	interfaces func() ([]net.Addr, error)
	lookup     func(ctx context.Context, host string) ([]netip.Addr, error)
	now        func() time.Time

	mu    sync.Mutex
	addrs map[netip.Addr]bool
	next  time.Time // when to look the addresses up again
}

// The lookups of ownPorts.
const (
	addrsTTL      = 10 * time.Second
	nameRetry     = time.Second
	lookupTimeout = 2 * time.Second
)

func newOwnPorts(cfg config.AllInOne) (*ownPorts, error) {
	o := &ownPorts{fixed: map[uint16]bool{}, interfaces: net.InterfaceAddrs, now: time.Now,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}}
	addrs := []string{cfg.Listen.TCP, cfg.Listen.UDP, cfg.Listen.TunnelUDP, cfg.Listen.Admin}
	if cfg.Listen.HTTP != nil {
		addrs = append(addrs, *cfg.Listen.HTTP)
	}
	for _, a := range addrs {
		if a == "" {
			continue
		}
		_, port, err := net.SplitHostPort(a)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("allinone: the port of %q: %w", a, err)
		}
		o.fixed[uint16(n)] = true
	}
	if u, err := url.Parse(cfg.PublicURL); err == nil && u.Hostname() != "" {
		o.setNames([]string{u.Hostname()})
	}
	return o, nil
}

// setNames sets the public names whose addresses are the host's too; the next check looks them up.
func (o *ownPorts) setNames(names []string) {
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	o.names.Store(&names)
	o.mu.Lock()
	o.next = time.Time{}
	o.mu.Unlock()
}

// own reports whether ap is one of the process's own listeners on this host.
func (o *ownPorts) own(ap netip.AddrPort) bool {
	if !o.fixed[ap.Port()] {
		if r := o.routes.Load(); r == nil || !(*r)(ap.Port()) {
			return false
		}
	}
	a := ap.Addr().Unmap()
	if a.IsLoopback() || a.IsUnspecified() {
		return true
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if now := o.now(); o.addrs == nil || !now.Before(o.next) {
		o.refresh(now)
	}
	return o.addrs[a]
}

// refresh looks the host's addresses up again. Under o.mu.
func (o *ownPorts) refresh(now time.Time) {
	found, next := map[netip.Addr]bool{}, now.Add(addrsTTL)
	failed := false
	if ifaces, err := o.interfaces(); err != nil {
		failed, next = true, now // again at the next dial
	} else {
		for _, n := range ifaces {
			if p, ok := n.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(p.IP); ok {
					found[ip.Unmap()] = true
				}
			}
		}
	}
	if names := o.names.Load(); names != nil {
		for _, name := range *names {
			if ip, err := netip.ParseAddr(name); err == nil {
				found[ip.Unmap()] = true
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
			ips, err := o.lookup(ctx, name)
			cancel()
			if err != nil {
				failed = true
				if next.After(now.Add(nameRetry)) {
					next = now.Add(nameRetry)
				}
				continue
			}
			for _, ip := range ips {
				found[ip.Unmap()] = true
			}
		}
	}
	if failed {
		for a := range o.addrs { // keep what an earlier lookup found
			found[a] = true
		}
	}
	o.addrs, o.next = found, next
}
