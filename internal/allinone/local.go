// SPDX-License-Identifier: Apache-2.0

package allinone

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
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
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
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
	id              string // the agent ID its certificate names; "" without an identity
	leaf            *x509.Certificate
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
		// The ID is the certificate's, which the CA signed, not agent.json's.
		if len(a.leaf.URIs) == 1 {
			if named, err := pki.ParseSPIFFE(a.leaf.URIs[0], a.leaf.URIs[0].Host); err == nil && string(named.Kind) == a.role {
				a.id = named.ID
			}
		}
	}
	return l, nil
}

// unusable says why the agent must enroll again, or "" if it runs with the identity it has, which
// must name want, the built-in gateway or connector this database holds (an ID of "" names none):
// it has no identity, or one that names another agent, as a copy from another installation, or the
// controller cannot renew its certificate, as after a restore of a backup older than the
// certificate, or the certificate expired longer ago than Reauth's grace period. An identity that
// names want but is revoked stops the start: enrolling again as the same agent cannot lift that.
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
// initialised before ADR-0019, which marks none, the one the gateway's identity names, which it
// marks built in. It reads the group's public hostnames and makes the token of each agent that
// must enroll again (unusable, at now): the gateway's bound to it, and the connector's bound to the
// org's built-in connector if there is one, so that each keeps its ID, routes and name, or else one
// that creates the connector. The enrollment revokes, by serial, the certificates the database
// records for the identity it replaces; one it does not record, as one issued after a restored
// backup, stays valid until it expires, as any agent's does.
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
	// Neither the built-in flag nor a token is configuration that agents get: no revision.
	return store.WriteTx(sys, db, func(tx *ent.Tx) error {
		row, err := builtInGateway(sys, tx, l.gateway.id)
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
// marked, as on an installation initialised before ADR-0019, the gateway with ID id, the one the
// gateway's identity names, while it is in service.
func builtInGateway(ctx context.Context, tx *ent.Tx, id string) (*ent.Gateway, error) {
	row, err := tx.Gateway.Query().Where(gateway.BuiltIn(true), gateway.DecommissionedAtIsNil()).Only(ctx)
	if err == nil || !ent.IsNotFound(err) {
		return row, err
	}
	if marked, err := tx.Gateway.Query().Where(gateway.BuiltIn(true)).Exist(ctx); err != nil || marked {
		return nil, errors.Join(err, errIf(marked, errNoGateway))
	}
	if id != "" {
		row, err := tx.Gateway.Get(ctx, id)
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
// It reports whether they changed; the same names keep the addresses already looked up.
func (o *ownPorts) setNames(names []string) bool {
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	if old := o.names.Load(); old != nil && slices.Equal(*old, names) {
		return false
	}
	o.names.Store(&names)
	o.mu.Lock()
	o.next = time.Time{}
	o.mu.Unlock()
	return true
}

// namesFollowed, if set, is called with the names each time followNames changes them; for tests.
var namesFollowed func([]string)

// followNames keeps own's names, the public URL's host public and the built-in gateway group's
// public hostnames, in step with the database while ctx lasts: at every revision, which it looks
// for every interval as the controller does, it reads the group's hostnames again, so a hostname
// added or removed counts without a restart. A failed read keeps the names it has, is logged once,
// and is tried again at the next check.
func (l *local) followNames(ctx context.Context, cfg config.AllInOne, own *ownPorts, public string, every time.Duration, log *slog.Logger) {
	db, err := store.OpenSQLite(ctx, cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		log.Warn("the gateway group's public hostnames are not followed", "error", err)
		return
	}
	defer func() { _ = db.Close() }()
	sys, err := authz.System(ctx, "all-in-one", "rpmgr all-in-one: its own agents", audit.SystemScopes(db))
	if err != nil {
		log.Warn("the gateway group's public hostnames are not followed", "error", err)
		return
	}
	var (
		seen   store.Revision
		failed bool
		tick   = time.NewTicker(every)
	)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		var (
			rev   store.Revision
			names []string
		)
		err := store.ReadTx(sys, db, func(tx *ent.Tx, r store.Revision) error {
			if rev = r; r == seen {
				return nil
			}
			gw, err := tx.Gateway.Get(sys, l.gatewayID)
			if err != nil {
				return err
			}
			group, err := tx.GatewayGroup.Get(sys, gw.GatewayGroupID)
			if err == nil {
				names = group.PublicHostnames
			}
			return err
		})
		switch {
		case err != nil && ctx.Err() == nil:
			if !failed {
				log.Warn("cannot read the gateway group's public hostnames; keeping the ones known", "error", err)
			}
			failed = true
			continue
		case err != nil:
			return
		}
		failed = false
		if rev == seen {
			continue
		}
		seen = rev
		if own.setNames(append(slices.Clone(names), public)) && namesFollowed != nil {
			namesFollowed(*own.names.Load())
		}
	}
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
