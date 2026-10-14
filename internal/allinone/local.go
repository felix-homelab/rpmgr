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
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/token"
)

// ConnectorName is the host name all-in-one's own connector enrolls with, which becomes its name.
const ConnectorName = "local"

// tokenTTL bounds the tokens all-in-one makes for its own agents, which it redeems at once.
const tokenTTL = 10 * time.Minute

// connectorToken adds to tx a single-use token for all-in-one's own connector in org: bound to
// the built-in connector id for a new identity, or, without one, a built-in token that enrolls a
// new built-in connector (ADR-0019).
func connectorToken(ctx context.Context, tx *ent.Tx, org, id, actor string) (string, error) {
	tok, err := token.New(token.Enrollment)
	if err != nil {
		return "", err
	}
	c := tx.EnrollmentToken.Create().SetOrgID(org).SetTokenHash(token.Hash(tok)).SetRole(enrollmenttoken.RoleConnector).
		SetMaxUses(1).SetExpiresAt(time.Now().Add(tokenTTL)).SetCreatedBy(actor)
	if id != "" {
		c.SetConnectorID(id)
	} else {
		c.SetBuiltIn(true)
	}
	row, err := c.Save(ctx)
	if err != nil {
		return "", err
	}
	_, err = audit.Append(ctx, tx, audit.Entry{OrgID: org, ActorType: audit.ActorSystem, ActorID: actor, Action: "enrollment_token.create",
		TargetType: "enrollment_token", TargetID: row.ID, Result: audit.Success, Reason: "all-in-one's own connector"})
	return tok, err
}

// local is what Run needs to know of its own agents before it starts them.
type local struct {
	gatewayID string
	// token, if set, enrolls the connector, which has no identity yet; it trusts root.
	token string
	root  *x509.Certificate
}

// enroll enrolls the connector with l.token through dial, the in-process controller.
func (l local) enroll(ctx context.Context, cfg config.AllInOne, dial func(context.Context, string) (net.Conn, error)) error {
	_, err := agent.Enroll(ctx, agent.EnrollOptions{Controller: cfg.PublicURL, Pin: pki.RootPin(l.root), Token: l.token,
		IdentityDir: cfg.Connector().IdentityDir, Bundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.root.Raw}),
		Dial: dial, Host: &agentv1.HostFacts{Hostname: ConnectorName}})
	if err != nil {
		return fmt.Errorf("allinone: enroll the connector: %w", err)
	}
	return nil
}

// prepare runs before the controller starts, while nothing else holds the database. It marks the
// gateway built in, for installations initialised before ADR-0019, and, when the connector has no
// identity, makes the token it enrolls with: bound to the built-in connector if there is one, so
// that it keeps its ID, routes and name, or else one that creates it.
func prepare(ctx context.Context, cfg config.AllInOne) (local, error) {
	gw, err := agent.ReadIdentity(cfg.Gateway().IdentityDir)
	if err != nil {
		return local{}, fmt.Errorf("allinone: the gateway's identity; run rpmgr all-in-one init first: %w", err)
	}
	l := local{gatewayID: gw.AgentID}
	_, err = agent.ReadIdentity(cfg.Connector().IdentityDir)
	missing := errors.Is(err, fs.ErrNotExist)
	if err != nil && !missing {
		return local{}, fmt.Errorf("allinone: the connector's identity: %w", err)
	}
	db, err := store.OpenSQLite(ctx, cfg.Database.DSN, store.SQLiteOptions{})
	if err != nil {
		return local{}, err
	}
	defer func() { _ = db.Close() }()
	const actor = "all-in-one"
	sys, err := authz.System(ctx, actor, "rpmgr all-in-one: its own agents", audit.SystemScopes(db))
	if err != nil {
		return local{}, err
	}
	// Neither the built-in flag nor a token is configuration that agents get: no revision.
	err = store.WriteTx(sys, db, func(tx *ent.Tx) error {
		row, err := tx.Gateway.Get(sys, l.gatewayID)
		if err != nil {
			return err
		}
		if !row.BuiltIn {
			if err := tx.Gateway.UpdateOne(row).SetBuiltIn(true).Exec(sys); err != nil {
				return err
			}
		}
		if !missing {
			return nil
		}
		ca, err := tx.CAKey.Query().Where(cakey.KindEQ(cakey.KindRoot), cakey.StatusEQ(cakey.StatusActive)).Only(sys)
		if err != nil {
			return err
		}
		if l.root, err = x509.ParseCertificate(ca.Certificate); err != nil {
			return err
		}
		id := ""
		if con, err := tx.Connector.Query().Where(connector.OrgID(row.OrgID), connector.BuiltIn(true), connector.DecommissionedAtIsNil()).
			First(sys); err == nil {
			id = con.ID
		} else if !ent.IsNotFound(err) {
			return err
		}
		l.token, err = connectorToken(sys, tx, row.OrgID, id, actor)
		return err
	})
	return l, err
}

// ownPorts reports the addresses and ports all-in-one's connector never dials, whatever its local
// policy allows (ADR-0019): the ports of the process's own listeners, which are the admin listener,
// the gateway's ports 443, 80 and tunnel UDP and the ports of its tcp and udp routes, on any
// address of this host. Those are loopback, the unspecified addresses, and the addresses of its
// interfaces, which it looks up again at most every interfacesTTL.
type ownPorts struct {
	fixed      map[uint16]bool
	routes     atomic.Pointer[func(uint16) bool]
	interfaces func() ([]net.Addr, error)
	now        func() time.Time

	mu    sync.Mutex
	addrs map[netip.Addr]bool
	at    time.Time
}

// interfacesTTL is how long ownPorts keeps the host's addresses.
const interfacesTTL = 10 * time.Second

func newOwnPorts(cfg config.AllInOne) (*ownPorts, error) {
	o := &ownPorts{fixed: map[uint16]bool{}, interfaces: net.InterfaceAddrs, now: time.Now}
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
	return o, nil
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
	if now := o.now(); o.addrs == nil || now.Sub(o.at) >= interfacesTTL {
		addrs, err := o.interfaces()
		if err == nil || o.addrs == nil {
			o.addrs, o.at = map[netip.Addr]bool{}, now
		}
		for _, n := range addrs {
			if p, ok := n.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(p.IP); ok {
					o.addrs[ip.Unmap()] = true
				}
			}
		}
	}
	return o.addrs[a]
}
