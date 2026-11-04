// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/budget"
	"github.com/felix-homelab/rpmgr/internal/dns/dnsadapter"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
)

// DNS01 turns on DNS-01 for the hostnames that lie in a managed zone of the route's org: they get
// their certificates by writing the challenge TXT through the zone's provider, and wildcard
// hostnames there get one at all (docs/15-dns.md, "ACME DNS-01"; D166). Every other hostname keeps
// HTTP-01 and TLS-ALPN-01, and so does the controller's own certificate (Own), which never uses it.
type DNS01 struct {
	// Dial makes the client of a provider account; nil is providers.Dial.
	Dial providers.Dialer
	// Budget is the request budget of the providers, which DNS-01 takes from as its own kind and
	// at most half of; nil: none, for tests of other things.
	Budget *budget.Budget
	// TrustDomain is this instance's, in the marker of the challenge records.
	TrustDomain string
	// Resolvers are the DNS servers that find a name's zone and check that the TXT record is
	// visible; empty: the system's.
	Resolvers []string
	// PropagationTimeout bounds that check; 0 is certmagic's default and -1 skips it (tests whose
	// fake DNS has no name servers).
	PropagationTimeout time.Duration
}

// configs are the certmagic configurations of one pass on one storage and one certificate cache:
// the one that answers HTTP-01 and TLS-ALPN-01, and, per org, the one that answers DNS-01. Enabling
// DNS-01 on an issuer turns its other challenges off, so a name has exactly one of them, and the
// choice is made again from the zone on every order, so that a renewal needs no memory of the
// first issuance (docs/15-dns.md, "ACME DNS-01").
type configs struct {
	m     *Manager
	inst  *rpmgrv1.InstanceSettings
	cache *certmagic.Cache
	http  *certmagic.Config

	mu  sync.Mutex
	dns map[string]*certmagic.Config
}

// newConfig returns a configuration on the shared cache and storage with one issuer.
func (c *configs) newConfig(tune func(*certmagic.ACMEIssuer)) *certmagic.Config {
	m := c.m
	cfg := certmagic.New(c.cache, certmagic.Config{Storage: m.o.Storage, Logger: zap.NewNop(), DisableARI: m.o.DisableARI,
		RenewalWindowRatio: m.o.RenewalWindowRatio})
	iss := newIssuer(cfg, c.inst, m.o.TrustedRoots, m.o.Proxy, false, false)
	if m.o.TestCA != "" {
		iss.TestCA = m.o.TestCA
	}
	if tune != nil {
		tune(iss)
	}
	cfg.Issuers = []certmagic.Issuer{iss}
	return cfg
}

// dnsConfig returns the DNS-01 configuration of org, whose adapter writes only in the org's zones.
func (c *configs) dnsConfig(org string) *certmagic.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cfg, ok := c.dns[org]; ok {
		return cfg
	}
	d := c.m.o.DNS
	cfg := c.newConfig(func(iss *certmagic.ACMEIssuer) {
		iss.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider: &dnsadapter.Adapter{DB: c.m.o.DB, Sys: c.m.o.Sys, Sealer: c.m.o.Sealer, Dial: d.Dial, Budget: d.Budget,
				TrustDomain: d.TrustDomain, Org: org},
			Resolvers: d.Resolvers, PropagationTimeout: d.PropagationTimeout, Logger: zap.NewNop(),
		}}
	})
	if c.dns == nil {
		c.dns = map[string]*certmagic.Config{}
	}
	c.dns[org] = cfg
	return cfg
}

// pick chooses the configuration that obtains and renews w: DNS-01 when DNS-01 is on and the name
// lies in a managed zone of its org, else HTTP-01 and TLS-ALPN-01. A wildcard outside a managed
// zone has none (ErrWildcard), and a name in a disabled zone is refused (D166) before any order.
func (c *configs) pick(ctx context.Context, w wanted) (*certmagic.Config, error) {
	wild := len(w.name) > 2 && w.name[:2] == "*."
	if c.m.o.DNS == nil {
		if wild {
			return nil, ErrWildcard
		}
		return c.http, nil
	}
	z, err := dnsadapter.ZoneFor(ctx, c.m.o.DB.ReadClient(), w.org, w.name)
	switch {
	case errors.Is(err, dnsadapter.ErrZoneNotManaged) && wild:
		return nil, ErrWildcard
	case errors.Is(err, dnsadapter.ErrZoneNotManaged):
		return c.http, nil
	case err != nil:
		return nil, err
	case z.SyncState == dnszone.SyncStateDisabled:
		return nil, dnsadapter.ErrZoneDisabled
	}
	return c.dnsConfig(w.org), nil
}

// rateLimitedUntil returns when the provider's block ends if err says the provider rate-limited a
// request of the order, so that the retry waits for it and not for a block that is still on.
func rateLimitedUntil(err error) (time.Time, bool) {
	var rl dns.RateLimited
	if errors.As(err, &rl) {
		return rl.Until, true
	}
	return time.Time{}, false
}
