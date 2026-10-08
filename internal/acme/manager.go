// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
)

// JobEvery is how often the ACME job looks for certificates to obtain or renew
// (docs/03-connections.md, "Timeouts, keepalive and backoff").
const JobEvery = time.Minute

// ErrWildcard is the reason a wildcard hostname of an acme route gets no certificate (R42): its
// certificate needs DNS-01, which comes with managed DNS in Phase 2.
var ErrWildcard = errors.New("acme: a wildcard needs DNS-01 (Phase 2); upload a certificate for it")

// ManagerOptions configure a Manager.
type ManagerOptions struct {
	DB      *store.DB
	Sys     context.Context // the system scope
	Sealer  *secret.Sealer
	Storage certmagic.Storage // normally a ChallengeStorage
	// Proxy chooses the proxy of the ACME client's requests; nil is http.ProxyFromEnvironment
	// (HTTPS_PROXY, ALL_PROXY, NO_PROXY; R44).
	Proxy func(*http.Request) (*url.URL, error)
	// TrustedRoots, if set, replaces the system roots for the CA's own TLS certificate (tests).
	TrustedRoots *x509.CertPool
	// DisableARI renews by the renewal window only (tests whose certificates live minutes).
	DisableARI bool
	// RenewalWindowRatio is the part of a certificate's lifetime left when it is renewed; 0 is
	// certmagic's default (a third).
	RenewalWindowRatio float64
	Logger             *slog.Logger
}

// Manager obtains and renews the certificates of http routes in acme mode with certmagic on the
// controller (docs/04-security.md, "Controller certificates"): one certificate per hostname,
// stored in the certificates table of the route's org, which gateways then fetch. It runs as the
// singleton job "acme" (Job), so replicas never work on it at once.
type Manager struct {
	o ManagerOptions
}

// NewManager returns a Manager.
func NewManager(o ManagerOptions) *Manager {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Proxy == nil {
		o.Proxy = http.ProxyFromEnvironment
	}
	return &Manager{o: o}
}

// wanted is a hostname that needs an ACME certificate, with the org that owns it.
type wanted struct{ org, name string }

// Sync makes one pass: every hostname of an enabled http route in acme mode gets its certificate,
// obtained or renewed as needed; a hostname that cannot have one gets a failed row with the
// reason. It returns the first error after trying every hostname.
func (m *Manager) Sync(ctx context.Context) error {
	want, err := m.wanted()
	if err != nil {
		return err
	}
	if len(want) == 0 {
		return nil
	}
	cfg, stop, err := m.config()
	if err != nil {
		return err
	}
	defer stop()
	var errs []error
	for _, w := range want {
		if err := m.one(ctx, cfg, w); err != nil {
			m.o.Logger.Warn("route certificate not obtained", "hostname", w.name, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", w.name, err))
		}
	}
	return errors.Join(errs...)
}

// wanted lists the hostnames of enabled http routes in acme mode, each once.
func (m *Manager) wanted() ([]wanted, error) {
	var out []wanted
	err := store.ReadTx(m.o.Sys, m.o.DB, func(tx *ent.Tx, _ store.Revision) error {
		acmeRoutes, err := tx.RouteHTTP.Query().Where(routehttp.TLSModeEQ(routehttp.TLSModeAcme)).
			Select(routehttp.FieldRouteID).Strings(m.o.Sys)
		if err != nil || len(acmeRoutes) == 0 {
			return err
		}
		hosts, err := tx.RouteHostname.Query().Where(routehostname.RouteIDIn(acmeRoutes...),
			routehostname.HasRouteWith(route.Enabled(true))).Order(ent.Asc(routehostname.FieldHostname)).All(m.o.Sys)
		if err != nil {
			return err
		}
		for _, h := range hosts {
			w := wanted{org: h.OrgID, name: h.Hostname}
			if !slices.Contains(out, w) {
				out = append(out, w)
			}
		}
		return nil
	})
	return out, err
}

// config returns a certmagic configuration on the storage, with the CA and account of the
// instance settings.
func (m *Manager) config() (*certmagic.Config, func(), error) {
	inst, _, err := settings.Instance(m.o.Sys, m.o.DB.Client())
	if err != nil {
		return nil, nil, err
	}
	cache := certmagic.NewCache(certmagic.CacheOptions{Logger: zap.NewNop(),
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return nil, errors.New("acme: the cache does not renew; the job does")
		}})
	cfg := certmagic.New(cache, certmagic.Config{Storage: m.o.Storage, Logger: zap.NewNop(), DisableARI: m.o.DisableARI,
		RenewalWindowRatio: m.o.RenewalWindowRatio})
	alt := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0
		}
		defer func() { _ = ln.Close() }()
		return ln.Addr().(*net.TCPAddr).Port
	}
	cfg.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA: inst.GetAcmeDirectoryUrl(), Email: inst.GetAcmeEmail(), Agreed: true, TrustedRoots: m.o.TrustedRoots,
		HTTPProxy: m.o.Proxy, Logger: zap.NewNop(),
		// certmagic still starts its own challenge listeners; they go where no CA connects, as
		// the gateways answer the challenges (ChallengeStorage).
		ListenHost: "127.0.0.1", AltHTTPPort: alt(), AltTLSALPNPort: alt(),
	})}
	return cfg, cache.Stop, nil
}

// one obtains or renews the certificate of one hostname and records it.
func (m *Manager) one(ctx context.Context, cfg *certmagic.Config, w wanted) error {
	if strings.HasPrefix(w.name, "*.") {
		return m.record(w, nil, ErrWildcard)
	}
	if err := cfg.ObtainCertSync(ctx, w.name); err != nil {
		return m.record(w, nil, err)
	}
	cert, err := cfg.CacheManagedCertificate(ctx, w.name)
	if err != nil {
		return m.record(w, nil, err)
	}
	if cert.NeedsRenewal(cfg) {
		if err := cfg.RenewCertSync(ctx, w.name, false); err != nil {
			return m.record(w, &cert, err) // the old certificate serves on while it is valid
		}
		if cert, err = cfg.CacheManagedCertificate(ctx, w.name); err != nil {
			return m.record(w, nil, err)
		}
	}
	return m.record(w, &cert, nil)
}

// record writes a hostname's ACME certificate row: in a configuration transaction when the
// certificate changed, so gateways get a new snapshot, and otherwise only the outcome of the
// attempt. It returns attempt.
func (m *Manager) record(w wanted, cert *certmagic.Certificate, attempt error) error {
	var (
		chain []*x509.Certificate
		key   crypto.Signer
	)
	if cert != nil {
		for _, der := range cert.Certificate.Certificate {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return err
			}
			chain = append(chain, c)
		}
		signer, ok := cert.PrivateKey.(crypto.Signer)
		if !ok {
			return fmt.Errorf("acme: the key of %s cannot sign", w.name)
		}
		key = signer
	}
	var changed bool
	write := func(tx *ent.Tx) ([]string, error) {
		row, ch, err := certs.RecordACME(m.o.Sys, tx, m.o.Sealer, w.org, w.name, chain, key, attempt)
		if err != nil {
			return nil, err
		}
		changed = ch
		return []string{row.ID}, nil
	}
	// A certificate that changes is configuration: it gets a revision. An outcome alone is not.
	err := store.WriteTx(m.o.Sys, m.o.DB, func(tx *ent.Tx) error {
		row, err := certs.ACMERow(m.o.Sys, tx, w.org, w.name)
		if err != nil {
			return err
		}
		changed = cert != nil && (row == nil || !sameItem(row, cert))
		if changed {
			return nil
		}
		_, err = write(tx)
		return err
	})
	if err == nil && changed {
		_, err = store.ConfigTx(m.o.Sys, m.o.DB, write)
	}
	if err != nil {
		return errors.Join(attempt, err)
	}
	return attempt
}

// sameItem reports whether a row holds cert's chain already.
func sameItem(row *ent.Certificate, cert *certmagic.Certificate) bool {
	var raw []byte
	for _, der := range cert.Certificate.Certificate {
		raw = append(raw, der...)
	}
	return bytes.Equal(row.Chain, raw)
}

// Job is the singleton job that runs Sync every interval on the replica that holds its lease.
func (m *Manager) Job(every time.Duration) lease.Job {
	return lease.Job{Name: "acme", Reason: "obtain and renew route certificates", Every: every,
		Run: func(ctx context.Context, _ lease.Lease) error { return m.Sync(ctx) }}
}
