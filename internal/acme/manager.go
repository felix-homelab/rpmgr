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
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/proxyenv"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/certificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/route"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehostname"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routehttp"
)

// JobEvery is how often the ACME job looks for certificates to obtain or renew
// (docs/03-connections.md, "Timeouts, keepalive and backoff").
const JobEvery = time.Minute

// RetryFirst is the wait before a hostname whose attempt failed is tried again, and RetryMax the
// longest wait; each wait doubles the one before (docs/03-connections.md, "Timeouts, keepalive and
// backoff").
const (
	RetryFirst = time.Minute
	RetryMax   = 6 * time.Hour
)

// retryWait is the wait after failures attempts in a row failed, the first of them waiting first.
func retryWait(failures int, first time.Duration) time.Duration {
	wait := first
	for i := 1; i < failures && wait < RetryMax; i++ {
		wait *= 2
	}
	return min(wait, RetryMax)
}

// failing is a hostname whose attempts failed: how many in a row, and when the next is due.
type failing struct {
	failures int
	next     time.Time
}

// ErrWildcard is the reason a wildcard hostname of an acme route gets no certificate (R42): its
// certificate needs DNS-01, which comes with managed DNS in Phase 2.
var ErrWildcard = errors.New("acme: a wildcard needs DNS-01 (Phase 2); upload a certificate for it")

// ErrNotWanted is returned by Renew for a hostname of no enabled http route in acme mode.
var ErrNotWanted = errors.New("acme: no enabled http route in acme mode has the hostname")

// ManagerOptions configure a Manager.
type ManagerOptions struct {
	DB      *store.DB
	Sys     context.Context // the system scope
	Sealer  *secret.Sealer
	Storage certmagic.Storage // normally a ChallengeStorage
	// Proxy chooses the proxy of the ACME client's requests; nil is proxyenv.FromEnvironment
	// (HTTPS_PROXY, else ALL_PROXY; NO_PROXY; R44, D93).
	Proxy func(*http.Request) (*url.URL, error)
	// TrustedRoots, if set, replaces the system roots for the CA's own TLS certificate (tests).
	TrustedRoots *x509.CertPool
	// DisableARI renews by the renewal window only (tests whose certificates live minutes).
	DisableARI bool
	// RenewalWindowRatio is the part of a certificate's lifetime left when it is renewed; 0 is
	// certmagic's default (a third).
	RenewalWindowRatio float64
	// TestCA is the directory where a retry rehearses before it orders at the CA; "" is
	// certmagic's choice: Let's Encrypt's staging directory when the CA is Let's Encrypt's
	// production one, and none for another CA.
	TestCA string
	// RetryFirst is the wait before a failed hostname's first retry; 0 is RetryFirst (tests
	// shorten it).
	RetryFirst time.Duration
	// Now is the clock of the retry waits; nil is time.Now.
	Now    func() time.Time
	Logger *slog.Logger
}

// Manager obtains and renews the certificates of http routes in acme mode with certmagic on the
// controller (docs/04-security.md, "Controller certificates"): one certificate per hostname,
// stored in the certificates table of the route's org, which gateways then fetch. It runs as the
// singleton job "acme" (Job), so replicas never work on it at once.
//
// A hostname whose attempt failed waits before the next, and every retry rehearses at the test CA
// before it orders at the CA, so that a name the CA cannot validate fails at the test CA and not
// against the account's limits at the CA. The record of failures lives in memory; a hostname
// without a certificate, as its row then says, counts as failed already, so that a controller that
// starts or takes the job over rehearses it too.
type Manager struct {
	o        ManagerOptions
	renewing sync.Map // the wanted hostnames RenewAsync renews

	mu      sync.Mutex
	failing map[wanted]failing
}

// NewManager returns a Manager.
func NewManager(o ManagerOptions) *Manager {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Proxy == nil {
		o.Proxy = proxyenv.FromEnvironment
	}
	if o.RetryFirst == 0 {
		o.RetryFirst = RetryFirst
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Manager{o: o, failing: map[wanted]failing{}}
}

// wanted is a hostname that needs an ACME certificate, with the org that owns it.
type wanted struct{ org, name string }

// Sync makes one pass: every hostname of an enabled http route in acme mode gets its certificate,
// obtained or renewed as needed; a hostname that cannot have one gets a failed row with the
// reason. A hostname whose last attempt failed is tried only once its wait is over. It returns the
// errors of the hostnames it tried.
func (m *Manager) Sync(ctx context.Context) error {
	want, err := m.wanted()
	if err != nil {
		return err
	}
	if err := m.remember(want); err != nil {
		return err
	}
	now := m.o.Now()
	due := slices.DeleteFunc(want, func(w wanted) bool { return m.waiting(w, now) })
	if len(due) == 0 {
		return nil
	}
	cfg, stop, err := m.config()
	if err != nil {
		return err
	}
	defer stop()
	var errs []error
	for _, w := range due {
		if err := m.attempt(ctx, cfg, w, false); err != nil {
			m.o.Logger.Warn("route certificate not obtained", "hostname", w.name, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", w.name, err))
		}
	}
	return errors.Join(errs...)
}

// remember brings the record of failures in line with the wanted hostnames: it forgets those no
// longer wanted, so that one that comes back starts afresh, and takes a wanted hostname that it has
// no record of but whose row is failed, without a certificate, as failed once and due now.
func (m *Manager) remember(want []wanted) error {
	m.mu.Lock()
	for w := range m.failing {
		if !slices.Contains(want, w) {
			delete(m.failing, w)
		}
	}
	unknown := slices.ContainsFunc(want, func(w wanted) bool { _, ok := m.failing[w]; return !ok })
	m.mu.Unlock()
	if !unknown {
		return nil
	}
	var failed []*ent.Certificate
	err := store.ReadTx(m.o.Sys, m.o.DB, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		failed, err = tx.Certificate.Query().Where(certificate.SourceEQ(certificate.SourceAcme),
			certificate.StatusEQ(certificate.StatusFailed)).All(m.o.Sys)
		return err
	})
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, row := range failed {
		for _, name := range row.Sans {
			w := wanted{org: row.OrgID, name: name}
			if _, ok := m.failing[w]; !ok && slices.Contains(want, w) {
				m.failing[w] = failing{failures: 1}
			}
		}
	}
	return nil
}

// waiting reports whether w failed and its next attempt is not due at now.
func (m *Manager) waiting(w wanted, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.failing[w]
	return ok && now.Before(f.next)
}

// attempt runs one for w and keeps its record of failures (docs/04-security.md, "Controller
// certificates"). A retry tells certmagic that it is one, so that it rehearses at the test CA first
// and orders at the CA only once the test CA validated the name; an attempt that fails waits as
// retryWait says.
func (m *Manager) attempt(ctx context.Context, cfg *certmagic.Config, w wanted, force bool) error {
	m.mu.Lock()
	failures := m.failing[w].failures
	m.mu.Unlock()
	if failures > 0 {
		attempts := failures
		ctx = context.WithValue(ctx, certmagic.AttemptsCtxKey, &attempts)
	}
	err := m.one(ctx, cfg, w, force)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		delete(m.failing, w)
		return nil
	}
	failures++
	m.failing[w] = failing{failures: failures, next: m.o.Now().Add(retryWait(failures, m.o.RetryFirst))}
	return err
}

// RenewAsync starts renewing the certificate of one hostname of org in the background, under ctx:
// now, even before it is due or while it waits after a failure, or obtaining it if it has none yet,
// with the outcome recorded as Sync does. It reports false if a renewal of the hostname runs
// already.
func (m *Manager) RenewAsync(ctx context.Context, org, name string) (bool, error) {
	want, err := m.wanted()
	if err != nil {
		return false, err
	}
	w := wanted{org: org, name: name}
	if !slices.Contains(want, w) {
		return false, ErrNotWanted
	}
	if _, running := m.renewing.LoadOrStore(w, struct{}{}); running {
		return false, nil
	}
	go func() {
		defer m.renewing.Delete(w)
		cfg, stop, err := m.config()
		if err == nil {
			defer stop()
			err = m.attempt(ctx, cfg, w, true)
		}
		if err != nil {
			m.o.Logger.Warn("route certificate not renewed", "hostname", name, "error", err)
		}
	}()
	return true, nil
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
	iss := newIssuer(cfg, inst, m.o.TrustedRoots, m.o.Proxy, false, false)
	if m.o.TestCA != "" {
		iss.TestCA = m.o.TestCA
	}
	cfg.Issuers = []certmagic.Issuer{iss}
	return cfg, cache.Stop, nil
}

// newIssuer returns certmagic's ACME issuer for cfg with the CA and account of the instance
// settings. certmagic still starts its own challenge listeners; they go to free ports of 127.0.0.1,
// where no CA connects, as the gateways or the controller's own servers answer the challenges.
func newIssuer(cfg *certmagic.Config, inst *rpmgrv1.InstanceSettings, roots *x509.CertPool,
	proxy func(*http.Request) (*url.URL, error), noHTTP01, noTLSALPN01 bool) *certmagic.ACMEIssuer {
	free := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0
		}
		defer func() { _ = ln.Close() }()
		return ln.Addr().(*net.TCPAddr).Port
	}
	return certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA: inst.GetAcmeDirectoryUrl(), Email: inst.GetAcmeEmail(), Agreed: true, TrustedRoots: roots, HTTPProxy: proxy,
		Logger: zap.NewNop(), DisableHTTPChallenge: noHTTP01, DisableTLSALPNChallenge: noTLSALPN01,
		ListenHost: "127.0.0.1", AltHTTPPort: free(), AltTLSALPNPort: free(),
	})
}

// one obtains or renews the certificate of one hostname and records it. With force, a certificate
// that was there before is renewed even if it is not due.
func (m *Manager) one(ctx context.Context, cfg *certmagic.Config, w wanted, force bool) error {
	if strings.HasPrefix(w.name, "*.") {
		return m.record(w, nil, ErrWildcard)
	}
	had := cfg.Storage.Exists(ctx, certmagic.StorageKeys.SiteCert(cfg.Issuers[0].IssuerKey(), w.name))
	if err := cfg.ObtainCertSync(ctx, w.name); err != nil {
		return m.record(w, nil, err)
	}
	cert, err := cfg.CacheManagedCertificate(ctx, w.name)
	if err != nil {
		return m.record(w, nil, err)
	}
	if force && had || cert.NeedsRenewal(cfg) {
		err := cfg.RenewCertSync(ctx, w.name, force)
		if err != nil && !cfg.DisableARI && strings.Contains(err.Error(), "creating new order") {
			// The order named the certificate it replaces (ARI), and a CA refuses that for a
			// certificate of another account of the same directory, as after a change of the
			// account's e-mail address; certmagic names it only for the same directory. No
			// challenge was tried yet, so renew once more without naming it, as certmagic's own
			// background retries do.
			cfg.DisableARI = true
			err = cfg.RenewCertSync(ctx, w.name, true)
			cfg.DisableARI = false
		}
		if err != nil {
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
		_, err = store.ConfigTx(store.RevisionOrg(m.o.Sys, w.org), m.o.DB, write)
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
