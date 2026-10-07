// SPDX-License-Identifier: Apache-2.0

// Package controller is the controller side of S6: certmagic with two configurations on one
// storage, chosen per name (docs/15-dns.md, "ACME DNS-01"):
//
//   - names in a managed zone (and every wildcard) use a configuration whose ACME issuer has a
//     DNS01Solver, which in certmagic disables the other challenge types for that issuer;
//   - all other names use a configuration with HTTP-01 and TLS-ALPN-01, answered by the gateways
//     through controlplane.SyncStorage.
//
// One certmagic.Cache serves both and picks the configuration of a certificate by its name, so
// renewals use the same challenge kind as the first issuance.
package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// Options configure a controller replica.
type Options struct {
	Storage      certmagic.Storage
	DirectoryURL string
	ACMETrust    *x509.CertPool // trust for the ACME server's TLS certificate (test CA only)
	Email        string

	ManagedZones []string              // names below these use DNS-01
	DNSProvider  certmagic.DNSProvider // libdns adapter over the DNS provider's API
	Resolvers    []string              // DNS servers used to find a name's zone
	// DNSPropagationTimeout bounds certmagic's check that the TXT record is visible at the
	// zone's authoritative nameservers: 0 = certmagic's default (2 min), -1 = no check.
	DNSPropagationTimeout time.Duration

	DisableHTTP01, DisableTLSALPN01 bool

	RenewalWindowRatio float64
	// DisableARI makes renewal follow RenewalWindowRatio only. Tests with certificates that live
	// seconds need it: Pebble's ARI window then starts at issuance, so a fresh certificate can
	// be due for renewal at once.
	DisableARI   bool
	CacheOptions certmagic.CacheOptions // RenewCheckInterval etc.

	// PushCertificate receives every obtained or renewed certificate (in rpmgr: pushed to the
	// gateways that serve its names).
	PushCertificate func(*tls.Certificate) error
	// OnObtained is called after every issuance or renewal.
	OnObtained func(identifier string, renewal bool)
	Logger     *zap.Logger
}

// Controller is one controller replica's ACME manager.
type Controller struct {
	opts    Options
	cache   *certmagic.Cache
	httpCfg *certmagic.Config
	dnsCfg  *certmagic.Config
}

// New builds the two configurations.
func New(opts Options) (*Controller, error) {
	if opts.Logger == nil {
		opts.Logger = zap.NewNop()
	}
	if opts.DNSProvider == nil && len(opts.ManagedZones) > 0 {
		return nil, errors.New("controller: managed zones need a DNS provider")
	}
	c := &Controller{opts: opts}
	co := opts.CacheOptions
	co.Logger = opts.Logger
	co.GetConfigForCert = func(cert certmagic.Certificate) (*certmagic.Config, error) {
		if len(cert.Names) == 0 {
			return nil, errors.New("controller: certificate without names")
		}
		return c.ConfigFor(cert.Names[0]), nil
	}
	c.cache = certmagic.NewCache(co)
	c.httpCfg = c.newConfig(false)
	c.dnsCfg = c.newConfig(true)
	return c, nil
}

func (c *Controller) newConfig(dns01 bool) *certmagic.Config {
	cfg := certmagic.New(c.cache, certmagic.Config{
		Storage:            c.opts.Storage,
		RenewalWindowRatio: c.opts.RenewalWindowRatio,
		DisableARI:         c.opts.DisableARI,
		Logger:             c.opts.Logger,
		OnEvent:            c.onEvent,
	})
	tmpl := certmagic.ACMEIssuer{
		CA:           c.opts.DirectoryURL,
		Email:        c.opts.Email,
		Agreed:       true,
		TrustedRoots: c.opts.ACMETrust,
		Logger:       c.opts.Logger,
	}
	if dns01 {
		tmpl.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider:        c.opts.DNSProvider,
			Resolvers:          c.opts.Resolvers,
			PropagationTimeout: c.opts.DNSPropagationTimeout,
			Logger:             c.opts.Logger,
		}}
	} else {
		tmpl.DisableHTTPChallenge = c.opts.DisableHTTP01
		tmpl.DisableTLSALPNChallenge = c.opts.DisableTLSALPN01
		// certmagic still starts its own challenge listeners; bind them where no CA connects, so
		// that only the gateways can answer.
		tmpl.ListenHost = "127.0.0.1"
		tmpl.AltHTTPPort = freePort()
		tmpl.AltTLSALPNPort = freePort()
	}
	cfg.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(cfg, tmpl)}
	return cfg
}

// IsManaged reports whether name (or, for a wildcard, its base) is in a managed zone.
func (c *Controller) IsManaged(name string) bool {
	n := strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(name, "."), "*."))
	for _, z := range c.opts.ManagedZones {
		z = strings.ToLower(strings.TrimSuffix(z, "."))
		if n == z || strings.HasSuffix(n, "."+z) {
			return true
		}
	}
	return false
}

// ConfigFor returns the configuration that obtains and renews name.
func (c *Controller) ConfigFor(name string) *certmagic.Config {
	if c.IsManaged(name) {
		return c.dnsCfg
	}
	return c.httpCfg
}

// ErrWildcardNeedsManagedZone: wildcards can only be validated with DNS-01.
var ErrWildcardNeedsManagedZone = errors.New("controller: a wildcard needs a managed zone (DNS-01)")

// Manage obtains (if needed) and keeps renewing certificates for names.
func (c *Controller) Manage(ctx context.Context, names []string) error {
	var dnsNames, httpNames []string
	for _, n := range names {
		switch {
		case c.IsManaged(n):
			dnsNames = append(dnsNames, n)
		case strings.HasPrefix(n, "*."):
			return fmt.Errorf("%w: %s", ErrWildcardNeedsManagedZone, n)
		default:
			httpNames = append(httpNames, n)
		}
	}
	if len(dnsNames) > 0 {
		if err := c.dnsCfg.ManageSync(ctx, dnsNames); err != nil {
			return err
		}
	}
	if len(httpNames) > 0 {
		return c.httpCfg.ManageSync(ctx, httpNames)
	}
	return nil
}

// Obtain obtains one certificate under the issuance lock, without managing it.
func (c *Controller) Obtain(ctx context.Context, name string) error {
	if strings.HasPrefix(name, "*.") && !c.IsManaged(name) {
		return fmt.Errorf("%w: %s", ErrWildcardNeedsManagedZone, name)
	}
	return c.ConfigFor(name).ObtainCertSync(ctx, name)
}

// Renew renews one certificate under the issuance lock; force renews even if not yet due.
func (c *Controller) Renew(ctx context.Context, name string, force bool) error {
	return c.ConfigFor(name).RenewCertSync(ctx, name, force)
}

// Load returns the stored certificate for name.
func (c *Controller) Load(ctx context.Context, name string) (*tls.Certificate, error) {
	cfg := c.ConfigFor(name)
	issuer := cfg.Issuers[0]
	certPEM, err := cfg.Storage.Load(ctx, certmagic.StorageKeys.SiteCert(issuer.IssuerKey(), name))
	if err != nil {
		return nil, err
	}
	keyPEM, err := cfg.Storage.Load(ctx, certmagic.StorageKeys.SitePrivateKey(issuer.IssuerKey(), name))
	if err != nil {
		return nil, err
	}
	return parsePair(certPEM, keyPEM)
}

// Stop stops certificate maintenance.
func (c *Controller) Stop() { c.cache.Stop() }

func (c *Controller) onEvent(ctx context.Context, event string, data map[string]any) error {
	if event != "cert_obtained" {
		return nil
	}
	name, _ := data["identifier"].(string)
	renewal, _ := data["renewal"].(bool)
	if c.opts.PushCertificate != nil {
		certPath, _ := data["certificate_path"].(string)
		keyPath, _ := data["private_key_path"].(string)
		certPEM, err1 := c.opts.Storage.Load(ctx, certPath)
		keyPEM, err2 := c.opts.Storage.Load(ctx, keyPath)
		if err := errors.Join(err1, err2); err != nil {
			c.opts.Logger.Error("loading obtained certificate", zap.Error(err))
		} else if cert, err := parsePair(certPEM, keyPEM); err != nil {
			c.opts.Logger.Error("parsing obtained certificate", zap.Error(err))
		} else if err := c.opts.PushCertificate(cert); err != nil {
			c.opts.Logger.Error("pushing certificate to gateways", zap.Error(err))
		}
	}
	if c.opts.OnObtained != nil {
		c.opts.OnObtained(name, renewal)
	}
	return nil
}

func parsePair(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	return &cert, err
}

func freePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
