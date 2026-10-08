// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
	"go.uber.org/zap"

	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// ownRenewCheck is how often the controller checks whether its own certificate is due for renewal
// (docs/03-connections.md, "Timeouts, keepalive and backoff"); a variable for tests.
var ownRenewCheck = JobEvery

// ownNoTLSALPN01 leaves TLS-ALPN-01 out, so a test knows which challenge the CA validates.
var ownNoTLSALPN01 = false

// ErrNoCertificate is returned by Own.GetCertificate before ACME obtained a certificate.
var ErrNoCertificate = errors.New("acme: no certificate obtained yet")

// OwnOptions configure an Own.
type OwnOptions struct {
	DB  *store.DB
	Sys context.Context // the system scope
	// Storage is the plain database Storage, not a ChallengeStorage: the controller answers the
	// challenges of its own name itself.
	Storage certmagic.Storage
	Host    string // the public URL's
	// NoHTTP01 leaves HTTP-01 out, for a controller without a port-80 listener.
	NoHTTP01 bool
	// Proxy chooses the proxy of the ACME client's requests; nil is http.ProxyFromEnvironment.
	Proxy func(*http.Request) (*url.URL, error)
	// TrustedRoots, if set, replaces the system roots for the CA's own TLS certificate (tests).
	TrustedRoots *x509.CertPool
	// DisableARI and RenewalWindowRatio are as in ManagerOptions (tests).
	DisableARI         bool
	RenewalWindowRatio float64
	Logger             *slog.Logger
}

// Own obtains and renews the controller's certificate for the host of its public URL with
// certmagic (docs/04-security.md, "Controller certificates"), when the boot file names no
// certificate files. The controller answers the challenges itself: HTTP-01 on its port-80
// listener (HTTPHandler) and TLS-ALPN-01 on port 443 (GetCertificate), through the gateway in
// all-in-one. The certificate and the ACME account live in the database Storage, whose locks let
// one replica at a time order. A renewal that fails keeps the certificate in use.
type Own struct {
	host   string
	cfg    *certmagic.Config
	issuer *certmagic.ACMEIssuer
	cache  *certmagic.Cache
}

// Eligible reports whether a public URL's host can have a certificate from a public CA: a DNS name
// of two labels or more that is not internal (localhost, .local, .internal, .home.arpa).
func Eligible(host string) bool {
	return net.ParseIP(host) == nil && strings.Contains(host, ".") && !strings.Contains(host, "*") &&
		certmagic.SubjectQualifiesForPublicCert(host)
}

// NewOwn returns an Own with the CA and account of the instance settings at this moment; it orders
// nothing before Manage.
func NewOwn(o OwnOptions) (*Own, error) {
	if !Eligible(o.Host) {
		return nil, errors.New("acme: the public URL's host cannot have a certificate from a public CA")
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Proxy == nil {
		o.Proxy = http.ProxyFromEnvironment
	}
	inst, _, err := settings.Instance(o.Sys, o.DB.Client())
	if err != nil {
		return nil, err
	}
	own := &Own{host: strings.ToLower(o.Host)}
	own.cache = certmagic.NewCache(certmagic.CacheOptions{Logger: zap.NewNop(), RenewCheckInterval: ownRenewCheck,
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return own.cfg, nil }})
	own.cfg = certmagic.New(own.cache, certmagic.Config{Storage: o.Storage, Logger: zap.NewNop(), DisableARI: o.DisableARI,
		RenewalWindowRatio: o.RenewalWindowRatio, OnEvent: func(_ context.Context, event string, data map[string]any) error {
			switch event {
			case "cert_obtained":
				o.Logger.Info("obtained the public URL's certificate", "host", data["identifier"], "renewal", data["renewal"])
			case "cert_failed":
				o.Logger.Warn("cannot obtain the public URL's certificate; keeping the one in use", "host", data["identifier"],
					"renewal", data["renewal"], "error", data["error"])
			}
			return nil
		}})
	own.issuer = newIssuer(own.cfg, inst, o.TrustedRoots, o.Proxy, o.NoHTTP01, ownNoTLSALPN01)
	own.cfg.Issuers = []certmagic.Issuer{own.issuer}
	return own, nil
}

// Load puts a stored certificate in use at once, so that a restart serves it from the first
// connection on; without one it does nothing.
func (o *Own) Load(ctx context.Context) error {
	if _, err := o.cfg.CacheManagedCertificate(ctx, o.host); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Manage loads the certificate from storage, or obtains it in the background, retrying with
// certmagic's backoff, and renews it until ctx ends.
func (o *Own) Manage(ctx context.Context) error {
	return o.cfg.ManageAsync(ctx, []string{o.host})
}

// Stop ends the renewal checks.
func (o *Own) Stop() { o.cache.Stop() }

// Has reports whether a certificate for the host was obtained.
func (o *Own) Has() bool { return len(o.cache.AllMatchingCertificates(o.host)) > 0 }

// GetCertificate answers a TLS-ALPN-01 challenge, and otherwise returns the host's certificate
// whatever name the client asked for, or ErrNoCertificate.
func (o *Own) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acmez.ACMETLS1Protocol {
		return o.cfg.GetCertificate(hello)
	}
	if !o.Has() {
		return nil, ErrNoCertificate
	}
	h := *hello
	h.ServerName = o.host
	return o.cfg.GetCertificate(&h)
}

// HTTPHandler answers HTTP-01 challenges for the host and passes every other request to next.
func (o *Own) HTTPHandler(next http.Handler) http.Handler { return o.issuer.HTTPChallengeHandler(next) }
