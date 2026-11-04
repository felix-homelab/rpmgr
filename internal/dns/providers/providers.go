// SPDX-License-Identifier: Apache-2.0

// Package providers is what DnsProviderService and the hourly token check share about a connected
// DNS provider account: how its credential is bound to its row, how a provider client is made from
// it, and how a check of the credential is read (docs/15-dns.md, "Connecting, importing and
// disconnecting"). The credential is a secret.Value throughout.
package providers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// KindCloudflare is the kind of a Cloudflare account.
const KindCloudflare = "cloudflare"

// The times of the token check; the values are those of docs/15-dns.md, "Timers and limits".
const (
	// CheckEvery is how often the job checks every provider's token.
	CheckEvery = time.Hour
	// ExpiryWarning is how long before its expiry a token is flagged.
	ExpiryWarning = 14 * 24 * time.Hour
)

// SecretContext binds a provider's sealed credential to its row.
func SecretContext(id string) secret.Context {
	return secret.Context{Table: "dns_providers", Column: "credential_enc", RowID: id}
}

// Dialer makes the client of a provider account.
type Dialer func(kind, accountID string, token secret.Value) (dns.Provider, error)

// Dial is the Dialer of a production controller: the compiled-in API of the provider.
func Dial(kind, accountID string, token secret.Value) (dns.Provider, error) {
	if kind != KindCloudflare {
		return nil, fmt.Errorf("providers: unknown kind %q", kind)
	}
	return cloudflare.New(cloudflare.Config{Token: token, AccountID: accountID})
}

// Outcome is what a check of a credential found.
type Outcome struct {
	// OK: the provider accepts the credential.
	OK bool
	// Expires is when the token expires; nil for one that does not.
	Expires *time.Time
	// Reason is why the credential is not usable; fixed words, never the provider's, empty if OK.
	Reason string
	// Err is set instead when no verdict could be had: the provider is unreachable, rate-limiting
	// or answered something unexpected. The credential is neither accepted nor refused.
	Err error
}

// Check asks the provider about its credential.
func Check(ctx context.Context, p dns.Provider) Outcome {
	info, err := p.Verify(ctx)
	switch {
	case errors.Is(err, dns.ErrUnauthorized) || errors.Is(err, dns.ErrForbidden):
		return Outcome{Reason: "the provider does not accept the token"}
	case errors.Is(err, dns.ErrInvalid):
		return Outcome{Reason: "the account ID is not valid"}
	case err != nil:
		return Outcome{Err: err}
	case !info.Active():
		return Outcome{Reason: "the provider reports the token as not active"}
	}
	o := Outcome{OK: true}
	if !info.ExpiresAt.IsZero() {
		t := info.ExpiresAt.UTC()
		o.Expires = &t
	}
	return o
}

// Expiring reports whether a token that expires at exp is flagged at now: it expires within
// ExpiryWarning, or already has. A token without an expiry never is.
func Expiring(exp *time.Time, now time.Time) bool {
	return exp != nil && exp.Sub(now) <= ExpiryWarning
}
