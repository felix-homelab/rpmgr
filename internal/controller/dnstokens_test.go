// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsprovider"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// tokenFake answers Verify by the token it was made with.
type tokenFake struct {
	mu    sync.Mutex
	state map[string]func() (dns.TokenInfo, error)
	calls int
}

func (f *tokenFake) dial(_, _ string, tok secret.Value) (dns.Provider, error) {
	for k := range f.state {
		if tok.EqualString(k) {
			return tokenProvider{f, k}, nil
		}
	}
	return nil, errors.New("unknown token")
}

type tokenProvider struct {
	f   *tokenFake
	tok string
}

func (p tokenProvider) Verify(context.Context) (dns.TokenInfo, error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.calls++
	return p.f.state[p.tok]()
}
func (tokenProvider) ListZones(context.Context) ([]dns.Zone, error)             { return nil, nil }
func (tokenProvider) ListRecords(context.Context, string) ([]dns.Record, error) { return nil, nil }
func (tokenProvider) Apply(context.Context, string, dns.Batch) error            { return nil }
func (tokenProvider) Caps() dns.Capabilities                                    { return dns.Capabilities{} }

// TestDNSTokenJob (docs/15-dns.md, "Timers and limits"): the hourly check records what the provider
// says: a refused or expired token makes the provider invalid with a fixed reason, a token that
// expires is recorded with its expiry (flagged by providers.Expiring), a good one is ok again; a
// provider that cannot be reached or rate-limits gives no verdict and changes nothing; a replica
// without the lease records nothing; and no log line holds a token.
func TestDNSTokenJob(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	sys := storetest.SystemCtx(t)
	kek, _ := secret.NewKEK([]byte("0123456789abcdef0123456789abcdef"))
	sealer, _ := secret.NewSealer(kek)
	leases := lease.New(db, "ctn_test", nil)
	held, ok, err := leases.TryAcquire(sys, "dns-tokens")
	if err != nil || !ok {
		t.Fatal("no lease", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	logs := &bytes.Buffer{}
	expiry := now.Add(3 * 24 * time.Hour)
	f := &tokenFake{state: map[string]func() (dns.TokenInfo, error){
		"token-good-0001":   func() (dns.TokenInfo, error) { return dns.TokenInfo{Status: "active"}, nil },
		"token-expiring-02": func() (dns.TokenInfo, error) { return dns.TokenInfo{Status: "active", ExpiresAt: expiry}, nil },
		"token-revoked-003": func() (dns.TokenInfo, error) {
			return dns.TokenInfo{}, &dns.ProviderError{Status: 401, Err: dns.ErrUnauthorized}
		},
		"token-expired-004": func() (dns.TokenInfo, error) { return dns.TokenInfo{Status: "expired"}, nil },
		"token-limited-005": func() (dns.TokenInfo, error) { return dns.TokenInfo{}, dns.RateLimited{Until: now.Add(time.Minute)} },
		"token-offline-0006": func() (dns.TokenInfo, error) {
			return dns.TokenInfo{}, errors.New("cloudflare: GET /user/tokens/verify: timeout")
		},
	}}
	job := controller.DNSTokenJob(controller.DNSTokenOptions{DB: db, Leases: leases, Sealer: sealer, Dial: f.dial,
		Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if job.Name != "dns-tokens" || job.Every != providers.CheckEvery {
		t.Fatalf("job %q every %v", job.Name, job.Every)
	}

	org := storetest.Org(t, db, "org-a")
	c := db.Client()
	add := func(name, tok string, edit func(*ent.DNSProviderCreate)) string {
		id := ids.New("dnp")
		sealed, err := sealer.Seal(providers.SecretContext(id), secret.New(tok))
		if err != nil {
			t.Fatal(err)
		}
		cr := c.DNSProvider.Create().SetID(id).SetOrgID(org).SetKind(dnsprovider.KindCloudflare).SetName(name).SetCredentialEnc(sealed)
		if edit != nil {
			edit(cr)
		}
		cr.ExecX(sys)
		return id
	}
	good := add("good", "token-good-0001", func(cr *ent.DNSProviderCreate) { cr.SetStatus(dnsprovider.StatusInvalid).SetLastError("old") })
	expiring := add("expiring", "token-expiring-02", nil)
	revoked := add("revoked", "token-revoked-003", nil)
	expired := add("expired", "token-expired-004", nil)
	limited := add("limited", "token-limited-005", nil)
	offline := add("offline", "token-offline-0006", func(cr *ent.DNSProviderCreate) { cr.SetStatus(dnsprovider.StatusInvalid).SetLastError("kept") })
	unsealable := ids.New("dnp")
	c.DNSProvider.Create().SetID(unsealable).SetOrgID(org).SetKind(dnsprovider.KindCloudflare).SetName("broken").SetCredentialEnc([]byte("not sealed")).ExecX(sys)

	// A replica that lost the lease records nothing.
	if err := job.Run(context.WithoutCancel(sys), lease.Lease{Name: "dns-tokens", Token: held.Token + 1}); !errors.Is(err, lease.ErrLost) {
		t.Fatalf("a lost lease: %v", err)
	}
	if n := c.DNSProvider.Query().Where(dnsprovider.LastCheckedAtNotNil()).CountX(sys); n != 0 {
		t.Fatalf("%d providers were recorded without the lease", n)
	}

	if err := job.Run(context.WithoutCancel(sys), held); err != nil {
		t.Fatal(err)
	}
	row := func(id string) *ent.DNSProvider { return c.DNSProvider.GetX(sys, id) }
	if r := row(good); r.Status != dnsprovider.StatusOk || r.LastError != "" || r.TokenExpiresAt != nil || r.LastCheckedAt == nil || !r.LastCheckedAt.Equal(now) {
		t.Errorf("good: %+v", r)
	}
	if r := row(expiring); r.Status != dnsprovider.StatusOk || r.TokenExpiresAt == nil || !r.TokenExpiresAt.Equal(expiry) || !providers.Expiring(r.TokenExpiresAt, now) {
		t.Errorf("expiring: %+v", r)
	}
	if r := row(good); providers.Expiring(r.TokenExpiresAt, now) {
		t.Error("a token without an expiry is flagged")
	}
	for name, id := range map[string]string{"revoked": revoked, "expired": expired} {
		if r := row(id); r.Status != dnsprovider.StatusInvalid || r.LastError == "" || r.LastCheckedAt == nil {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if r := row(expired); !strings.Contains(r.LastError, "not active") {
		t.Errorf("expired: %q", r.LastError)
	}
	for name, id := range map[string]string{"limited": limited, "offline": offline, "unsealable": unsealable} {
		if r := row(id); r.LastCheckedAt != nil || r.Version != 1 {
			t.Errorf("%s was recorded without a verdict: %+v", name, r)
		}
	}
	if r := row(offline); r.Status != dnsprovider.StatusInvalid || r.LastError != "kept" {
		t.Errorf("offline: %+v", r)
	}
	if strings.Contains(logs.String(), "token-") || strings.Contains(logs.String(), "not sealed") {
		t.Errorf("a log line holds a token: %s", logs.String())
	}
	for _, id := range []string{limited, offline, unsealable} {
		if !strings.Contains(logs.String(), id) {
			t.Errorf("the log does not name %s", id)
		}
	}

	// The provider takes the token back, later: the next pass changes it.
	f.mu.Lock()
	f.state["token-good-0001"] = func() (dns.TokenInfo, error) {
		return dns.TokenInfo{}, &dns.ProviderError{Status: 403, Err: dns.ErrForbidden}
	}
	f.mu.Unlock()
	now = now.Add(providers.CheckEvery)
	if err := job.Run(context.WithoutCancel(sys), held); err != nil {
		t.Fatal(err)
	}
	if r := row(good); r.Status != dnsprovider.StatusInvalid || r.LastError == "" || !r.LastCheckedAt.Equal(now) {
		t.Errorf("good after the provider refused it: %+v", r)
	}
}
