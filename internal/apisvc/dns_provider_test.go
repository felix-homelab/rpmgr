// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/budget"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/pki/castore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/secretmeta"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// The tokens of the tests are not real credentials: none has the shape of a Cloudflare token.
const (
	dnsToken1 = "test-dns-token-one-aaaaaaaa" //nolint:gosec // G101: a test value
	dnsToken2 = "test-dns-token-two-bbbbbbbb" //nolint:gosec // G101: a test value
	dnsToken3 = "test-dns-token-three-cccccc" //nolint:gosec // G101: a test value
)

// fakeDNS is the provider side of DnsProviderService: it knows tokens, and answers as Cloudflare
// would for each. dial is the service's Dialer.
type fakeDNS struct {
	mu      sync.Mutex
	tokens  map[string]*fakeDNSToken
	zones   []dns.Zone
	records []dns.Record // what ListRecords returns for every zone
	dialed  []string     // the token of each client made
	batches []dns.Batch  // what Apply was sent
}

type fakeDNSToken struct {
	status  string // "active" if empty
	expires time.Time
	err     error // what every call answers instead
}

func (f *fakeDNS) know(tok string, t fakeDNSToken) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokens == nil {
		f.tokens = map[string]*fakeDNSToken{}
	}
	f.tokens[tok] = &t
}

func (f *fakeDNS) dial(_, _ string, tok secret.Value) (dns.Provider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := ""
	for k := range f.tokens {
		if tok.EqualString(k) {
			key = k
		}
	}
	f.dialed = append(f.dialed, key)
	return fakeProvider{f: f, tok: key}, nil
}

func (f *fakeDNS) dials() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dialed)
}

type fakeProvider struct {
	f   *fakeDNS
	tok string
}

func (p fakeProvider) token() (*fakeDNSToken, error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	t := p.f.tokens[p.tok]
	switch {
	case t == nil:
		return nil, &dns.ProviderError{Status: 401, Err: dns.ErrUnauthorized}
	case t.err != nil:
		return nil, t.err
	}
	return t, nil
}

func (p fakeProvider) Verify(context.Context) (dns.TokenInfo, error) {
	t, err := p.token()
	if err != nil {
		return dns.TokenInfo{}, err
	}
	status := t.status
	if status == "" {
		status = "active"
	}
	return dns.TokenInfo{ID: "tok", Status: status, ExpiresAt: t.expires}, nil
}

func (p fakeProvider) ListZones(context.Context) ([]dns.Zone, error) {
	if _, err := p.token(); err != nil {
		return nil, err
	}
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	return append([]dns.Zone(nil), p.f.zones...), nil
}

func (p fakeProvider) ListRecords(context.Context, string) ([]dns.Record, error) {
	if _, err := p.token(); err != nil {
		return nil, err
	}
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	return append([]dns.Record(nil), p.f.records...), nil
}

// Apply patches the records ListRecords returns, and remembers what it was sent; it refuses with
// the error of the token, like every other call.
func (p fakeProvider) Apply(_ context.Context, _ string, b dns.Batch) error {
	if _, err := p.token(); err != nil {
		return err
	}
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.batches = append(p.f.batches, b)
	for _, r := range b.Patches {
		for i := range p.f.records {
			if p.f.records[i].ID == r.ID {
				p.f.records[i] = r
			}
		}
	}
	return nil
}

func (fakeProvider) Caps() dns.Capabilities { return dns.Capabilities{} }

func connectProvider(b *browser, org, name, tok, account string) (*rpmgrv1.DnsProvider, error) {
	r, err := b.dnsp.ConnectDnsProvider(context.Background(), connect.NewRequest(&rpmgrv1.ConnectDnsProviderRequest{OrgId: org,
		DnsProvider: &rpmgrv1.DnsProvider{Name: name, Kind: &rpmgrv1.DnsProvider_Cloudflare{
			Cloudflare: &rpmgrv1.CloudflareProvider{ApiToken: tok, AccountId: account}}}}))
	if err != nil {
		return nil, err
	}
	return r.Msg.GetDnsProvider(), nil
}

func updateProvider(b *browser, p *rpmgrv1.DnsProvider, etag string, paths ...string) (*rpmgrv1.DnsProvider, error) {
	r, err := b.dnsp.UpdateDnsProvider(context.Background(), connect.NewRequest(&rpmgrv1.UpdateDnsProviderRequest{DnsProvider: p, Etag: etag,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}}))
	if err != nil {
		return nil, err
	}
	return r.Msg.GetDnsProvider(), nil
}

func rotation(id, tok, account string) *rpmgrv1.DnsProvider {
	return &rpmgrv1.DnsProvider{Id: id, Kind: &rpmgrv1.DnsProvider_Cloudflare{
		Cloudflare: &rpmgrv1.CloudflareProvider{ApiToken: tok, AccountId: account}}}
}

// dnsEnv is a signed-in Owner who has stepped up, an org and a provider's fake that knows
// dnsToken1.
func dnsEnv(t *testing.T) (*env, *browser, string) {
	t.Helper()
	e, ada, org, _ := gatewayEnv(t)
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	e.logs.Secret(dnsToken1, dnsToken2, dnsToken3)
	e.dns.know(dnsToken1, fakeDNSToken{})
	return e, ada, org
}

// TestDNS_TokenWriteOnlyAndBaseURLFixed is the API, export and log clause of the test of docs/12
// ("Security testing"); the base-URL clause is TestDNS_TokenWriteOnlyAndBaseURLFixed_BaseURL in
// internal/dns/cloudflare, and the constant is checked here too. A provider's token is returned
// by no response of any method, appears in no audit entry, audit export, manifest export, log line
// or error message, and is stored sealed under the KEK, bound to its row.
func TestDNS_TokenWriteOnlyAndBaseURLFixed(t *testing.T) {
	e, ada, org := dnsEnv(t)
	ctx := context.Background()
	e.dns.know(dnsToken2, fakeDNSToken{expires: e.clock.Add(90 * 24 * time.Hour)})
	e.dns.zones = []dns.Zone{{ID: "z1", Name: "example.com", Status: "active", Type: "full"}}

	var seen strings.Builder
	record := func(m proto.Message, err error) {
		t.Helper()
		if err != nil {
			fmt.Fprintf(&seen, "error: %v\n", err)
			return
		}
		seen.WriteString(protojson.Format(m) + "\n")
	}
	p, err := connectProvider(ada, org, "main", dnsToken1, "")
	record(p, err)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.GetCloudflare().GetApiToken(); got != "" {
		t.Fatalf("the connect response returns the token %q", got)
	}
	g, err := ada.dnsp.GetDnsProvider(ctx, connect.NewRequest(&rpmgrv1.GetDnsProviderRequest{DnsProviderId: p.GetId()}))
	record(g.Msg, err)
	l, err := ada.dnsp.ListDnsProviders(ctx, connect.NewRequest(&rpmgrv1.ListDnsProvidersRequest{OrgId: org}))
	record(l.Msg, err)
	z, err := ada.dnsp.ListProviderZones(ctx, connect.NewRequest(&rpmgrv1.ListProviderZonesRequest{DnsProviderId: p.GetId()}))
	record(z.Msg, err)
	renamed, err := updateProvider(ada, &rpmgrv1.DnsProvider{Id: p.GetId(), Name: "primary"}, "", "name")
	record(renamed, err)
	rotated, err := updateProvider(ada, rotation(p.GetId(), dnsToken2, ""), "", "cloudflare.api_token")
	record(rotated, err)
	if err != nil {
		t.Fatal(err)
	}
	// Refusals say nothing of the token either.
	_, err = connectProvider(ada, org, "bad", dnsToken3, "") // unknown to the provider
	record(nil, err)
	_, err = connectProvider(ada, org, "key", strings.Repeat("a1", 18)+"f", "")
	record(nil, err)
	if err == nil {
		t.Fatal("a Global API Key was accepted")
	}
	_, err = updateProvider(ada, rotation(p.GetId(), dnsToken3, ""), "", "cloudflare.api_token")
	record(nil, err)

	for _, tok := range []string{dnsToken1, dnsToken2, dnsToken3} {
		if strings.Contains(seen.String(), tok) {
			t.Errorf("a response or an error shows the token %s…", tok[:12])
		}
	}

	// The stored value is sealed, bound to the provider's row, and holds the new token.
	row := e.db.Client().DNSProvider.GetX(e.sys, p.GetId())
	for _, tok := range []string{dnsToken1, dnsToken2} {
		if strings.Contains(string(row.CredentialEnc), tok) {
			t.Errorf("the stored value holds %s…", tok[:12])
		}
	}
	opened, err := e.sealer.Open(providers.SecretContext(row.ID), row.CredentialEnc)
	if err != nil || !opened.EqualString(dnsToken2) {
		t.Errorf("the stored token after a rotation: %v", err)
	}
	if _, err := e.sealer.Open(providers.SecretContext("dnp_other"), row.CredentialEnc); err == nil {
		t.Error("the stored token opens for another row")
	}
	if strings.Contains(fmt.Sprintf("%+v %v %#v", row, row, row), dnsToken2) {
		t.Error("the row prints its token")
	}
	if n := e.db.Client().SecretMeta.Query().Where(secretmeta.TableName("dns_providers"), secretmeta.RowID(row.ID)).CountX(e.sys); n != 1 {
		t.Errorf("%d secrets_meta rows for the credential, want 1", n)
	}

	// The audit log, its export, the manifest export and the events.
	stored := everythingStored(t, e)
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		return castore.InitCA(e.sys, tx, e.sealer, "rpmgr-teststor", e.clock.Add(-time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	ca, err := castore.LoadCA(e.sys, e.db, e.sealer, func() time.Time { return e.clock })
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteTx(e.sys, e.db, func(tx *ent.Tx) error {
		_, err := audit.WriteCheckpoints(e.sys, tx, ca.AuditSigner(), e.clock, audit.Pending)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	lines, err := exportOrg(ada, org)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ada.man.ExportManifests(ctx, connect.NewRequest(&rpmgrv1.ExportManifestsRequest{OrgId: org}))
	if err != nil {
		t.Fatal(err)
	}
	exports := stored + strings.Join(lines, "\n") + m.Msg.GetYaml()
	for _, tok := range []string{dnsToken1, dnsToken2, dnsToken3} {
		if strings.Contains(exports, tok) {
			t.Errorf("the audit log or an export shows the token %s…", tok[:12])
		}
	}
	if !strings.Contains(stored, "ConnectDnsProvider") || !strings.Contains(stored, "UpdateDnsProvider") {
		t.Error("the audit log has no entry of the calls")
	}
	if strings.Contains(m.Msg.GetYaml(), p.GetId()) {
		t.Error("a manifest export names a DNS provider")
	}
	// The sink of e.logs fails the test at the end if a line held a registered token, which these
	// calls made sure to log around: a refusal and an unsealing are logged by the service.
	if e.logs.Lines() == 0 {
		t.Error("the services logged nothing, so the log clause proves nothing")
	}

	if cloudflare.BaseURL != "https://api.cloudflare.com/client/v4" {
		t.Errorf("BaseURL %q", cloudflare.BaseURL)
	}
}

// TestDnsProviders_Connect: a connection checks the token at the provider and stores nothing that
// the provider refuses; the answers are fixed words.
func TestDnsProviders_Connect(t *testing.T) {
	e, ada, org := dnsEnv(t)
	count := func() int { return e.db.Client().DNSProvider.Query().CountX(e.sys) }
	e.dns.know(dnsToken2, fakeDNSToken{expires: e.clock.Add(10 * 24 * time.Hour)})

	p, err := connectProvider(ada, org, "  main ", dnsToken1, "")
	if err != nil || p.GetName() != "main" || p.GetStatus() != rpmgrv1.ProviderStatus_PROVIDER_STATUS_OK || p.GetEtag() != "1" ||
		p.GetTokenExpiresAt() != nil || p.GetTokenExpiring() || !strings.HasPrefix(p.GetId(), "dnp_") || p.GetLastCheckTime() == nil {
		t.Fatalf("connected: %v %v", p, err)
	}
	// A token that expires within the warning period is flagged, the account ID is kept.
	soon, err := connectProvider(ada, org, "soon", dnsToken2, "acc-1")
	if err != nil || !soon.GetTokenExpiring() || soon.GetTokenExpiresAt() == nil || soon.GetCloudflare().GetAccountId() != "acc-1" {
		t.Fatalf("an expiring token: %v %v", soon, err)
	}
	if count() != 2 {
		t.Fatalf("%d providers", count())
	}

	for name, c := range map[string]struct {
		name, tok, account string
		want               connect.Code
	}{
		"duplicate name":     {"main", dnsToken1, "", connect.CodeAlreadyExists},
		"empty name":         {" ", dnsToken1, "", connect.CodeInvalidArgument},
		"long name":          {strings.Repeat("n", 65), dnsToken1, "", connect.CodeInvalidArgument},
		"no token":           {"x", "", "", connect.CodeInvalidArgument},
		"token with a space": {"x", "has a space inside", "", connect.CodeInvalidArgument},
		"global key":         {"x", "0123456789abcdef0123456789abcdef01234", "", connect.CodeInvalidArgument},
		"long account":       {"x", dnsToken1, strings.Repeat("a", 65), connect.CodeInvalidArgument},
		"unknown token":      {"x", dnsToken3, "", connect.CodeInvalidArgument},
	} {
		if _, err := connectProvider(ada, org, c.name, c.tok, c.account); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if count() != 2 {
		t.Errorf("a refused connection stored a provider: %d", count())
	}
	if n := e.db.Client().SecretMeta.Query().Where(secretmeta.TableName("dns_providers")).CountX(e.sys); n != 2 {
		t.Errorf("%d secrets_meta rows, want 2", n)
	}

	// The global-key shape is refused without asking the provider.
	before := e.dns.dials()
	if _, err := connectProvider(ada, org, "key", "0123456789ABCDEF0123456789ABCDEF01234", ""); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("a Global API Key: %v", err)
	}
	if e.dns.dials() != before {
		t.Error("a Global API Key was sent to the provider")
	}

	// What the provider says about the token decides.
	for name, c := range map[string]struct {
		t    fakeDNSToken
		want connect.Code
	}{
		"401":          {fakeDNSToken{err: &dns.ProviderError{Status: 401, Err: dns.ErrUnauthorized}}, connect.CodeInvalidArgument},
		"403":          {fakeDNSToken{err: &dns.ProviderError{Status: 403, Err: dns.ErrForbidden}}, connect.CodeInvalidArgument},
		"expired":      {fakeDNSToken{status: "expired"}, connect.CodeInvalidArgument},
		"disabled":     {fakeDNSToken{status: "disabled"}, connect.CodeInvalidArgument},
		"rate limited": {fakeDNSToken{err: dns.RateLimited{Until: e.clock.Add(time.Minute)}}, connect.CodeResourceExhausted},
		"unreachable":  {fakeDNSToken{err: errors.New("dial tcp: connection refused")}, connect.CodeUnavailable},
	} {
		e.dns.know(dnsToken3, c.t)
		_, err := connectProvider(ada, org, "t-"+name, dnsToken3, "")
		if code(err) != c.want || (err != nil && strings.Contains(err.Error(), dnsToken3)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if count() != 2 {
		t.Errorf("a token the provider does not accept was stored: %d", count())
	}
}

// TestDnsProviders_StepUp: connecting, rotating and deleting need a step-up and check nothing at
// the provider without one; a rename and the reads need none.
func TestDnsProviders_StepUp(t *testing.T) {
	e, ada, org := dnsEnv(t)
	ctx := context.Background()
	p, err := connectProvider(ada, org, "main", dnsToken1, "")
	if err != nil {
		t.Fatal(err)
	}
	e.dns.know(dnsToken2, fakeDNSToken{})
	e.clock = e.clock.Add(api.StepUpWindow + time.Second) // the step-up lapses
	dials := e.dns.dials()
	if _, err := connectProvider(ada, org, "second", dnsToken2, ""); reason(err) != api.ReasonStepUpRequired {
		t.Errorf("connect: %v", err)
	}
	if _, err := updateProvider(ada, rotation(p.GetId(), dnsToken2, ""), "", "cloudflare.api_token"); reason(err) != api.ReasonStepUpRequired {
		t.Errorf("rotate: %v", err)
	}
	if _, err := ada.dnsp.DeleteDnsProvider(ctx, connect.NewRequest(&rpmgrv1.DeleteDnsProviderRequest{DnsProviderId: p.GetId()})); reason(err) != api.ReasonStepUpRequired {
		t.Errorf("delete: %v", err)
	}
	if e.dns.dials() != dials {
		t.Error("the provider was asked before the step-up was checked")
	}
	if _, err := updateProvider(ada, &rpmgrv1.DnsProvider{Id: p.GetId(), Name: "renamed"}, "", "name"); err != nil {
		t.Errorf("a rename: %v", err)
	}
	if _, err := ada.dnsp.GetDnsProvider(ctx, connect.NewRequest(&rpmgrv1.GetDnsProviderRequest{DnsProviderId: p.GetId()})); err != nil {
		t.Errorf("get: %v", err)
	}
	if _, err := ada.dnsp.ListProviderZones(ctx, connect.NewRequest(&rpmgrv1.ListProviderZonesRequest{DnsProviderId: p.GetId()})); err != nil {
		t.Errorf("list zones: %v", err)
	}
	row := e.db.Client().DNSProvider.GetX(e.sys, p.GetId())
	if tok, _ := e.sealer.Open(providers.SecretContext(row.ID), row.CredentialEnc); !tok.EqualString(dnsToken1) || row.Name != "renamed" {
		t.Error("a refused rotation changed the token")
	}
}

// TestDnsProviders_Roles: Owners and Admins manage providers; an Operator and a Viewer cannot even
// read them.
func TestDnsProviders_Roles(t *testing.T) {
	e, ada, org := dnsEnv(t)
	ctx := context.Background()
	p, err := connectProvider(ada, org, "main", dnsToken1, "")
	if err != nil {
		t.Fatal(err)
	}
	adm, _ := e.join(t, ada, org, "adm@example.com", "admin")
	if err := adm.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := connectProvider(adm, org, "by-admin", dnsToken1, ""); err != nil {
		t.Errorf("an Admin connects: %v", err)
	}
	if _, err := adm.dnsp.GetDnsProvider(ctx, connect.NewRequest(&rpmgrv1.GetDnsProviderRequest{DnsProviderId: p.GetId()})); err != nil {
		t.Errorf("an Admin reads: %v", err)
	}
	for _, role := range []string{"operator", "viewer"} {
		u, _ := e.join(t, ada, org, role+"@example.com", role)
		if err := u.stepUp(pw, ""); err != nil { // so that only the role can refuse
			t.Fatal(err)
		}
		calls := map[string]func() error{
			"connect": func() error { _, err := connectProvider(u, org, "x", dnsToken1, ""); return err },
			"get": func() error {
				_, err := u.dnsp.GetDnsProvider(ctx, connect.NewRequest(&rpmgrv1.GetDnsProviderRequest{DnsProviderId: p.GetId()}))
				return err
			},
			"list": func() error {
				_, err := u.dnsp.ListDnsProviders(ctx, connect.NewRequest(&rpmgrv1.ListDnsProvidersRequest{OrgId: org}))
				return err
			},
			"rename": func() error {
				_, err := updateProvider(u, &rpmgrv1.DnsProvider{Id: p.GetId(), Name: "x"}, "", "name")
				return err
			},
			"rotate": func() error {
				_, err := updateProvider(u, rotation(p.GetId(), dnsToken1, ""), "", "cloudflare.api_token")
				return err
			},
			"delete": func() error {
				_, err := u.dnsp.DeleteDnsProvider(ctx, connect.NewRequest(&rpmgrv1.DeleteDnsProviderRequest{DnsProviderId: p.GetId()}))
				return err
			},
			"zones": func() error {
				_, err := u.dnsp.ListProviderZones(ctx, connect.NewRequest(&rpmgrv1.ListProviderZonesRequest{DnsProviderId: p.GetId()}))
				return err
			},
		}
		for name, call := range calls {
			if c := code(call()); c != connect.CodePermissionDenied {
				t.Errorf("a %s calls %s: %v", role, name, c)
			}
		}
	}
	if n := e.db.Client().DNSProvider.Query().CountX(e.sys); n != 2 {
		t.Errorf("%d providers, want the 2 made by the Owner and the Admin", n)
	}
}

// TestDnsProviders_OtherOrg: another org's provider, and an org the caller is not in, are NOT_FOUND to every
// method, and nothing changes.
func TestDnsProviders_OtherOrg(t *testing.T) {
	e, ada, org := dnsEnv(t)
	ctx := context.Background()
	p, err := connectProvider(ada, org, "main", dnsToken1, "")
	if err != nil {
		t.Fatal(err)
	}
	orgB := storetest.Org(t, e.db, "org-b")
	bob, _ := e.addOwner(t, orgB, "bob@example.com")
	if err := bob.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	e.dns.know(dnsToken2, fakeDNSToken{})
	id := p.GetId()
	for name, c := range map[string]struct {
		call func() error
		want connect.Code
	}{
		"get": {func() error {
			_, err := bob.dnsp.GetDnsProvider(ctx, connect.NewRequest(&rpmgrv1.GetDnsProviderRequest{DnsProviderId: id}))
			return err
		}, connect.CodeNotFound},
		"rename": {func() error {
			_, err := updateProvider(bob, &rpmgrv1.DnsProvider{Id: id, Name: "x"}, "", "name")
			return err
		}, connect.CodeNotFound},
		"rotate": {func() error {
			_, err := updateProvider(bob, rotation(id, dnsToken2, ""), "", "cloudflare.api_token")
			return err
		}, connect.CodeNotFound},
		"delete": {func() error {
			_, err := bob.dnsp.DeleteDnsProvider(ctx, connect.NewRequest(&rpmgrv1.DeleteDnsProviderRequest{DnsProviderId: id}))
			return err
		}, connect.CodeNotFound},
		"zones": {func() error {
			_, err := bob.dnsp.ListProviderZones(ctx, connect.NewRequest(&rpmgrv1.ListProviderZonesRequest{DnsProviderId: id}))
			return err
		}, connect.CodeNotFound},
		"connect in org a": {func() error { _, err := connectProvider(bob, org, "x", dnsToken1, ""); return err }, connect.CodeNotFound},
		"list org a": {func() error {
			_, err := bob.dnsp.ListDnsProviders(ctx, connect.NewRequest(&rpmgrv1.ListDnsProvidersRequest{OrgId: org}))
			return err
		}, connect.CodeNotFound},
	} {
		if got := code(c.call()); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	row := e.db.Client().DNSProvider.GetX(e.sys, id)
	if tok, _ := e.sealer.Open(providers.SecretContext(id), row.CredentialEnc); !tok.EqualString(dnsToken1) || row.Name != "main" || row.Version != 1 {
		t.Error("another org's call changed the provider")
	}
	// Bob's own list is empty, and his provider of the same name is possible: names are per org.
	if l, err := bob.dnsp.ListDnsProviders(ctx, connect.NewRequest(&rpmgrv1.ListDnsProvidersRequest{OrgId: orgB})); err != nil || len(l.Msg.GetDnsProviders()) != 0 {
		t.Errorf("bob lists %v: %v", l, err)
	}
	if _, err := connectProvider(bob, orgB, "main", dnsToken1, ""); err != nil {
		t.Errorf("the same name in another org: %v", err)
	}
}

// TestDnsProviders_Rotate: a rotation checks the new token first and replaces the old one in the
// same row, so the ID, the name and the zones imported from it stay; a token the provider refuses
// changes nothing.
func TestDnsProviders_Rotate(t *testing.T) {
	e, ada, org := dnsEnv(t)
	e.dns.know(dnsToken2, fakeDNSToken{expires: e.clock.Add(5 * 24 * time.Hour)})
	zones := map[string]int{}
	e.dnsp.ZoneCount = func(_ context.Context, _ *ent.Tx, id string) (int, error) { return zones[id], nil }
	p, err := connectProvider(ada, org, "main", dnsToken1, "")
	if err != nil {
		t.Fatal(err)
	}
	zones[p.GetId()] = 3 // three zones imported from it
	opened := func() string {
		row := e.db.Client().DNSProvider.GetX(e.sys, p.GetId())
		tok, err := e.sealer.Open(providers.SecretContext(row.ID), row.CredentialEnc)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{dnsToken1, dnsToken2, dnsToken3} {
			if tok.EqualString(k) {
				return k
			}
		}
		return "unknown"
	}

	// Refused: a token the provider does not know, an empty one, a Global API Key, an account ID
	// without a token, an empty mask and a stale etag.
	for name, c := range map[string]struct {
		do   func() error
		want connect.Code
	}{
		"unknown token": {func() error {
			_, err := updateProvider(ada, rotation(p.GetId(), dnsToken3, ""), "", "cloudflare.api_token")
			return err
		}, connect.CodeInvalidArgument},
		"empty token": {func() error {
			_, err := updateProvider(ada, rotation(p.GetId(), "", ""), "", "cloudflare.api_token")
			return err
		}, connect.CodeInvalidArgument},
		"global key": {func() error {
			_, err := updateProvider(ada, rotation(p.GetId(), "0123456789abcdef0123456789abcdef01234", ""), "", "cloudflare.api_token")
			return err
		}, connect.CodeInvalidArgument},
		"account without token": {func() error {
			_, err := updateProvider(ada, rotation(p.GetId(), "", "acc-9"), "", "cloudflare.account_id")
			return err
		}, connect.CodeInvalidArgument},
		"empty mask": {func() error { _, err := updateProvider(ada, rotation(p.GetId(), dnsToken2, ""), ""); return err }, connect.CodeInvalidArgument},
		"other field": {func() error {
			_, err := updateProvider(ada, &rpmgrv1.DnsProvider{Id: p.GetId(), LastError: "x"}, "", "last_error")
			return err
		}, connect.CodeInvalidArgument},
		"empty name": {func() error {
			_, err := updateProvider(ada, &rpmgrv1.DnsProvider{Id: p.GetId()}, "", "name")
			return err
		}, connect.CodeInvalidArgument},
		"stale etag": {func() error {
			_, err := updateProvider(ada, rotation(p.GetId(), dnsToken2, ""), "7", "cloudflare.api_token")
			return err
		}, connect.CodeFailedPrecondition},
	} {
		if got := code(c.do()); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	if opened() != dnsToken1 || e.db.Client().DNSProvider.GetX(e.sys, p.GetId()).Version != 1 {
		t.Fatal("a refused rotation changed the provider")
	}

	r, err := updateProvider(ada, rotation(p.GetId(), dnsToken2, "acc-2"), "1", "cloudflare.api_token", "cloudflare.account_id")
	if err != nil {
		t.Fatal(err)
	}
	if r.GetId() != p.GetId() || r.GetName() != "main" || r.GetEtag() != "2" || !r.GetTokenExpiring() || r.GetCloudflare().GetAccountId() != "acc-2" ||
		r.GetStatus() != rpmgrv1.ProviderStatus_PROVIDER_STATUS_OK {
		t.Fatalf("rotated: %v", r)
	}
	if opened() != dnsToken2 {
		t.Error("the new token is not stored")
	}
	if n, _ := e.dnsp.ZoneCount(context.Background(), nil, p.GetId()); n != 3 {
		t.Errorf("the zones of the provider: %d", n)
	}
	if n := e.db.Client().DNSProvider.Query().CountX(e.sys); n != 1 {
		t.Errorf("a rotation made %d rows", n)
	}
	// A new token without an expiry clears the old one's.
	e.dns.know(dnsToken3, fakeDNSToken{})
	if r, err = updateProvider(ada, rotation(p.GetId(), dnsToken3, ""), "", "cloudflare.api_token"); err != nil || r.GetTokenExpiresAt() != nil || r.GetTokenExpiring() {
		t.Errorf("a token without an expiry: %v %v", r, err)
	}
	// A rename keeps the token and bumps the etag.
	if r, err = updateProvider(ada, &rpmgrv1.DnsProvider{Id: p.GetId(), Name: "renamed"}, "", "name"); err != nil || r.GetName() != "renamed" || opened() != dnsToken3 {
		t.Errorf("a rename: %v %v", r, err)
	}
}

// TestDnsProviders_Delete: a provider with zones stays, one without goes with the record of its
// sealed token, and the etag is checked.
func TestDnsProviders_Delete(t *testing.T) {
	e, ada, org := dnsEnv(t)
	ctx := context.Background()
	zones := 2
	e.dnsp.ZoneCount = func(context.Context, *ent.Tx, string) (int, error) { return zones, nil }
	p, err := connectProvider(ada, org, "main", dnsToken1, "")
	if err != nil {
		t.Fatal(err)
	}
	// The provider has taken requests, so its budget row exists.
	if err := e.dnsp.Budget.Take(e.sys, p.GetId(), budget.Job); err != nil {
		t.Fatal(err)
	}
	del := func(etag string) error {
		_, err := ada.dnsp.DeleteDnsProvider(ctx, connect.NewRequest(&rpmgrv1.DeleteDnsProviderRequest{DnsProviderId: p.GetId(), Etag: etag}))
		return err
	}
	if err := del(""); code(err) != connect.CodeFailedPrecondition || reason(err) != apisvc.ReasonDependantsExist {
		t.Fatalf("a provider with zones: %v", err)
	}
	zones = 0
	if err := del("9"); code(err) != connect.CodeFailedPrecondition || reason(err) != api.ReasonEtagMismatch {
		t.Fatalf("a stale etag: %v", err)
	}
	if err := del("1"); err != nil {
		t.Fatal(err)
	}
	if n := e.db.Client().DNSProvider.Query().CountX(e.sys); n != 0 {
		t.Error("the provider is still there")
	}
	if n := e.db.Client().DNSRateBudget.Query().CountX(e.sys); n != 0 {
		t.Errorf("%d rate budgets outlive the provider", n)
	}
	if n := e.db.Client().SecretMeta.Query().Where(secretmeta.TableName("dns_providers")).CountX(e.sys); n != 0 {
		t.Errorf("%d secrets_meta rows outlive the provider", n)
	}
	if err := del(""); code(err) != connect.CodeNotFound {
		t.Errorf("a second delete: %v", err)
	}
	// Without a ZoneCount, as before zones exist, nothing blocks a delete.
	e.dnsp.ZoneCount = nil
	q, err := connectProvider(ada, org, "again", dnsToken1, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.dnsp.DeleteDnsProvider(ctx, connect.NewRequest(&rpmgrv1.DeleteDnsProviderRequest{DnsProviderId: q.GetId()})); err != nil {
		t.Error(err)
	}
}

// TestDnsProviders_ListZones: the zones are read live from the provider, by name; what the
// provider answers maps to a status code, in fixed words.
func TestDnsProviders_ListZones(t *testing.T) {
	e, ada, org := dnsEnv(t)
	ctx := context.Background()
	p, err := connectProvider(ada, org, "main", dnsToken1, "")
	if err != nil {
		t.Fatal(err)
	}
	e.dns.zones = []dns.Zone{{ID: "z2", Name: "b.example", Status: "pending", Type: "full"}, {ID: "z1", Name: "a.example", Status: "active", Type: "partial"}}
	list := func() (*rpmgrv1.ListProviderZonesResponse, error) {
		r, err := ada.dnsp.ListProviderZones(ctx, connect.NewRequest(&rpmgrv1.ListProviderZonesRequest{DnsProviderId: p.GetId()}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	r, err := list()
	if err != nil || len(r.GetZones()) != 2 || r.GetZones()[0].GetName() != "a.example" || r.GetZones()[0].GetType() != "partial" ||
		r.GetZones()[1].GetId() != "z2" || r.GetZones()[1].GetStatus() != "pending" {
		t.Fatalf("zones: %v %v", r, err)
	}
	for name, c := range map[string]struct {
		err  error
		want connect.Code
	}{
		"revoked":      {&dns.ProviderError{Status: 401, Err: dns.ErrUnauthorized}, connect.CodeFailedPrecondition},
		"forbidden":    {&dns.ProviderError{Status: 403, Err: dns.ErrForbidden}, connect.CodeFailedPrecondition},
		"rate limited": {dns.RateLimited{Until: e.clock.Add(time.Minute)}, connect.CodeResourceExhausted},
		"unreachable":  {errors.New("dial tcp 198.51.100.1:443: i/o timeout"), connect.CodeUnavailable},
	} {
		e.dns.know(dnsToken1, fakeDNSToken{err: c.err})
		if _, err := list(); code(err) != c.want || strings.Contains(fmt.Sprint(err), "198.51.100.1") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ada.dnsp.ListProviderZones(ctx, connect.NewRequest(&rpmgrv1.ListProviderZonesRequest{DnsProviderId: "dnp_missing"})); code(err) != connect.CodeNotFound {
		t.Errorf("a missing provider: %v", err)
	}
	// A 429 of the provider blocks the provider's budget for the DNS job's replicas as well.
	if st, err := e.dnsp.Budget.Status(e.sys, p.GetId()); err != nil || st.Blocked != time.Minute {
		t.Errorf("the 429 blocks the budget for %v, %v; want a minute", st.Blocked, err)
	}
}

// TestDnsProviders_ListPages: providers come by ID, page by page, with a token that only fits the
// same request.
func TestDnsProviders_ListPages(t *testing.T) {
	e, ada, org := dnsEnv(t)
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c"} {
		if _, err := connectProvider(ada, org, n, dnsToken1, ""); err != nil {
			t.Fatal(err)
		}
	}
	p1, err := ada.dnsp.ListDnsProviders(ctx, connect.NewRequest(&rpmgrv1.ListDnsProvidersRequest{OrgId: org, PageSize: 2}))
	if err != nil || len(p1.Msg.GetDnsProviders()) != 2 || p1.Msg.GetNextPageToken() == "" {
		t.Fatalf("page 1: %v %v", p1, err)
	}
	p2, err := ada.dnsp.ListDnsProviders(ctx, connect.NewRequest(&rpmgrv1.ListDnsProvidersRequest{OrgId: org, PageSize: 2, PageToken: p1.Msg.GetNextPageToken()}))
	if err != nil || len(p2.Msg.GetDnsProviders()) != 1 || p2.Msg.GetDnsProviders()[0].GetName() != "c" || p2.Msg.GetNextPageToken() != "" {
		t.Fatalf("page 2: %v %v", p2, err)
	}
	if _, err := ada.dnsp.ListDnsProviders(ctx, connect.NewRequest(&rpmgrv1.ListDnsProvidersRequest{OrgId: org, PageToken: "forged"})); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a forged page token: %v", err)
	}
	if _, err := ada.dnsp.ListDnsProviders(ctx, connect.NewRequest(&rpmgrv1.ListDnsProvidersRequest{OrgId: org, PageSize: -1})); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a negative page size: %v", err)
	}
	_ = e
}
