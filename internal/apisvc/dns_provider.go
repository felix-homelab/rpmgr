// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsprovider"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
)

// DnsProviders is DnsProviderService (docs/07-api.md; docs/15-dns.md, "Connecting, importing and
// disconnecting"). Its methods run in the org scope the interceptor gives them. The provider's
// token is sealed under the KEK, goes in with a connection or a rotation, and is read back by
// nothing but the calls to the provider that it authorises: no response, audit entry or log line
// holds it, and no error message quotes it.
type DnsProviders struct {
	rpmgrv1connect.UnimplementedDnsProviderServiceHandler
	DB     *store.DB
	API    *api.Server
	Sealer *secret.Sealer
	// Dial makes the client of a provider account; nil is providers.Dial, the compiled-in API.
	Dial providers.Dialer
	// ZoneCount returns how many managed zones are imported from a provider, read in tx; nil
	// counts the rows of dns_zones. DeleteDnsProvider is refused while it is not zero.
	ZoneCount func(ctx context.Context, tx *ent.Tx, providerID string) (int, error)
	Logger    *slog.Logger
	Now       func() time.Time
}

// providerFields are the fields UpdateDnsProvider may change.
var providerFields = []string{"name", "cloudflare.api_token", "cloudflare.account_id"}

func (d *DnsProviders) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// log records what was done to a provider: its ID and org, never the token.
func (d *DnsProviders) log(ctx context.Context, msg string, args ...any) {
	if d.Logger != nil {
		d.Logger.InfoContext(ctx, msg, args...)
	}
}

func (d *DnsProviders) dial(kind, account string, tok secret.Value) (dns.Provider, error) {
	if d.Dial != nil {
		return d.Dial(kind, account, tok)
	}
	return providers.Dial(kind, account, tok)
}

// providerOf is the API's view of a row: never the credential.
func (d *DnsProviders) providerOf(r *ent.DNSProvider) *rpmgrv1.DnsProvider {
	p := &rpmgrv1.DnsProvider{Id: r.ID, Name: r.Name, Etag: etagOf(r.Version), LastError: r.LastError,
		Status:        rpmgrv1.ProviderStatus_PROVIDER_STATUS_OK,
		TokenExpiring: providers.Expiring(r.TokenExpiresAt, d.now()),
		Kind:          &rpmgrv1.DnsProvider_Cloudflare{Cloudflare: &rpmgrv1.CloudflareProvider{AccountId: r.AccountID}}}
	if r.Status == dnsprovider.StatusInvalid {
		p.Status = rpmgrv1.ProviderStatus_PROVIDER_STATUS_INVALID
	}
	if r.TokenExpiresAt != nil {
		p.TokenExpiresAt = timestamppb.New(*r.TokenExpiresAt)
	}
	if r.LastCheckedAt != nil {
		p.LastCheckTime = timestamppb.New(*r.LastCheckedAt)
	}
	return p
}

// verify checks a token at the provider before it is stored or replaces another, and maps what the
// provider says to the API's errors. None of them quotes the provider's words or the token.
func (d *DnsProviders) verify(ctx context.Context, account, token string) (providers.Outcome, error) {
	if err := cloudflare.CheckToken(token); err != nil {
		return providers.Outcome{}, invalid(err)
	}
	p, err := d.dial(providers.KindCloudflare, account, secret.New(token))
	if err != nil {
		return providers.Outcome{}, connect.NewError(connect.CodeInternal, errors.New("apisvc: the provider client cannot be made"))
	}
	out := providers.Check(ctx, p)
	if out.Err != nil {
		d.log(ctx, "a dns provider could not check a token", "err", out.Err)
		return out, providerError(out.Err)
	}
	if !out.OK {
		d.log(ctx, "a dns provider refused a token", "reason", out.Reason)
		return out, invalid(errors.New("apisvc: " + out.Reason))
	}
	return out, nil
}

// providerError maps a failed call to a provider to a status code, in fixed words.
func providerError(err error) error {
	var rl dns.RateLimited
	switch {
	case errors.Is(err, dns.ErrUnauthorized), errors.Is(err, dns.ErrForbidden):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("apisvc: the provider does not accept the token"))
	case errors.As(err, &rl):
		return connect.NewError(connect.CodeResourceExhausted, errors.New("apisvc: the provider rate-limits requests; retry later"))
	default:
		return connect.NewError(connect.CodeUnavailable, errors.New("apisvc: the provider cannot be reached"))
	}
}

// ConnectDnsProvider implements DnsProviderService. The token is checked at the provider first; a
// token it refuses is not stored.
func (d *DnsProviders) ConnectDnsProvider(ctx context.Context, req *connect.Request[rpmgrv1.ConnectDnsProviderRequest]) (
	*connect.Response[rpmgrv1.ConnectDnsProviderResponse], error) {
	m := req.Msg
	in := m.GetDnsProvider()
	name := strings.TrimSpace(in.GetName())
	cf := in.GetCloudflare()
	switch {
	case name == "" || len(name) > 64:
		return nil, invalid(errors.New("apisvc: the name must be 1 to 64 characters"))
	case cf == nil:
		return nil, invalid(errors.New("apisvc: the kind of the provider is not set"))
	case len(cf.GetAccountId()) > 64:
		return nil, invalid(errors.New("apisvc: account_id is too long"))
	}
	tok := secret.New(cf.GetApiToken())
	out, err := d.verify(ctx, cf.GetAccountId(), cf.GetApiToken())
	if err != nil {
		return nil, err
	}
	id := ids.New("dnp")
	var row *ent.DNSProvider
	err = store.WriteTx(ctx, d.DB, func(tx *ent.Tx) error {
		sealed, err := store.Seal(ctx, tx, d.Sealer, providers.SecretContext(id), tok)
		if err != nil {
			return err
		}
		c := tx.DNSProvider.Create().SetID(id).SetOrgID(m.GetOrgId()).SetKind(dnsprovider.KindCloudflare).SetName(name).
			SetCredentialEnc(sealed).SetAccountID(cf.GetAccountId()).SetLastCheckedAt(d.now().UTC()).
			SetNillableTokenExpiresAt(out.Expires)
		row, err = c.Save(ctx)
		return err
	})
	if err != nil {
		return nil, storeError(err)
	}
	d.log(ctx, "a dns provider was connected", "dns_provider", row.ID, "org", row.OrgID, "kind", row.Kind)
	return connect.NewResponse(&rpmgrv1.ConnectDnsProviderResponse{DnsProvider: d.providerOf(row)}), nil
}

// GetDnsProvider implements DnsProviderService.
func (d *DnsProviders) GetDnsProvider(ctx context.Context, req *connect.Request[rpmgrv1.GetDnsProviderRequest]) (
	*connect.Response[rpmgrv1.GetDnsProviderResponse], error) {
	row, err := d.DB.ReadClient().DNSProvider.Get(ctx, req.Msg.GetDnsProviderId())
	if err != nil {
		return nil, storeError(err)
	}
	return connect.NewResponse(&rpmgrv1.GetDnsProviderResponse{DnsProvider: d.providerOf(row)}), nil
}

// ListDnsProviders implements DnsProviderService.
func (d *DnsProviders) ListDnsProviders(ctx context.Context, req *connect.Request[rpmgrv1.ListDnsProvidersRequest]) (
	*connect.Response[rpmgrv1.ListDnsProvidersResponse], error) {
	m := req.Msg
	size, err := api.PageSize(m.GetPageSize())
	if err != nil {
		return nil, err
	}
	after, err := d.API.AfterPage(m.GetPageToken(), m)
	if err != nil {
		return nil, err
	}
	q := d.DB.ReadClient().DNSProvider.Query().Where(dnsprovider.OrgID(m.GetOrgId())).Order(ent.Asc(dnsprovider.FieldID)).Limit(size + 1)
	if after != "" {
		q.Where(dnsprovider.IDGT(after))
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, storeError(err)
	}
	out := &rpmgrv1.ListDnsProvidersResponse{}
	if len(rows) > size {
		rows = rows[:size]
		out.NextPageToken = d.API.PageToken(rows[size-1].ID, m)
	}
	for _, r := range rows {
		out.DnsProviders = append(out.DnsProviders, d.providerOf(r))
	}
	return connect.NewResponse(out), nil
}

// UpdateDnsProvider implements DnsProviderService: a rename, or a rotation, which checks the new
// token at the provider and then replaces the old one in the same row, so the zones imported from
// the provider and everything that depends on it stay. A rotation needs a step-up.
func (d *DnsProviders) UpdateDnsProvider(ctx context.Context, req *connect.Request[rpmgrv1.UpdateDnsProviderRequest]) (
	*connect.Response[rpmgrv1.UpdateDnsProviderResponse], error) {
	m := req.Msg
	id := m.GetDnsProvider().GetId()
	cur, err := d.DB.ReadClient().DNSProvider.Get(ctx, id)
	if err != nil {
		return nil, storeError(err)
	}
	if err := api.CheckEtag(m.GetEtag(), cur.Version, d.providerOf(cur)); err != nil {
		return nil, err
	}
	next := proto.Clone(d.providerOf(cur)).(*rpmgrv1.DnsProvider)
	if err := api.ApplyMask(next, m.GetDnsProvider(), m.GetUpdateMask(), providerFields...); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(next.GetName())
	if name == "" || len(name) > 64 {
		return nil, invalid(errors.New("apisvc: the name must be 1 to 64 characters"))
	}
	rotate := slices.Contains(m.GetUpdateMask().GetPaths(), "cloudflare.api_token")
	if !rotate && slices.Contains(m.GetUpdateMask().GetPaths(), "cloudflare.account_id") {
		return nil, invalid(errors.New("apisvc: the account is set together with a new token"))
	}
	var tok secret.Value
	var out providers.Outcome
	if rotate {
		if err := api.RequireStepUp(ctx, d.now()); err != nil {
			return nil, err
		}
		tok = secret.New(next.GetCloudflare().GetApiToken())
		if out, err = d.verify(ctx, next.GetCloudflare().GetAccountId(), next.GetCloudflare().GetApiToken()); err != nil {
			return nil, err
		}
	}
	var row *ent.DNSProvider
	err = store.WriteTx(ctx, d.DB, func(tx *ent.Tx) error {
		u := tx.DNSProvider.UpdateOneID(id).Where(dnsprovider.Version(cur.Version)).SetName(name)
		if rotate {
			sealed, err := store.Seal(ctx, tx, d.Sealer, providers.SecretContext(id), tok)
			if err != nil {
				return err
			}
			u.SetCredentialEnc(sealed).SetAccountID(next.GetCloudflare().GetAccountId()).SetStatus(dnsprovider.StatusOk).
				SetLastError("").SetLastCheckedAt(d.now().UTC()).SetNillableTokenExpiresAt(out.Expires)
			if out.Expires == nil {
				u.ClearTokenExpiresAt()
			}
		}
		row, err = u.Save(ctx)
		return err
	})
	if err != nil {
		return nil, storeError(err)
	}
	if rotate {
		d.log(ctx, "a dns provider's token was rotated", "dns_provider", row.ID, "org", row.OrgID)
	}
	return connect.NewResponse(&rpmgrv1.UpdateDnsProviderResponse{DnsProvider: d.providerOf(row)}), nil
}

// DeleteDnsProvider implements DnsProviderService: the provider and its token go together, and a
// provider that zones are imported from stays.
func (d *DnsProviders) DeleteDnsProvider(ctx context.Context, req *connect.Request[rpmgrv1.DeleteDnsProviderRequest]) (
	*connect.Response[rpmgrv1.DeleteDnsProviderResponse], error) {
	id := req.Msg.GetDnsProviderId()
	err := store.WriteTx(ctx, d.DB, func(tx *ent.Tx) error {
		cur, err := tx.DNSProvider.Get(ctx, id)
		if err != nil {
			return err
		}
		if err := api.CheckEtag(req.Msg.GetEtag(), cur.Version, d.providerOf(cur)); err != nil {
			return err
		}
		count := d.ZoneCount
		if count == nil {
			count = func(ctx context.Context, tx *ent.Tx, id string) (int, error) {
				return tx.DNSZone.Query().Where(dnszone.DNSProviderID(id)).Count(ctx)
			}
		}
		n, err := count(ctx, tx, id)
		if err != nil {
			return err
		}
		if n > 0 {
			return dependants("zones are imported from the provider; remove them first")
		}
		if err := tx.DNSProvider.DeleteOneID(id).Where(dnsprovider.Version(cur.Version)).Exec(ctx); err != nil {
			return err
		}
		return store.ForgetSealed(ctx, tx, providers.SecretContext(id))
	})
	if err != nil {
		return nil, storeError(err)
	}
	d.log(ctx, "a dns provider was deleted", "dns_provider", id)
	return connect.NewResponse(&rpmgrv1.DeleteDnsProviderResponse{}), nil
}

// client opens the token of a stored provider and makes the client of its account. Its errors are
// fixed words: none quotes the token.
func (d *DnsProviders) client(ctx context.Context, row *ent.DNSProvider) (dns.Provider, error) {
	tok, err := d.Sealer.Open(providers.SecretContext(row.ID), row.CredentialEnc)
	if err != nil {
		if d.Logger != nil {
			d.Logger.ErrorContext(ctx, "a dns provider's token cannot be opened", "dns_provider", row.ID)
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("apisvc: the stored token cannot be opened"))
	}
	p, err := d.dial(string(row.Kind), row.AccountID, tok)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("apisvc: the provider client cannot be made"))
	}
	return p, nil
}

// ListProviderZones implements DnsProviderService: the zones the token sees, read live.
func (d *DnsProviders) ListProviderZones(ctx context.Context, req *connect.Request[rpmgrv1.ListProviderZonesRequest]) (
	*connect.Response[rpmgrv1.ListProviderZonesResponse], error) {
	row, err := d.DB.ReadClient().DNSProvider.Get(ctx, req.Msg.GetDnsProviderId())
	if err != nil {
		return nil, storeError(err)
	}
	p, err := d.client(ctx, row)
	if err != nil {
		return nil, err
	}
	zones, err := p.ListZones(ctx)
	if err != nil {
		return nil, providerError(err)
	}
	slices.SortFunc(zones, func(a, b dns.Zone) int { return strings.Compare(a.Name, b.Name) })
	out := &rpmgrv1.ListProviderZonesResponse{}
	for _, z := range zones {
		out.Zones = append(out.Zones, &rpmgrv1.ProviderZone{Id: z.ID, Name: z.Name, Status: z.Status, Type: z.Type})
	}
	return connect.NewResponse(out), nil
}
