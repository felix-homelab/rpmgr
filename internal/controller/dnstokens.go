// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"log/slog"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsprovider"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
)

// DNSTokenOptions configure the DNS token check.
type DNSTokenOptions struct {
	DB     *store.DB
	Leases *lease.Leases
	Sealer *secret.Sealer
	// Dial makes the client of a provider account; nil is providers.Dial.
	Dial providers.Dialer
	// Delegation finds the public nameservers of a zone's domain; nil checks no delegation.
	Delegation domains.DelegationLookup
	Now        func() time.Time
	Logger     *slog.Logger
}

// DNSTokenJob is the singleton job that checks every connected DNS provider's token
// (docs/15-dns.md, "Timers and limits"): whether the provider still accepts it, and when it
// expires. It runs under its lease, and each result is recorded in a fenced transaction. A
// provider that cannot be reached, or that rate-limits the check, gives no verdict and changes
// nothing: only a refusal marks a provider invalid. The job is started with the other DNS jobs.
func DNSTokenJob(o DNSTokenOptions) lease.Job {
	return lease.Job{Name: "dns-tokens", Reason: "check the tokens of the dns providers", Every: providers.CheckEvery,
		Run: func(ctx context.Context, l lease.Lease) error { return checkDNSTokens(ctx, o, l) }}
}

func checkDNSTokens(ctx context.Context, o DNSTokenOptions, l lease.Lease) error {
	rows, err := o.DB.ReadClient().DNSProvider.Query().Order(ent.Asc(dnsprovider.FieldID)).All(ctx)
	if err != nil {
		return err
	}
	dial := o.Dial
	if dial == nil {
		dial = providers.Dial
	}
	for _, r := range rows {
		tok, err := o.Sealer.Open(providers.SecretContext(r.ID), r.CredentialEnc)
		if err != nil {
			// The error comes from the KEK's unsealing and names no secret.
			o.warn(ctx, "a dns provider's token cannot be opened", r.ID, "err", err)
			continue
		}
		p, err := dial(string(r.Kind), r.AccountID, tok)
		if err != nil {
			o.warn(ctx, "a dns provider's client cannot be made", r.ID)
			continue
		}
		out := providers.Check(ctx, p)
		if out.Err != nil {
			o.warn(ctx, "a dns provider's token could not be checked", r.ID, "err", out.Err)
			continue
		}
		err = store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
			if err := o.Leases.Fence(ctx, tx, l); err != nil {
				return err
			}
			u := tx.DNSProvider.UpdateOneID(r.ID).Where(dnsprovider.Version(r.Version)).SetLastCheckedAt(o.Now().UTC())
			status, reason := dnsprovider.StatusOk, ""
			if !out.OK {
				status, reason = dnsprovider.StatusInvalid, out.Reason
			}
			u.SetStatus(status).SetLastError(reason).SetNillableTokenExpiresAt(out.Expires)
			if out.Expires == nil {
				u.ClearTokenExpiresAt()
			}
			if _, err := u.Save(ctx); err != nil {
				return err
			}
			return nil
		})
		if ent.IsNotFound(err) {
			continue // changed or deleted since it was read; the next pass sees it
		}
		if err != nil {
			return err
		}
		if out.OK && o.Delegation != nil {
			if err := checkDelegations(ctx, o, l, p, r.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkDelegations refreshes, for the imported zones of a provider whose token is valid, the
// nameservers the provider assigned and whether the public DNS delegates the domain to them
// (docs/15-dns.md, "Delegation"). A provider that cannot be listed, or a lookup that fails, gives
// no verdict: a zone keeps what it had, or is unknown.
func checkDelegations(ctx context.Context, o DNSTokenOptions, l lease.Lease, p dns.Provider, providerID string) error {
	rows, err := o.DB.ReadClient().DNSZone.Query().Where(dnszone.DNSProviderID(providerID)).Order(ent.Asc(dnszone.FieldID)).All(ctx)
	if err != nil || len(rows) == 0 {
		return err
	}
	listed, err := p.ListZones(ctx)
	if err != nil {
		o.warn(ctx, "a dns provider's zones could not be listed", providerID, "err", err)
		return nil
	}
	assigned := map[string][]string{}
	for _, z := range listed {
		assigned[z.ID] = z.NameServers
	}
	for _, z := range rows {
		ns, ok := assigned[z.ProviderZoneID]
		if !ok {
			continue // not listed any more: nothing to compare with
		}
		state, public := domains.CheckDelegation(ctx, o.Delegation, z.Name, ns)
		err := store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
			if err := o.Leases.Fence(ctx, tx, l); err != nil {
				return err
			}
			_, err := tx.DNSZone.UpdateOneID(z.ID).Where(dnszone.Version(z.Version)).SetAssignedNameservers(ns).
				SetDelegationState(state).SetDelegationNameservers(public).SetDelegationCheckedAt(o.Now().UTC()).Save(ctx)
			return err
		})
		if err != nil && !ent.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (o DNSTokenOptions) warn(ctx context.Context, msg, id string, args ...any) {
	if o.Logger != nil {
		o.Logger.WarnContext(ctx, msg, append([]any{"dns_provider", id}, args...)...)
	}
}
