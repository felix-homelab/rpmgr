// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/cfranges"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The results the Cloudflare range refresh counts (rpmgr_dns_cloudflare_ranges_refresh_total).
const (
	RangesOK       = "ok"       // a list was accepted and stored
	RangesRejected = "rejected" // a list arrived, but its sanity bounds failed
	RangesFailed   = "failed"   // Cloudflare could not be reached or answered no list
)

// CloudflareRangesOptions configure the Cloudflare range refresh job.
type CloudflareRangesOptions struct {
	DB     *store.DB
	Leases *lease.Leases
	Now    func() time.Time
	Logger *slog.Logger
	// Client fetches the list; nil is cfranges.Client with the proxy of the environment, which
	// the caller passes as Proxy.
	Client *http.Client
	// URL is where the list is fetched; "" is cfranges.URL.
	URL string
	// Result, if set, counts each attempt's result.
	Result func(result string)
}

// CloudflareRangesJob refreshes Cloudflare's IP ranges under a lease, while the instance setting
// cloudflare_ip_refresh is on (docs/15-dns.md, "Proxied HTTP routes"): it fetches them when the
// stored list is a day old, and again an hour after a failure or a rejected list. An accepted
// list is stored in a configuration transaction fenced by the lease, so gateways get it in their
// next snapshots; a rejected one changes nothing, and the list in use stays.
func CloudflareRangesJob(o CloudflareRangesOptions) lease.Job {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Client == nil {
		o.Client = cfranges.Client(nil)
	}
	if o.URL == "" {
		o.URL = cfranges.URL
	}
	return lease.Job{Name: "cloudflare-ranges", Reason: "refresh the Cloudflare IP ranges", Every: cfranges.RetryEvery,
		Run: func(ctx context.Context, l lease.Lease) error { return refreshCloudflareRanges(ctx, o, l) }}
}

func refreshCloudflareRanges(ctx context.Context, o CloudflareRangesOptions, l lease.Lease) error {
	count := func(r string) {
		if o.Result != nil && ctx.Err() == nil {
			o.Result(r)
		}
	}
	inst, _, err := settings.Instance(ctx, o.DB.ReadClient())
	if err != nil {
		return err
	}
	now := o.Now().UTC()
	current := cfranges.FromSettings(inst)
	if !inst.GetCloudflareIpRefresh() || (inst.GetCloudflareIpRanges().GetRefreshedAt() != nil && current.Age(now) < cfranges.RefreshEvery) {
		return nil
	}
	next, err := cfranges.Fetch(ctx, o.Client, o.URL, now)
	if err == nil {
		err = cfranges.Accept(current, next)
	}
	switch {
	case err != nil && ctx.Err() != nil:
		return nil // a shutdown, not a failed refresh
	case errors.Is(err, cfranges.ErrRejected):
		count(RangesRejected)
		o.Logger.Warn("cloudflare ip ranges: list rejected; the list in use stays", "error", err)
		return err
	case err != nil:
		count(RangesFailed)
		o.Logger.Warn("cloudflare ip ranges: refresh failed; the list in use stays", "error", err)
		return err
	}
	if _, err := settings.RecordCloudflareRanges(ctx, o.DB, next.Proto(), func(tx *ent.Tx) error { return o.Leases.Fence(ctx, tx, l) }); err != nil {
		return err
	}
	count(RangesOK)
	o.Logger.Info("cloudflare ip ranges refreshed", "ipv4", len(next.IPv4), "ipv6", len(next.IPv6))
	return nil
}

// cloudflareRangesStale reports whether the stale alert's condition holds at now: the refresh is
// on, the list in use is older than cfranges.StaleAfter and a proxied route needs it.
func cloudflareRangesStale(inst *rpmgrv1.InstanceSettings, proxiedRoutes bool, now time.Time) bool {
	return proxiedRoutes && inst.GetCloudflareIpRefresh() && cfranges.FromSettings(inst).Age(now) > cfranges.StaleAfter
}
