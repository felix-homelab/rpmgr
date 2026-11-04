// SPDX-License-Identifier: Apache-2.0

// Package job is the DNS job (docs/15-dns.md, "The DNS job"): under the `dns` lease it reads the
// sources of each managed zone, compiles the records they want, lists the provider's, plans, applies
// the plan through the ownership ledger (internal/dns/apply) and records what each name's status is.
//
// A pass runs for a zone when a configuration revision touched a source (after a debounce), on a
// timer, when this replica took the lease, and when asked. Nothing is mounted here: the controller
// starts the job with the other DNS jobs.
package job

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/apply"
	"github.com/felix-homelab/rpmgr/internal/dns/compile"
	"github.com/felix-homelab/rpmgr/internal/dns/plan"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/configrevision"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsnamestatus"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
)

// The timing of the job; the values of docs/15-dns.md, "Timers and limits", and of the lease in
// docs/03-connections.md, "Timeouts, keepalive and backoff".
const (
	LeaseName = "dns"
	// LeaseTTL is the DNS lease's own time to live: a request to the provider may take as long as
	// the margin, so a lease of the default TTL could never outlast one.
	LeaseTTL = 90 * time.Second
	// Margin is how long the lease must still hold before a batch is sent.
	Margin = 30 * time.Second
	// Debounce coalesces the revisions that touch a source into one pass.
	Debounce = 2 * time.Second
	// FullEvery is the interval of the pass over every zone.
	FullEvery = 15 * time.Minute
	// PollEvery is how often the job looks for new revisions.
	PollEvery = time.Second
)

// ErrLeaseEnding is the error of a batch that was not sent, because the lease would not outlast it.
var ErrLeaseEnding = errors.New("dnsjob: the lease ends too soon to send a batch")

// sourcePrefixes are the IDs of the resources that are sources of DNS records: routes, gateway
// groups (their DNS target), domains, DNS names and zones.
var sourcePrefixes = []string{"rt_", "gwg_", "dom_", "dnn_", "dnz_"}

// Options configure the job.
type Options struct {
	DB     *store.DB
	Leases *lease.Leases
	Sealer *secret.Sealer
	// Dial makes the client of a provider account; nil is providers.Dial.
	Dial providers.Dialer
	// TrustDomain is this instance's, in every marker.
	TrustDomain string
	// Reserved returns the names that are never written: the controller's public URL and aliases,
	// the agent endpoints. Nil: none besides the compiler's own.
	Reserved func(ctx context.Context) []string
	// Now is the clock; it must be the lease's. Nil is time.Now.
	Now    func() time.Time
	Logger *slog.Logger
	// Report, if set, is called after a pass of a zone that found something to report: records
	// that carry this instance's marker without a ledger row (orphans, never deleted), records
	// someone else changed, and records that are no longer corrected because they changed again
	// within the stop window. The alerts of docs/10 are raised from it.
	Report func(ctx context.Context, zone *ent.DNSZone, r apply.Report)
	// Debounce and Full override the timing, for tests; zero is the default.
	Debounce, Full time.Duration
}

// Job is the DNS job.
type Job struct {
	o Options

	mu       sync.Mutex
	token    int64                // the fencing token of the lease the state below belongs to
	seen     int64                // the last configuration revision looked at
	nextFull time.Time            // when the next pass over every zone is due
	dirty    map[string]time.Time // zone ID ("": every zone) -> when it was first marked
	force    map[string]bool      // zones to run in full at the next tick
	clean    map[string]string    // zone ID -> what the last pass without a failure compiled
}

// New returns the job.
func New(o Options) *Job {
	if o.Dial == nil {
		o.Dial = providers.Dial
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Debounce == 0 {
		o.Debounce = Debounce
	}
	if o.Full == 0 {
		o.Full = FullEvery
	}
	return &Job{o: o, dirty: map[string]time.Time{}, force: map[string]bool{}, clean: map[string]string{}}
}

// Lease returns the singleton job for the lease runner.
func (j *Job) Lease() lease.Job {
	return lease.Job{Name: LeaseName, Reason: "reconcile the dns zones", Every: PollEvery, TTL: LeaseTTL, Run: j.Run}
}

// Trigger marks zones dirty: dns_dirty in process. No zone ID marks every zone. A pass follows
// after the debounce, on the replica that holds the lease.
func (j *Job) Trigger(zoneIDs ...string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(zoneIDs) == 0 {
		zoneIDs = []string{""}
	}
	for _, z := range zoneIDs {
		if _, ok := j.dirty[z]; !ok {
			j.dirty[z] = j.o.Now()
		}
	}
}

// Sync asks for a full pass of one zone at the next tick, without a debounce ("Sync now").
func (j *Job) Sync(zoneID string) {
	j.mu.Lock()
	j.force[zoneID] = true
	j.mu.Unlock()
}

// Run is one tick under the lease. It runs a full pass over every zone when this replica has just
// taken the lease or the timer is due, and otherwise the passes that revisions or Trigger asked
// for. Only a lost lease or a database error is returned: a provider that fails leaves its zone
// as it is and is tried again at the next trigger or full pass.
func (j *Job) Run(ctx context.Context, l lease.Lease) error {
	now := j.o.Now()
	j.mu.Lock()
	full := l.Token != j.token || !now.Before(j.nextFull)
	if l.Token != j.token {
		j.token, j.seen, j.clean = l.Token, 0, map[string]string{}
	}
	if full {
		j.nextFull = now.Add(j.o.Full)
	}
	since := j.seen
	j.mu.Unlock()

	cur, touched, err := j.revisions(ctx, since, full)
	if err != nil {
		return err
	}
	j.mu.Lock()
	j.seen = cur
	if touched {
		if _, ok := j.dirty[""]; !ok {
			j.dirty[""] = now
		}
	}
	var due []string
	for z, at := range j.dirty {
		if now.Sub(at) >= j.o.Debounce {
			due = append(due, z)
			delete(j.dirty, z)
		}
	}
	forced := j.force
	j.force = map[string]bool{}
	j.mu.Unlock()

	zones, err := j.o.DB.ReadClient().DNSZone.Query().Order(ent.Asc(dnszone.FieldID)).All(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, z := range zones {
		isFull := full || forced[z.ID]
		if !isFull && !slices.Contains(due, "") && !slices.Contains(due, z.ID) {
			continue
		}
		if err := j.pass(ctx, l, z, isFull); err != nil {
			if errors.Is(err, lease.ErrLost) {
				return err
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// revisions reads the configuration revisions after since: the current one, and whether one of
// them changed a source. On the first look after a takeover, since is 0 and nothing is touched: the
// full pass covers it.
func (j *Job) revisions(ctx context.Context, since int64, full bool) (cur int64, touched bool, err error) {
	err = store.ReadTx(ctx, j.o.DB, func(tx *ent.Tx, rev store.Revision) error {
		cur = rev.Seq
		if since == 0 || full || rev.Seq <= since {
			return nil
		}
		rows, err := tx.ConfigRevision.Query().Where(configrevision.IDGT(since), configrevision.IDLTE(rev.Seq)).All(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			for _, id := range r.ChangedResources {
				if slices.ContainsFunc(sourcePrefixes, func(p string) bool { return strings.HasPrefix(id, p) }) {
					touched = true
				}
			}
		}
		return nil
	})
	return cur, touched, err
}

// guard refuses a batch the lease will not outlast by the margin (docs/15-dns.md, "The DNS job").
// The fencing token protects the database, not the provider, so this is the only thing that keeps
// a replica that has lost its lease out of it.
func (j *Job) guard(l lease.Lease) func(context.Context) error {
	return func(context.Context) error {
		if left := l.Left(j.o.Now()); left < Margin {
			return fmt.Errorf("%w (%s left, %s needed)", ErrLeaseEnding, left.Round(time.Second), Margin)
		}
		return nil
	}
}

// outcome is what a pass found, for the statuses.
type outcome struct {
	cr  compile.Result
	pl  plan.Plan // empty, with no hash, when the provider's records could not be listed
	res apply.Result
	// report is what the pass found that a person should know of: orphans, drift, a repair.
	report apply.Report
	stop   error // the pass stopped: the provider failed, or the lease ends
}

// pass reconciles one zone. A failure of the provider or the lease is recorded and not returned;
// only a lost lease and database errors are.
func (j *Job) pass(ctx context.Context, l lease.Lease, z *ent.DNSZone, full bool) error {
	var in compile.Input
	reserved := []string(nil)
	if j.o.Reserved != nil {
		reserved = j.o.Reserved(ctx)
	}
	err := store.ReadTx(ctx, j.o.DB, func(tx *ent.Tx, _ store.Revision) error {
		cur, err := tx.DNSZone.Get(ctx, z.ID)
		if err != nil {
			return err
		}
		z = cur
		in, err = sources(ctx, tx, z, reserved)
		return err
	})
	if ent.IsNotFound(err) {
		return nil // removed since it was listed
	}
	if err != nil {
		return err
	}
	o := outcome{cr: compile.Compile(in)}
	key := fmt.Sprintf("%v|%v|%v", o.cr.Desired, o.cr.Names, z.SyncState)
	j.mu.Lock()
	same := j.clean[z.ID] == key
	j.mu.Unlock()
	if !full && same {
		return nil // a revision that changed nothing this zone publishes
	}
	if z.SyncState == dnszone.SyncStateActive {
		if err := j.sync(ctx, l, z, reserved, &o); err != nil {
			return err
		}
	}
	if err := j.record(ctx, l, z, o); err != nil {
		return err
	}
	if o.stop == nil && len(o.res.Failed) == 0 {
		j.mu.Lock()
		j.clean[z.ID] = key
		j.mu.Unlock()
	}
	return nil
}

// sync lists the provider, plans and applies. Its failures go to o.stop.
func (j *Job) sync(ctx context.Context, l lease.Lease, z *ent.DNSZone, reserved []string, o *outcome) error {
	prov, err := j.provider(ctx, z)
	if err != nil {
		o.stop = err
		return nil
	}
	eng := &apply.Engine{DB: j.o.DB, Leases: j.o.Leases, TrustDomain: j.o.TrustDomain, Guard: j.guard(l), Now: j.o.Now}
	out, err := eng.Reconcile(ctx, l, prov, apply.Zone{ID: z.ID, OrgID: z.OrgID, Name: z.Name, ProviderID: z.ProviderZoneID},
		apply.Wanted{Desired: o.cr.Desired, Keep: o.cr.Keep(), Reserved: reserved})
	o.pl, o.res, o.report = out.Plan, out.Result, out.Report
	switch {
	case errors.Is(err, lease.ErrLost):
		return err
	case err != nil:
		o.stop = err
	}
	return nil
}

// provider makes the client of the zone's provider account.
func (j *Job) provider(ctx context.Context, z *ent.DNSZone) (dns.Provider, error) {
	p, err := j.o.DB.ReadClient().DNSProvider.Get(ctx, z.DNSProviderID)
	if err != nil {
		return nil, err
	}
	tok, err := j.o.Sealer.Open(providers.SecretContext(p.ID), p.CredentialEnc)
	if err != nil {
		return nil, fmt.Errorf("the provider's token cannot be opened: %w", err)
	}
	return j.o.Dial(string(p.Kind), p.AccountID, tok)
}

// providerStatus maps the end of a pass to the zone's provider_status; ok is false for a stop that
// says nothing about the provider, such as a lease that ends.
func providerStatus(err error) (status dnszone.ProviderStatus, ok bool) {
	var rl dns.RateLimited
	switch {
	case err == nil:
		return dnszone.ProviderStatusOk, true
	case errors.Is(err, ErrLeaseEnding), errors.Is(err, context.Canceled):
		return "", false
	case errors.Is(err, dns.ErrUnauthorized), errors.Is(err, dns.ErrForbidden):
		return dnszone.ProviderStatusPermissionDenied, true
	case errors.As(err, &rl):
		return dnszone.ProviderStatusRateLimited, true
	}
	return dnszone.ProviderStatusUnreachable, true
}

// record commits the zone's provider status and its names' statuses in one fenced transaction.
func (j *Job) record(ctx context.Context, l lease.Lease, z *ent.DNSZone, o outcome) error {
	want := statuses(o)
	now := j.o.Now().UTC()
	err := store.WriteTx(ctx, j.o.DB, func(tx *ent.Tx) error {
		if err := j.o.Leases.Fence(ctx, tx, l); err != nil {
			return err
		}
		if z.SyncState == dnszone.SyncStateActive {
			u := tx.DNSZone.Update().Where(dnszone.ID(z.ID))
			if st, ok := providerStatus(o.stop); ok {
				u.SetProviderStatus(st)
			}
			if o.stop == nil {
				u.SetLastSyncedAt(now)
			}
			if err := u.Exec(ctx); err != nil {
				return err
			}
		}
		rows, err := tx.DNSNameStatus.Query().Where(dnsnamestatus.DNSZoneID(z.ID)).All(ctx)
		if err != nil {
			return err
		}
		have := map[string]*ent.DNSNameStatus{}
		for _, r := range rows {
			have[r.Name] = r
		}
		for _, w := range want {
			r := have[w.name]
			delete(have, w.name)
			switch {
			case r == nil:
				if err := tx.DNSNameStatus.Create().SetOrgID(z.OrgID).SetDNSZoneID(z.ID).SetName(w.name).SetStatus(w.status).SetReason(w.reason).SetSince(now).Exec(ctx); err != nil {
					return err
				}
			case w.keep: // the provider is out of reach: a name stays as it was
			case r.Status != w.status || r.Reason != w.reason:
				if err := tx.DNSNameStatus.UpdateOneID(r.ID).SetStatus(w.status).SetReason(w.reason).SetSince(now).Exec(ctx); err != nil {
					return err
				}
			}
		}
		for _, r := range have { // a name that has no source any more
			if err := tx.DNSNameStatus.DeleteOneID(r.ID).Exec(ctx); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if o.stop != nil && j.o.Logger != nil {
		j.o.Logger.WarnContext(ctx, "a dns zone was left as it is", "dns_zone", z.ID, "err", o.stop)
	}
	if r := o.report; len(r.Orphans)+len(r.Corrected)+len(r.Drifted)+r.Relinked > 0 {
		if j.o.Logger != nil {
			j.o.Logger.WarnContext(ctx, "a dns zone needs a look", "dns_zone", z.ID, "orphans", len(r.Orphans),
				"corrected", len(r.Corrected), "drifted", len(r.Drifted), "relinked", r.Relinked)
		}
		if j.o.Report != nil {
			j.o.Report(ctx, z, r)
		}
	}
	return nil
}

type nameStatus struct {
	name   string
	status dnsnamestatus.Status
	reason string
	keep   bool // leave an existing row as it is
}

// statuses derives the dns_status of every name with a source in the zone (docs/15-dns.md,
// "Publication rules"). A name is published once nothing is left to do at it: not while its plan
// was not sent, and not where the provider refused a record.
func statuses(o outcome) []nameStatus {
	conflicts := map[string]string{}
	for _, c := range o.pl.Conflicts {
		conflicts[c.Name] = string(c.Kind)
	}
	failed := map[string]string{}
	for _, f := range o.res.Failed {
		failed[f.Name] = f.Reason
	}
	touched := map[string]bool{}
	for _, r := range slices.Concat(o.pl.Creates, o.pl.Updates, o.pl.Deletes) {
		touched[r.Name] = true
	}
	var out []nameStatus
	for _, n := range o.cr.Names {
		if n.Claim {
			continue
		}
		s := nameStatus{name: n.Name}
		switch n.Status {
		case compile.StatusOk:
			switch reason, isConflict := conflicts[n.Name]; {
			case o.cr.Held:
				s.status = dnsnamestatus.StatusHeld
			case isConflict:
				s.status, s.reason = dnsnamestatus.StatusConflict, reason
			case failed[n.Name] != "":
				s.status, s.reason = dnsnamestatus.StatusError, failed[n.Name]
			case o.stop != nil && o.pl.Hash == "": // no plan: the provider could not be listed
				s.status, s.keep = dnsnamestatus.StatusPending, true
			case o.stop != nil && touched[n.Name]:
				s.status = dnsnamestatus.StatusPending
			default:
				s.status = dnsnamestatus.StatusPublished
			}
		case compile.StatusAmbiguous:
			s.status = dnsnamestatus.StatusAmbiguous
		case compile.StatusHeld:
			s.status = dnsnamestatus.StatusHeld
		case compile.StatusNotManaged:
			s.status = dnsnamestatus.StatusNotManaged
		default: // no_target, reserved, not_verified: shown as not_managed with the reason
			s.status, s.reason = dnsnamestatus.StatusNotManaged, string(n.Status)
		}
		out = append(out, s)
	}
	return out
}
