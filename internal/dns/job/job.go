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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/apply"
	"github.com/felix-homelab/rpmgr/internal/dns/budget"
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
	// Budget, if set, is the request budget of the providers, shared with the other replicas and
	// with DNS-01: every request the job sends is taken from it (docs/15-dns.md, "Batches,
	// failures and the rate budget"). Nil: no budget, for tests of other things.
	Budget *budget.Budget
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
	asked    map[string]time.Time // zone ID -> the last sync_requested_at that was acted on
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
	return &Job{o: o, dirty: map[string]time.Time{}, force: map[string]bool{}, asked: map[string]time.Time{}, clean: map[string]string{}}
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
		isFull := full || forced[z.ID] || j.requested(z)
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

// requested reports whether someone asked for a full pass of the zone (SyncZone) since the last
// one the job acted on. The request may have come in at another replica, so it is in the row.
func (j *Job) requested(z *ent.DNSZone) bool {
	if z.SyncRequestedAt == nil {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if !z.SyncRequestedAt.After(j.asked[z.ID]) {
		return false
	}
	j.asked[z.ID] = *z.SyncRequestedAt
	return true
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
	// held is why the zone is held after this pass: the gate refused to apply the plan, which is
	// stored with the zone for review. planned: a held zone's plan was computed, and is stored.
	held     string
	planned  bool
	approved bool // the plan was the approved one: the approval is used up
}

// pass reconciles one zone. A failure of the provider or the lease is recorded and not returned;
// only a lost lease and database errors are.
func (j *Job) pass(ctx context.Context, l lease.Lease, z *ent.DNSZone, full bool) error {
	z, in, reserved, err := j.read(ctx, z.ID)
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
	switch z.SyncState {
	case dnszone.SyncStateActive:
		if err := j.sync(ctx, l, z, reserved, &o); err != nil {
			return err
		}
	case dnszone.SyncStateHeld:
		j.plan(ctx, z, reserved, &o)
	case dnszone.SyncStateDisabled: // the job does nothing in the zone
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

// read returns the zone, as it is now, and what its sources compile from, in one snapshot.
func (j *Job) read(ctx context.Context, zoneID string) (z *ent.DNSZone, in compile.Input, reserved []string, err error) {
	if j.o.Reserved != nil {
		reserved = j.o.Reserved(ctx)
	}
	err = store.ReadTx(ctx, j.o.DB, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		if z, err = tx.DNSZone.Get(ctx, zoneID); err != nil {
			return err
		}
		in, err = sources(ctx, tx, z, reserved)
		return err
	})
	return z, in, reserved, err
}

func (j *Job) engine(l lease.Lease, guard bool) *apply.Engine {
	e := &apply.Engine{DB: j.o.DB, Leases: j.o.Leases, TrustDomain: j.o.TrustDomain, Now: j.o.Now}
	if guard {
		e.Guard = j.guard(l)
	}
	return e
}

func applyZone(z *ent.DNSZone) apply.Zone {
	return apply.Zone{ID: z.ID, OrgID: z.OrgID, Name: z.Name, ProviderID: z.ProviderZoneID}
}

// Inspection is what the API needs to know of a zone now.
type Inspection struct {
	// Live is every record of the zone at the provider.
	Live []dns.Record
	// Plan is the plan a pass would carry out, and its hash.
	Plan plan.Plan
	// Wanted are the names that the zone publishes records for: names with a source in the zone's
	// org that the compiler accepts. Only a record at one of them is adopted.
	Wanted []string
}

// Inspect lists the zone's records through p, which the caller makes from the zone's provider, and
// computes the plan as a pass would now, for the review of a held zone, for the approval, which is
// bound to its hash, and for adopting. It writes nothing.
func (j *Job) Inspect(ctx context.Context, zoneID string, p dns.Provider) (Inspection, error) {
	z, in, reserved, err := j.read(ctx, zoneID)
	if err != nil {
		return Inspection{}, err
	}
	live, err := p.ListRecords(ctx, z.ProviderZoneID)
	if err != nil {
		return Inspection{}, err
	}
	cr := compile.Compile(in)
	pl, err := j.engine(lease.Lease{}, false).PlanOf(ctx, live, applyZone(z), apply.Wanted{Desired: cr.Desired, Keep: cr.Keep(), Reserved: reserved})
	if err != nil {
		return Inspection{}, err
	}
	out := Inspection{Live: live, Plan: pl}
	for _, n := range cr.Names {
		if n.Status == compile.StatusOk && !n.Claim {
			out.Wanted = append(out.Wanted, n.Name)
		}
	}
	return out, nil
}

// Preview is the plan of a zone as Inspect computes it.
func (j *Job) Preview(ctx context.Context, zoneID string, p dns.Provider) (plan.Plan, error) {
	i, err := j.Inspect(ctx, zoneID, p)
	return i.Plan, err
}

// plan computes the plan of a held zone and writes nothing to the provider. Its failures go to
// o.stop; a plan that could not be computed leaves the stored one as it is.
func (j *Job) plan(ctx context.Context, z *ent.DNSZone, reserved []string, o *outcome) {
	prov, err := j.provider(ctx, z)
	if err != nil {
		o.stop = err
		return
	}
	pl, err := j.engine(lease.Lease{}, false).Plan(ctx, prov, applyZone(z), apply.Wanted{Desired: o.cr.Desired, Keep: o.cr.Keep(), Reserved: reserved})
	if err != nil {
		o.stop = err
		return
	}
	o.pl, o.planned = pl, true
}

// sync lists the provider, plans and applies. Its failures go to o.stop.
func (j *Job) sync(ctx context.Context, l lease.Lease, z *ent.DNSZone, reserved []string, o *outcome) error {
	prov, err := j.provider(ctx, z)
	if err != nil {
		o.stop = err
		return nil
	}
	eng := j.engine(l, true)
	if _, err := eng.Release(ctx, l, prov, applyZone(z)); err != nil { // requested releases, before the plan
		if errors.Is(err, lease.ErrLost) {
			return err
		}
		o.stop = err
		return nil
	}
	out, err := eng.Reconcile(ctx, l, prov, applyZone(z), apply.Wanted{Desired: o.cr.Desired, Keep: o.cr.Keep(),
		Reserved: reserved, Gate: apply.Guard(z.DeleteThreshold, z.PendingPlanHash)})
	o.pl, o.res, o.report, o.held, o.approved = out.Plan, out.Result, out.Report, out.Held, out.Approved
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
	prov, err := j.o.Dial(string(p.Kind), p.AccountID, tok)
	if err != nil || j.o.Budget == nil {
		return prov, err
	}
	return j.o.Budget.Wrap(prov, p.ID, budget.Job), nil
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
		if z.SyncState != dnszone.SyncStateDisabled {
			u := tx.DNSZone.Update().Where(dnszone.ID(z.ID))
			if st, ok := providerStatus(o.stop); ok {
				u.SetProviderStatus(st)
			}
			if o.stop == nil && z.SyncState == dnszone.SyncStateActive {
				u.SetLastSyncedAt(now)
			}
			// What a person decides, a hold, an approval, the plan under review, is written only
			// if the zone is still as the pass found it: an approval that came in meanwhile stays.
			switch {
			case o.held != "" || o.planned:
				plan, err := json.Marshal(o.pl)
				if err != nil {
					return err
				}
				u.Where(dnszone.Version(z.Version)).SetPendingPlan(plan).SetPendingPlanHash(o.pl.Hash)
				if o.held != "" {
					u.SetSyncState(dnszone.SyncStateHeld).SetHeldReason(o.held)
				}
			case o.approved:
				u.Where(dnszone.Version(z.Version)).ClearPendingPlan().SetPendingPlanHash("")
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
			case o.cr.Held, o.held != "":
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
