// SPDX-License-Identifier: Apache-2.0

// Package budget is the request budget of a DNS provider (docs/15-dns.md, "Batches, failures and
// the rate budget"; D164). One database row per provider holds the request window and the
// retry-after block. The DNS job and the DNS-01 adapter take each request from it in a transaction,
// on whichever replica they run, so that replicas never add up past the budget. The DNS-01 adapter
// may take at most half of the window, so that issuance never starves the job.
//
// The replicas' clocks differ a little, and the row carries times that one replica wrote and
// another reads. The budget errs on the side of fewer requests: a window that starts in the future
// of the reader stays open, and a block is cut to MaxBlock from the writer's now, so a reader
// whose clock is behind waits at most the skew longer.
package budget

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsratebudget"
)

// The values of docs/15-dns.md, "Timers and limits".
const (
	// Window is the length of the request window.
	Window = 5 * time.Minute
	// Limit is how many requests a provider's budget lends in one window.
	Limit = 300
	// Dns01Limit is how many of them the DNS-01 adapter may take: half.
	Dns01Limit = Limit / 2
	// DefaultBlock is the block after a 429 that names no usable retry-after.
	DefaultBlock = 5 * time.Minute
	// MaxBlock is the longest block that is recorded: a longer retry-after is cut to it.
	MaxBlock = time.Hour
)

// attempts bounds the retries of a transaction that lost a race for the row.
const attempts = 8

// Kind says who takes a request.
type Kind string

// The takers of a provider's budget.
const (
	// Job is the DNS job, and the API calls that read the provider live.
	Job Kind = "job"
	// DNS01 is the DNS-01 adapter; it may take at most Dns01Limit of the window.
	DNS01 Kind = "dns01"
)

// state is the budget row as the arithmetic reads it.
type state struct {
	start   time.Time
	used    int
	dns01   int
	blocked *time.Time
}

// Status is what the metrics and the zone's status show of a budget.
type Status struct {
	// Used is how many requests the window holds, by the job and DNS-01 together.
	Used int
	// Blocked is how long a retry-after block lasts yet; zero when there is none.
	Blocked time.Duration
}

// take is the arithmetic: the state after one request of kind at now, or the time until which the
// request must wait. It reads no clock and no database.
func take(s state, now time.Time, kind Kind) (next state, until time.Time, ok bool) {
	if s.blocked != nil {
		if now.Before(*s.blocked) {
			return s, *s.blocked, false
		}
		s.blocked = nil
	}
	switch {
	case s.start.IsZero(), now.Sub(s.start) >= Window, s.start.Sub(now) > Window:
		// A new window; also one that a replica far ahead of this one started, which would
		// otherwise stay open for as long as the skew.
		s.start, s.used, s.dns01 = now, 0, 0
	}
	// A start in the future of now, a little, stays: the window is then longer, never shorter.
	end := s.start.Add(Window)
	if s.used >= Limit || (kind == DNS01 && s.dns01 >= Dns01Limit) {
		return s, end, false
	}
	s.used++
	if kind == DNS01 {
		s.dns01++
	}
	return s, time.Time{}, true
}

// Budget is the budgets of every provider, in one database.
type Budget struct {
	DB *store.DB
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Observe, if set, is called for each request that was sent to a provider (not for one the
	// budget refused) with the provider's ID and the HTTP status of the answer: "200" for a
	// success, the status of a failure, "error" for a request that got no answer. It feeds
	// rpmgr_dns_provider_requests_total.
	Observe func(providerID, code string)
}

func (b *Budget) now() time.Time {
	if b.Now != nil {
		return b.Now().UTC()
	}
	return time.Now().UTC()
}

// update runs fn on the row of provider in a transaction, creating the row if there is none. The
// row is locked for the transaction, and the update is conditional on its version besides, so two
// replicas never both build on the same state. fn gets the row's state and returns the new one,
// and whether to write it. The audit hook of the request's context is not run: a budget is runtime
// state, not a change.
func (b *Budget) update(ctx context.Context, providerID string, fn func(s state) (state, bool)) error {
	ctx = store.WithoutTxHook(ctx)
	for range attempts {
		err := store.WriteTx(ctx, b.DB, func(tx *ent.Tx) error {
			if b.DB.Dialect == store.Postgres {
				// The second taker waits for the first; SQLite has one writer. Ent's locking
				// feature is not generated, and a row that does not exist yet locks nothing.
				rows, err := tx.QueryContext(ctx, "SELECT id FROM dns_rate_budgets WHERE dns_provider_id = $1 FOR UPDATE", providerID)
				if err != nil {
					return err
				}
				for rows.Next() { // the locks are taken as the rows are read
				}
				if err := errors.Join(rows.Err(), rows.Close()); err != nil {
					return err
				}
			}
			row, err := tx.DNSRateBudget.Query().Where(dnsratebudget.DNSProviderID(providerID)).Only(ctx)
			if ent.IsNotFound(err) {
				p, err := tx.DNSProvider.Get(ctx, providerID)
				if err != nil {
					return err
				}
				row, err = tx.DNSRateBudget.Create().SetOrgID(p.OrgID).SetDNSProviderID(providerID).SetWindowStartedAt(b.now()).Save(ctx)
				if err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			next, write := fn(state{start: row.WindowStartedAt, used: row.Used, dns01: row.Dns01Used, blocked: row.BlockedUntil})
			if !write {
				return nil
			}
			u := tx.DNSRateBudget.UpdateOneID(row.ID).Where(dnsratebudget.Version(row.Version)).
				SetWindowStartedAt(next.start).SetUsed(next.used).SetDns01Used(next.dns01)
			if next.blocked == nil {
				u.ClearBlockedUntil()
			} else {
				u.SetBlockedUntil(*next.blocked)
			}
			return u.Exec(ctx)
		})
		// A lost race is a duplicate row for the creation of the first one, or, if nothing locked
		// the row, a missing row for the conditional update.
		if err == nil || (!ent.IsNotFound(err) && !ent.IsConstraintError(err)) {
			return err
		}
	}
	return errors.New("budget: the row of the provider is too contended to take a request")
}

// Take takes one request of kind from the budget of provider. It fails with Refused, a
// dns.RateLimited whose Until is when to try again, if the window is spent, or the DNS-01 half of
// it, or a block holds.
func (b *Budget) Take(ctx context.Context, providerID string, kind Kind) error {
	var until time.Time
	var ok bool
	now := b.now()
	err := b.update(ctx, providerID, func(s state) (state, bool) {
		var next state
		next, until, ok = take(s, now, kind)
		return next, ok || s.blocked != nil && next.blocked == nil // a lapsed block is cleared
	})
	if err != nil {
		return fmt.Errorf("budget: %w", err)
	}
	if !ok {
		return Refused{until}
	}
	return nil
}

// Refused is the error of a request the budget did not lend. It is a dns.RateLimited for errors.As,
// so that the job records the zone as rate_limited; it is told apart from the provider's own 429,
// which blocks the budget, by this type.
type Refused struct{ Until time.Time }

func (r Refused) Error() string { return dns.RateLimited{Until: r.Until}.Error() }

// Unwrap makes a Refused a dns.RateLimited.
func (r Refused) Unwrap() error { return dns.RateLimited{Until: r.Until} }

// Block records that the provider answered 429: no request is taken before until. A zero until is
// DefaultBlock from now. The block is never shortened, and never longer than MaxBlock.
func (b *Budget) Block(ctx context.Context, providerID string, until time.Time) error {
	now := b.now()
	if until.IsZero() {
		until = now.Add(DefaultBlock)
	}
	until = until.UTC()
	if m := now.Add(MaxBlock); until.After(m) {
		until = m
	}
	return b.update(ctx, providerID, func(s state) (state, bool) {
		if s.blocked != nil && !s.blocked.Before(until) {
			return s, false
		}
		s.blocked = &until
		return s, true
	})
}

// Status reads the budget of a provider; a provider that took nothing yet has none spent.
func (b *Budget) Status(ctx context.Context, providerID string) (Status, error) {
	now := b.now()
	row, err := b.DB.ReadClient().DNSRateBudget.Query().Where(dnsratebudget.DNSProviderID(providerID)).Only(ctx)
	if ent.IsNotFound(err) {
		return Status{}, nil
	}
	if err != nil {
		return Status{}, err
	}
	var st Status
	if !row.WindowStartedAt.IsZero() && now.Sub(row.WindowStartedAt) < Window {
		st.Used = row.Used
	}
	if row.BlockedUntil != nil {
		st.Blocked = max(0, min(row.BlockedUntil.Sub(now), MaxBlock))
	}
	return st, nil
}

type gate struct {
	b    *Budget
	id   string
	kind Kind
}

func (g gate) Take(ctx context.Context) error { return g.b.Take(ctx, g.id, g.kind) }

// Gate returns the budget of provider as a dns.Gate for one taker.
func (b *Budget) Gate(providerID string, kind Kind) dns.Gate { return gate{b, providerID, kind} }

// provider puts the gate in the context of every call and records a 429 as the provider's block,
// for every replica and every taker.
type provider struct {
	dns.Provider
	b    *Budget
	gate dns.Gate
	id   string
}

// Wrap returns p so that each of its requests is taken from the budget of the provider with the
// given ID as kind, and a 429 blocks the budget for everyone. The wrapped provider is as safe for
// concurrent use as p.
func (b *Budget) Wrap(p dns.Provider, providerID string, kind Kind) dns.Provider {
	return &provider{Provider: p, b: b, gate: b.Gate(providerID, kind), id: providerID}
}

// seen records what a call found: a 429 of the provider, but not the refusal of the budget itself,
// which is no news.
func (p *provider) seen(ctx context.Context, err error) error {
	var rl dns.RateLimited
	var own Refused
	if p.b.Observe != nil && !errors.As(err, &own) {
		p.b.Observe(p.id, codeOf(err))
	}
	if err != nil && errors.As(err, &rl) && !errors.As(err, &own) {
		if berr := p.b.Block(context.WithoutCancel(ctx), p.id, rl.Until); berr != nil {
			return errors.Join(err, berr)
		}
	}
	return err
}

// codeOf is the label of a call's outcome.
func codeOf(err error) string {
	var pe *dns.ProviderError
	switch {
	case err == nil:
		return "200"
	case errors.As(err, &pe) && pe.Status != 0:
		return strconv.Itoa(pe.Status)
	}
	return "error"
}

func (p *provider) Verify(ctx context.Context) (dns.TokenInfo, error) {
	t, err := p.Provider.Verify(dns.WithGate(ctx, p.gate))
	return t, p.seen(ctx, err)
}

func (p *provider) ListZones(ctx context.Context) ([]dns.Zone, error) {
	z, err := p.Provider.ListZones(dns.WithGate(ctx, p.gate))
	return z, p.seen(ctx, err)
}

func (p *provider) ListRecords(ctx context.Context, zoneID string) ([]dns.Record, error) {
	r, err := p.Provider.ListRecords(dns.WithGate(ctx, p.gate), zoneID)
	return r, p.seen(ctx, err)
}

func (p *provider) Apply(ctx context.Context, zoneID string, bt dns.Batch) error {
	return p.seen(ctx, p.Provider.Apply(dns.WithGate(ctx, p.gate), zoneID, bt))
}
