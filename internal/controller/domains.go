// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
)

// The schedule of pending claims (docs/15-dns.md, "Timers and limits").
const (
	DomainCheckEvery = time.Minute      // how often the job looks for due claims
	DomainEarly      = 15 * time.Minute // a claim's first quarter hour, checked every minute
	DomainLate       = 15 * time.Minute // the interval after it
	DomainFailAfter  = 7 * 24 * time.Hour
	domainParallel   = 8 // checks at once
)

// errNotProved is the error a claim keeps when it fails.
var errNotProved = errors.New("not proved within 7 days")

// DomainCheckOptions configure the job that checks pending claims.
type DomainCheckOptions struct {
	DB *store.DB
	// TXT and HTTP check the proofs; nil skips claims of that method.
	TXT, HTTP domains.Verifier
	Now       func() time.Time
	Logger    *slog.Logger
}

// DomainCheckJob checks, under a lease, each pending claim when it is due: every minute in its
// first 15 minutes, then every 15 minutes; a claim not proved within 7 days fails.
func DomainCheckJob(o DomainCheckOptions) lease.Job {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return lease.Job{Name: "domain-checks", Reason: "check the proofs of pending domain claims", Every: DomainCheckEvery,
		Run: func(ctx context.Context, _ lease.Lease) error { return checkDomains(ctx, o) }}
}

func checkDomains(ctx context.Context, o DomainCheckOptions) error {
	now := o.Now()
	pending, err := o.DB.ReadClient().Domain.Query().Where(domain.StatusEQ(domain.StatusPending),
		domain.MethodIn(domain.MethodDNSTxt, domain.MethodHTTP)).Order(ent.Asc(domain.FieldID)).All(ctx)
	if err != nil {
		return err
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
		sem  = make(chan struct{}, domainParallel)
	)
	for _, d := range pending {
		age := now.Sub(d.CreatedAt)
		var result error
		switch {
		case age >= DomainFailAfter:
			result = errNotProved
		case !due(d, age, now):
			continue
		}
		v := o.TXT
		if d.Method == domain.MethodHTTP {
			v = o.HTTP
		}
		if v == nil && result == nil {
			continue
		}
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			if result == nil {
				result = v.Verify(ctx, domains.ChallengeOf(d))
			}
			if err := recordCheck(ctx, o, d, result, now); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

// due reports whether a pending claim of age is due for a check.
func due(d *ent.Domain, age time.Duration, now time.Time) bool {
	if d.LastCheckedAt == nil {
		return true
	}
	since := now.Sub(*d.LastCheckedAt)
	if age < DomainEarly {
		return since >= DomainCheckEvery
	}
	return since >= DomainLate
}

// recordCheck records a check of a claim that is still pending with the same challenge.
func recordCheck(ctx context.Context, o DomainCheckOptions, d *ent.Domain, result error, now time.Time) error {
	return store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
		latest, err := tx.Domain.Get(ctx, d.ID)
		if ent.IsNotFound(err) {
			return nil // deleted meanwhile
		}
		if err != nil || latest.Status != domain.StatusPending || latest.ChallengeValue != d.ChallengeValue {
			return err
		}
		if errors.Is(result, errNotProved) {
			return tx.Domain.UpdateOne(latest).SetStatus(domain.StatusFailed).SetLastCheckedAt(now).SetLastError(result.Error()).Exec(ctx)
		}
		if result == nil {
			o.Logger.Info("a domain claim is verified", "domain", d.Fqdn, "org", d.OrgID)
		}
		_, err = domains.Record(ctx, tx, latest, result, now)
		return err
	})
}
