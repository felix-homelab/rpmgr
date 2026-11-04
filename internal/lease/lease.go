// SPDX-License-Identifier: Apache-2.0

// Package lease runs the controller's singleton jobs under database leases (docs/10-operations.md,
// "High availability"): at most one replica holds a lease at a time, a lease expires unless its
// holder renews it, and its fencing token rises at every takeover, so a replica that lost a lease
// cannot commit work started under it.
package lease

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The lease timing (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	TTL         = 30 * time.Second
	RenewEvery  = TTL / 3
	RetryWithin = 5 * time.Second // how soon a replica tries again to take a lease another holds
)

// ErrLost is returned when a lease is no longer held: it expired, or another holder took it.
var ErrLost = errors.New("lease: not held any more")

// Lease is one held lease. The handle carries the time the lease ends (Expires): set when the
// lease is taken and moved on at every renewal, as read back from the database row, so a job can
// refuse work the lease will not outlast. Copies of a handle share it. A handle whose renewal
// failed keeps its old expiry, so it runs out (docs/15-dns.md, "The DNS job"; D164).
type Lease struct {
	Name  string
	Token int64
	ttl   time.Duration // the job's own TTL; zero is TTL
	ends  *atomic.Int64 // expires_at, Unix milliseconds; nil for a handle that was not taken
}

// Expires returns when the lease ends. It is the zero time for a handle that was not taken from
// the database, which no job may rely on.
func (l Lease) Expires() time.Time {
	if l.ends == nil {
		return time.Time{}
	}
	return time.UnixMilli(l.ends.Load())
}

// Left returns how long the lease still holds at now; zero or less once it ended.
func (l Lease) Left(now time.Time) time.Duration {
	if l.ends == nil {
		return 0
	}
	return time.UnixMilli(l.ends.Load()).Sub(now)
}

func (l Lease) ttlOr(d time.Duration) time.Duration {
	if l.ttl > 0 {
		return l.ttl
	}
	return d
}

// Leases takes and keeps leases for one holder, the controller node.
type Leases struct {
	db     *store.DB
	holder string
	ttl    time.Duration
	now    func() time.Time
}

// New returns the leases of holder. now is the clock every replica must share within a second;
// nil is time.Now.
func New(db *store.DB, holder string, now func() time.Time) *Leases {
	if now == nil {
		now = time.Now
	}
	return &Leases{db: db, holder: holder, ttl: TTL, now: now}
}

// TryAcquire takes the lease name if it is free or expired, raising its fencing token. ok is false
// if another holder has it.
func (l *Leases) TryAcquire(ctx context.Context, name string) (lease Lease, ok bool, err error) {
	return l.tryAcquire(ctx, name, l.ttl)
}

// TryAcquireFor is TryAcquire for a lease of its own TTL, which Renew keeps.
func (l *Leases) TryAcquireFor(ctx context.Context, name string, ttl time.Duration) (Lease, bool, error) {
	if ttl <= 0 {
		return Lease{}, false, errors.New("lease: a TTL must be positive")
	}
	lease, ok, err := l.tryAcquire(ctx, name, ttl)
	lease.ttl = ttl
	return lease, ok, err
}

func (l *Leases) tryAcquire(ctx context.Context, name string, ttl time.Duration) (lease Lease, ok bool, err error) {
	now := l.now().UnixMilli()
	var ends int64
	err = store.WriteTx(ctx, l.db, func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(ctx, `INSERT INTO leases (name, holder, fencing_token, expires_at)
			VALUES ($1, $2, 1, $3) ON CONFLICT (name) DO UPDATE SET holder = excluded.holder,
			fencing_token = leases.fencing_token + 1, expires_at = excluded.expires_at
			WHERE leases.expires_at <= $4 RETURNING fencing_token, expires_at`,
			name, l.holder, now+ttl.Milliseconds(), now)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		if ok = rows.Next(); ok {
			if err := rows.Scan(&lease.Token, &ends); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	if err != nil || !ok {
		return Lease{}, false, err
	}
	lease.Name = name
	lease.ends = new(atomic.Int64)
	lease.ends.Store(ends)
	return lease, true, nil
}

// Renew extends a held lease by the TTL. It fails with ErrLost once the lease expired or another
// holder took it, even if this holder took it again in between.
// The handle's expiry moves to the one the database row now holds; after a failed renewal it stays.
func (l *Leases) Renew(ctx context.Context, lease Lease) error {
	now := l.now().UnixMilli()
	var ends int64
	err := store.WriteTx(ctx, l.db, func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(ctx, `UPDATE leases SET expires_at = $1
			WHERE name = $2 AND holder = $3 AND fencing_token = $4 AND expires_at > $5 RETURNING expires_at`,
			now+lease.ttlOr(l.ttl).Milliseconds(), lease.Name, l.holder, lease.Token, now)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w: %s (token %d)", ErrLost, lease.Name, lease.Token)
		}
		return rows.Scan(&ends)
	})
	if err == nil && lease.ends != nil {
		lease.ends.Store(ends)
	}
	return err
}

// Release gives a held lease up, so another replica can take it at once.
func (l *Leases) Release(ctx context.Context, lease Lease) error {
	return l.exec(ctx, `UPDATE leases SET expires_at = 0
		WHERE name = $1 AND holder = $2 AND fencing_token = $3 AND expires_at > $4`,
		lease, lease.Name, l.holder, lease.Token, l.now().UnixMilli())
}

// Fence fails with ErrLost unless the lease is still held, inside tx: the transaction that commits
// the job's work. On PostgreSQL its row lock makes a takeover wait until tx ends.
func (l *Leases) Fence(ctx context.Context, tx *ent.Tx, lease Lease) error {
	res, err := tx.ExecContext(ctx, `UPDATE leases SET expires_at = expires_at
		WHERE name = $1 AND holder = $2 AND fencing_token = $3 AND expires_at > $4`,
		lease.Name, l.holder, lease.Token, l.now().UnixMilli())
	return affected(res, err, lease)
}

func (l *Leases) exec(ctx context.Context, q string, lease Lease, args ...any) error {
	return store.WriteTx(ctx, l.db, func(tx *ent.Tx) error {
		res, err := tx.ExecContext(ctx, q, args...)
		return affected(res, err, lease)
	})
}

func affected(res sql.Result, err error, lease Lease) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s (token %d)", ErrLost, lease.Name, lease.Token)
	}
	return nil
}

// Job is a singleton job. Run is called with the system scope, granted and audited when this
// replica took the lease; it must commit its work in a transaction that calls Fence.
type Job struct {
	Name   string        // the lease name
	Reason string        // the audited reason of its system scope
	Every  time.Duration // how often Run is called while the lease is held
	// TTL is the lease's own time to live, renewed every third of it; zero is the package's TTL. A
	// job that must not act in the last moments of its lease, such as one that calls a provider,
	// takes a longer one.
	TTL time.Duration
	Run func(ctx context.Context, lease Lease) error
}

// Run runs job until ctx ends: it takes the lease when it can, renews it, calls job.Run while it
// holds it, and stops calling it as soon as a renewal fails. Errors of job.Run are passed to
// onErr; they do not give the lease up.
func (l *Leases) Run(ctx context.Context, job Job, onErr func(error)) {
	if onErr == nil {
		onErr = func(error) {}
	}
	for ctx.Err() == nil {
		var lease Lease
		var ok bool
		var err error
		if job.TTL > 0 {
			lease, ok, err = l.TryAcquireFor(ctx, job.Name, job.TTL)
		} else {
			lease, ok, err = l.TryAcquire(ctx, job.Name)
		}
		switch {
		case err != nil && ctx.Err() != nil: // a shutdown, not a failure
		case err != nil:
			onErr(err)
		case ok:
			if err := l.hold(ctx, job, lease, onErr); err != nil && ctx.Err() == nil {
				onErr(err)
			}
		}
		if !sleep(ctx, RetryWithin) {
			return
		}
	}
}

// hold runs job while lease is held, and releases it when ctx ends.
func (l *Leases) hold(ctx context.Context, job Job, lease Lease, onErr func(error)) error {
	sys, err := authz.System(ctx, job.Name, job.Reason, audit.SystemScopes(l.db))
	switch {
	case err != nil && ctx.Err() != nil:
		return l.release(ctx, lease) // a shutdown during the grant, not a failure
	case err != nil:
		return err
	}
	renew := time.NewTicker(lease.ttlOr(TTL) / 3)
	defer renew.Stop()
	run := time.NewTimer(0)
	defer run.Stop()
	for {
		select {
		case <-ctx.Done():
			return l.release(ctx, lease)
		case <-renew.C:
			if err := l.Renew(ctx, lease); err != nil {
				if ctx.Err() != nil {
					return l.release(ctx, lease) // a shutdown during the renewal
				}
				return err
			}
		case <-run.C:
			if err := job.Run(sys, lease); err != nil {
				switch {
				case errors.Is(err, ErrLost):
					return err
				case ctx.Err() != nil:
					continue // a shutdown, not a failed run: the next pass releases the lease
				}
				onErr(err) // retried at the next interval; the lease stays
			}
			run.Reset(job.Every)
		}
	}
}

// release gives lease up once ctx is over, with a short context of its own.
func (l *Leases) release(ctx context.Context, lease Lease) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	return l.Release(rctx, lease)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
