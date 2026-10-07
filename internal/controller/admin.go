// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"ariga.io/atlas/sql/migrate"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// migrationCheck is how long a readiness check trusts the last migration check.
const migrationCheck = time.Minute

// Readiness is the controller's readiness (docs/10-operations.md, "Health"): the database answers
// a read, and every embedded migration is applied, which it checks at most once a minute.
type Readiness struct {
	db  *store.DB
	dir migrate.Dir
	sys context.Context

	mu      sync.Mutex
	checked time.Time
	err     error
}

// NewReadiness returns the readiness check of a controller on db with the migrations of dir; sys
// is a system scope.
func NewReadiness(db *store.DB, dir migrate.Dir, sys context.Context) *Readiness {
	return &Readiness{db: db, dir: dir, sys: sys}
}

// Ready returns why the controller is not ready, or nil.
func (r *Readiness) Ready(ctx context.Context) error {
	if err := store.ReadTx(r.sys, r.db, func(*ent.Tx, store.Revision) error { return ctx.Err() }); err != nil {
		return fmt.Errorf("database: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) < migrationCheck {
		return r.err
	}
	pending, err := store.Pending(ctx, r.db, r.dir)
	switch {
	case err != nil:
		return fmt.Errorf("migrations: %w", err) // not cached: checked again next time
	case len(pending) > 0:
		r.err = fmt.Errorf("%d migrations not applied", len(pending))
	default:
		r.err = nil
	}
	r.checked = time.Now()
	return r.err
}

// Register adds the controller's control-session metrics to reg (docs/10-operations.md,
// "Metrics"): the agents connected here, and each agent's apply status.
func (s *Sessions) Register(reg prometheus.Registerer) error {
	return errors.Join(
		reg.Register(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "rpmgr_controller_control_sessions",
			Help: "Agents with a control session on this controller."}, func() float64 { return float64(len(s.Connected())) })),
		reg.Register(applyStatusCollector{s}),
	)
}

var applyStatusDesc = prometheus.NewDesc("rpmgr_agent_apply_status",
	"1 for each agent's current apply status: pending, applied, rejected or apply_timeout.", []string{"agent", "status"}, nil)

// applyStatusCollector reads agent_state at every scrape.
type applyStatusCollector struct{ s *Sessions }

func (applyStatusCollector) Describe(ch chan<- *prometheus.Desc) { ch <- applyStatusDesc }

func (c applyStatusCollector) Collect(ch chan<- prometheus.Metric) {
	states, err := c.s.db.ReadClient().AgentState.Query().All(c.s.sys)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(applyStatusDesc, err)
		return
	}
	now := c.s.now()
	for _, st := range states {
		ch <- prometheus.MustNewConstMetric(applyStatusDesc, prometheus.GaugeValue, 1, st.ID, string(ApplyStatus(st, now)))
	}
}
