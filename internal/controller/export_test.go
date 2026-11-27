// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
)

// SetRunTimers shortens the drain wait and the certificate reload interval of Run for one test,
// which must not run in parallel with others.
func SetRunTimers(t testing.TB, drain, reload time.Duration) {
	oldDrain, oldReload, oldSettle := drainWait, webCertReload, lockSettle
	drainWait, webCertReload, lockSettle = drain, reload, func() time.Duration { return 0 }
	t.Cleanup(func() { drainWait, webCertReload, lockSettle = oldDrain, oldReload, oldSettle })
}

// SetStateDir makes the commands that read a boot file use dir as the state directory of a
// controller on PostgreSQL, for one test, which must not run in parallel with others.
func SetStateDir(t testing.TB, dir string) {
	old := stateDirOverride
	stateDirOverride = dir
	t.Cleanup(func() { stateDirOverride = old })
}

// SetLockSettle sets how long Run waits after it took the PostgreSQL controller lock, for one
// test, which must not run in parallel with others.
func SetLockSettle(t testing.TB, d time.Duration) {
	old := lockSettle
	lockSettle = func() time.Duration { return d }
	t.Cleanup(func() { lockSettle = old })
}

// NoJobs keeps Run from starting its background jobs (alerts, webhooks, DNS, mail, ...) for one
// test, which must not run in parallel with others.
func NoJobs(t testing.TB) {
	old := noJobs
	noJobs = true
	t.Cleanup(func() { noJobs = old })
}

// SetOperationTimers shortens the ticket validity and the deadline of imperative operations for
// one test, which must not run in parallel with others.
func SetOperationTimers(t testing.TB, ticket, deadline time.Duration) {
	oldTicket, oldDeadline := ticketValid, operationDeadline
	ticketValid, operationDeadline = ticket, deadline
	t.Cleanup(func() { ticketValid, operationDeadline = oldTicket, oldDeadline })
}

// WebMaxStreams is how many requests one HTTP/2 connection to the web server may have open.
const WebMaxStreams = webMaxStreams

// EndLeftOpen runs what seenLoop does first: it ends the sessions a stopped run left open.
func (s *Sessions) EndLeftOpen() { s.endLeftOpen() }

// SealedColumns lists the sealed columns `rpmgr kek rotate` re-wraps, as "table.column".
func SealedColumns() []string {
	out := make([]string, len(sealedColumns))
	for i, c := range sealedColumns {
		out[i] = c.table + "." + c.column
	}
	return out
}

// OlderThan reports whether agent version v is older than min, as Hello checks it.
func OlderThan(v, min string) bool { return olderThan(v, min) }

// NextReleaseCheck is nextReleaseCheck.
var NextReleaseCheck = nextReleaseCheck

// RunRollout runs one step of the rollout job.
func RunRollout(ctx context.Context, o RolloutOptions) error { return runRollout(ctx, o) }

// RolloutDrainPeriod is how long a gateway drains before the job offers it the release.
const RolloutDrainPeriod = rolloutDrainPeriod

// NewUpdateRecorder is a Sessions value that records agent update states, without a session.
func NewUpdateRecorder(db *store.DB, sys context.Context) *Sessions {
	return &Sessions{db: db, sys: sys, log: slog.New(slog.DiscardHandler)}
}

// RecordUpdate records one agent's update state, as the Status handler does.
func (s *Sessions) RecordUpdate(id pki.Identity, u *agentv1.UpdateState) { s.recordUpdate(id, u) }

// RolloutUpdateState is rolloutUpdateState.
func RolloutUpdateState(cur rollouttarget.State, u *agentv1.UpdateState, version string) (rollouttarget.State, string, bool) {
	return rolloutUpdateState(cur, u, version)
}

// LoopbackWebhooks lets every endpoint of o's job reach loopback, where tests' receivers listen.
func LoopbackWebhooks(o WebhookOptions) WebhookOptions {
	o.policy = func(*ent.Webhook) egress.Policy { return egress.Policy{Internal: true} }
	return o
}

// OnRestoreStep runs f at each step of Restore ("staged", "copying", "moving", "installing") until
// the test ends.
func OnRestoreStep(t testing.TB, f func(step string)) {
	restoreHook = f
	t.Cleanup(func() { restoreHook = nil })
}

// KMSProbe is a Transit KEK opened as Run does, with the metrics and the readiness check of a
// controller.
type KMSProbe struct {
	Registry *prometheus.Registry
	// Ready is the readiness answer.
	Ready func(context.Context) error
	// Touch makes a request of the kind a running controller makes, which a failure turns into a
	// not-ready controller.
	Touch func(context.Context) error
}

// OpenKMSWithMetrics opens the Transit key of cfg as Run does, with log as the client's logger. The
// probe is returned even when opening fails, with only its Registry.
func OpenKMSWithMetrics(ctx context.Context, cfg config.Controller, log *slog.Logger) (*KMSProbe, error) {
	h := newKMSHealth()
	p := &KMSProbe{Registry: prometheus.NewRegistry(), Ready: h.Ready}
	for _, c := range h.Collectors() {
		if err := p.Registry.Register(c); err != nil {
			return nil, err
		}
	}
	w, err := openKEK(ctx, cfg, nil, log, h.observe)
	if err != nil {
		return p, err
	}
	h.probe = w.Probe
	p.Touch = func(ctx context.Context) error {
		_, err := w.Wrap(ctx, make([]byte, 32), []byte("probe"))
		return err
	}
	return p, nil
}

// SetLocalLog replaces the logger of the Transit client in local commands for one test.
func SetLocalLog(t testing.TB, l *slog.Logger) {
	old := kmsLog
	kmsLog = l
	t.Cleanup(func() { kmsLog = old })
}

// KMSReady is the readiness answer of the Transit health after observing results, as the client
// reports them. While it is down, Ready reads the key again; that request has the result probe.
func KMSReady(ctx context.Context, probe string, results ...string) error {
	h := newKMSHealth()
	h.probe = func(context.Context) error {
		h.observe("check", probe)
		if probe != "ok" {
			return errors.New("check failed")
		}
		return nil
	}
	for _, r := range results {
		h.observe("encrypt", r)
	}
	return h.Ready(ctx)
}

// SetMigrateHook sets the hook MigrateDB calls at "before copy" and "after copy".
func SetMigrateHook(t testing.TB, f func(stage string)) {
	migrateHook = f
	t.Cleanup(func() { migrateHook = nil })
}

// PlanTarget notes the files of a SQLite target that do not exist yet; remove removes those.
func PlanTarget(path string) (remove func(), err error) {
	p, err := planTarget(config.Database{Driver: "sqlite", DSN: path})
	if err != nil {
		return nil, err
	}
	return p.remove, nil
}

// SetEffectiveUID makes migrate-db believe it runs as uid.
func SetEffectiveUID(t testing.TB, uid int) {
	effectiveUID = func() int { return uid }
	t.Cleanup(func() { effectiveUID = os.Geteuid })
}
