// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"log/slog"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
)

// SetRunTimers shortens the drain wait and the certificate reload interval of Run for one test,
// which must not run in parallel with others.
func SetRunTimers(t testing.TB, drain, reload time.Duration) {
	oldDrain, oldReload := drainWait, webCertReload
	drainWait, webCertReload = drain, reload
	t.Cleanup(func() { drainWait, webCertReload = oldDrain, oldReload })
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
