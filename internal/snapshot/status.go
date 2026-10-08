// SPDX-License-Identifier: Apache-2.0

package snapshot

import (
	"bytes"
	"time"

	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// ApplyTimeout is how long an agent has to answer a snapshot before it is apply_timeout
// (docs/03-connections.md, "Timeouts, keepalive and backoff").
const ApplyTimeout = 30 * time.Second

// ApplyState is an agent's apply status (docs/03-connections.md, "Configuration reconciliation",
// rule 7).
type ApplyState string

// The apply states.
const (
	ApplyPending  ApplyState = "pending"
	ApplyApplied  ApplyState = "applied"
	ApplyRejected ApplyState = "rejected"
	ApplyTimedOut ApplyState = "apply_timeout"
)

// ApplyStatus derives the apply status of the snapshot an agent was sent last from its state at
// now.
func ApplyStatus(st *ent.AgentState, now time.Time) ApplyState {
	switch {
	case len(st.PushedHash) == 0 || st.PushedAt == nil:
		return ApplyPending
	case bytes.Equal(st.PushedHash, st.AppliedHash):
		return ApplyApplied
	case bytes.Equal(st.PushedHash, st.RejectedHash):
		return ApplyRejected
	case now.Sub(*st.PushedAt) >= ApplyTimeout:
		return ApplyTimedOut
	}
	return ApplyPending
}

// RevisionStatus derives an agent's apply status of revision rev from its state at now: applied
// once it runs a snapshot of rev or later, which an agent whose snapshot rev did not change gets
// at once; rejected or apply_timeout if the snapshot of rev or later it was sent last was; pending
// otherwise, also for an agent of an older database epoch.
func RevisionStatus(st *ent.AgentState, rev store.Revision, now time.Time) ApplyState {
	switch {
	case st == nil:
		return ApplyPending
	case st.AppliedDbEpoch == rev.DBEpoch && st.AppliedSeq >= rev.Seq:
		return ApplyApplied
	case st.PushedDbEpoch != rev.DBEpoch || st.PushedSeq < rev.Seq:
		return ApplyPending
	}
	if s := ApplyStatus(st, now); s == ApplyRejected || s == ApplyTimedOut {
		return s
	}
	return ApplyPending
}
