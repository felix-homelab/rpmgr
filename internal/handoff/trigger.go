// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"context"
	"log/slog"
)

// Trigger runs a role's hand-offs on SIGUSR2 (docs/03, "Restarts with socket hand-off"):
// `systemctl reload`, `rpmgr handoff <role>`, the install scripts and the root updater send it.
// A signal names no binary and no descriptor.
type Trigger struct {
	// Dir is the role's runtime directory, /run/rpmgr/<role>, where the outcome goes.
	Dir string
	// Handoff runs one hand-off and returns the new process once it took over; nil while the role
	// has none, which refuses every hand-off.
	Handoff func(ctx context.Context) (*Child, error)
	Logger  *slog.Logger
}

// Outcome is a role's last hand-off, in OutcomeFile in its runtime directory.
type Outcome struct {
	// ID tells hand-offs apart: when it started, in Unix nanoseconds.
	ID     int64  `json:"id"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// OldPID is the process that handed off, NewPID the one that took over.
	OldPID int `json:"old_pid"`
	NewPID int `json:"new_pid,omitempty"`
	// Generation is the new process's.
	Generation uint64 `json:"generation,omitempty"`
}

// The states of an outcome.
const (
	StateRunning = "running"
	StateOK      = "ok"
	StateFailed  = "failed"  // the new process did not become ready; the old one serves on
	StateRefused = "refused" // no new process started
)

// OutcomeFile is the outcome's name in the runtime directory.
const OutcomeFile = "handoff.json"

// maxOutcome bounds the outcome file `rpmgr handoff` reads.
const maxOutcome = 64 << 10
