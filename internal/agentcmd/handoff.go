// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"time"

	"github.com/felix-homelab/rpmgr/internal/cli"
	"github.com/felix-homelab/rpmgr/internal/handoff"
	"github.com/felix-homelab/rpmgr/internal/update"
)

// handoffRoles are the roles that restart with socket hand-off: their units are Type=notify and
// they take SIGUSR2 (docs/03, "Restarts with socket hand-off"; D148, D149).
var handoffRoles = []string{"gateway", "all-in-one", "connector"}

// RunDir is the runtime directory of the roles, /run/rpmgr/<role> (RuntimeDirectory=); a test
// replaces it.
var RunDir = "/run/rpmgr"

// handoffWait is how long `rpmgr handoff` waits for the outcome: the readiness window, and the
// time before it for the binary check and the start (docs/03, "Timeouts, keepalive and backoff").
const handoffWait = handoff.ReadinessWindow + 30*time.Second

// mainPID returns the main process of a role's unit; a test replaces it.
var mainPID = func(ctx context.Context, role string) (int, error) {
	u, err := update.Systemd{}.State(ctx, "rpmgr-"+role+".service")
	return u.MainPID, err
}

// startHandoffs makes a role that restarts with socket hand-off ready for systemd (Type=notify)
// and starts taking SIGUSR2. The roles adopt sockets from 17.10 on; until then a hand-off is
// refused and the role keeps running.
func startHandoffs(ctx context.Context, env *cli.Env, role string) (stop func()) {
	if !slices.Contains(handoffRoles, role) {
		return func() {}
	}
	log := slog.New(slog.NewTextHandler(env.Stderr, nil)).With("role", role)
	if err := handoff.Notify(env.Getenv); err != nil {
		log.Warn("telling systemd the role runs", "error", err)
	}
	return (&handoff.Trigger{Dir: filepath.Join(RunDir, role), Logger: log}).Start(ctx)
}

// Handoff is `rpmgr handoff <role>`.
func Handoff() *cli.Command {
	return &cli.Command{
		Name:    "handoff",
		Summary: "restart a running gateway, all-in-one or connector with socket hand-off",
		Args:    "gateway|all-in-one|connector",
		Run: func(ctx context.Context, env *cli.Env, args []string) error {
			if len(args) != 1 || !slices.Contains(handoffRoles, args[0]) {
				return cli.Usagef("name one role: gateway, all-in-one or connector")
			}
			return runHandoff(ctx, env, args[0], 100*time.Millisecond, handoffWait)
		},
	}
}

// runHandoff signals the role's main process and waits for the outcome of the hand-off it starts.
func runHandoff(ctx context.Context, env *cli.Env, role string, poll, wait time.Duration) error {
	pid, err := mainPID(ctx, role)
	if err != nil {
		return fmt.Errorf("no systemd unit rpmgr-%s.service (a container restarts without a hand-off): %w", role, err)
	}
	if pid <= 0 {
		return fmt.Errorf("rpmgr-%s.service does not run", role)
	}
	dir := filepath.Join(RunDir, role)
	before, err := handoff.ReadOutcome(dir)
	if err == nil && before.State == handoff.StateRunning && before.OldPID == pid {
		return errors.New("refused: a hand-off is in progress")
	}
	if err := handoff.Signal(pid); err != nil {
		return fmt.Errorf("signalling process %d: %w", pid, err)
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("no outcome from process %d within %v; see journalctl -u rpmgr-%s", pid, wait, role)
		case <-t.C:
		}
		o, err := handoff.ReadOutcome(dir)
		if err != nil || o.OldPID != pid || o.ID == before.ID || o.State == handoff.StateRunning {
			continue
		}
		if o.State != handoff.StateOK {
			return fmt.Errorf("hand-off %s: %s; process %d serves on", o.State, o.Reason, pid)
		}
		_, err = fmt.Fprintf(env.Stdout, "Process %d handed rpmgr-%s over to process %d (generation %d).\n", pid, role, o.NewPID, o.Generation)
		return err
	}
}
