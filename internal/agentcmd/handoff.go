// SPDX-License-Identifier: Apache-2.0

package agentcmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"sync/atomic"
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

// readyRoles are the roles that report their own readiness and adopt the sockets of a hand-off
// (handoff.LinkFrom): the gateway. The others are ready for systemd (Type=notify) and take
// SIGUSR2 as soon as they run, and refuse a hand-off, until their slices of 17.10 to 17.9 land.
var readyRoles = []string{"gateway"}

// startHandoffs prepares a role for socket hand-off: it takes the hand-off that started this
// process, if any, and returns a context that carries the role's handoff.Link. The Link starts
// taking SIGUSR2 and tells systemd (Type=notify) where the role is ready: at once for a role not in
// readyRoles, else when the role calls Link.Ready. finish is called with the role's result. A hand-off
// that is refused, or not for this role, is an error: the process exits and the old one serves on.
func startHandoffs(ctx context.Context, env *cli.Env, role string) (_ context.Context, finish func(error), err error) {
	if !slices.Contains(handoffRoles, role) {
		return ctx, func(error) {}, nil
	}
	log := slog.New(slog.NewTextHandler(env.Stderr, nil)).With("role", role)
	var inherited *handoff.Handoff
	if slices.Contains(readyRoles, role) {
		if inherited, err = handoff.Inherited(env.Getenv); err != nil {
			return ctx, nil, err
		}
	}
	trigger := &handoff.Trigger{Dir: filepath.Join(RunDir, role), Logger: log}
	var stop atomic.Pointer[func()]
	link := handoff.NewLink(inherited, env.Getenv, func() { f := trigger.Start(ctx); stop.Store(&f) })
	trigger.Handoff = link.Handoff
	if !slices.Contains(readyRoles, role) {
		if err := link.Ready(); err != nil {
			log.Warn("telling systemd the role runs", "error", err)
		}
	}
	return handoff.WithLink(ctx, link), func(err error) {
		link.Finish(err)
		if f := stop.Load(); f != nil {
			(*f)()
		}
	}, nil
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
	if !handoff.Capable(dir, pid) {
		// An older release ends on SIGUSR2; one that is still starting has no trigger yet.
		return fmt.Errorf("refused: process %d of rpmgr-%s does not take hand-offs: it is a release without them "+
			"or has not finished starting; `systemctl restart rpmgr-%s` restarts it without one", pid, role, role)
	}
	before, err := handoff.ReadOutcome(dir)
	if err == nil && before.State == handoff.StateRunning && before.OldPID == pid {
		return errors.New("refused: a hand-off is in progress")
	}
	if err := handoff.Signal(pid); err != nil {
		return fmt.Errorf("signalling process %d: %w", pid, err)
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if parent.Err() != nil {
				return fmt.Errorf("stopped while waiting for the outcome from process %d: %w", pid, parent.Err())
			}
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
