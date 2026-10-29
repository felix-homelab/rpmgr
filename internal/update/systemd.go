// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Systemd restarts and watches units through systemctl.
type Systemd struct {
	// Systemctl is the command; empty means "systemctl" on PATH.
	Systemctl string
}

func (s Systemd) cmd() string {
	if s.Systemctl != "" {
		return s.Systemctl
	}
	return "systemctl"
}

// Restart runs systemctl restart, which waits until the unit has started. It reloads systemd
// first, so that a unit or drop-in file changed since, such as one a rollback removed, applies.
func (s Systemd) Restart(ctx context.Context, unit string) error {
	if out, err := exec.CommandContext(ctx, s.cmd(), "daemon-reload").CombinedOutput(); err != nil { //nolint:gosec // G204: a fixed argument
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	out, err := exec.CommandContext(ctx, s.cmd(), "restart", unit).CombinedOutput() //nolint:gosec // G204: a fixed unit name
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Handoff restarts the role with a socket hand-off: it runs `<bin> handoff <role>`, bin being the
// installed binary and not the running image, which the update left as "(deleted)". The command
// returns when the new process is ready, or when the hand-off failed, which leaves the old one
// serving. Its message is the error.
func (s Systemd) Handoff(ctx context.Context, bin, role string) error {
	out, err := exec.CommandContext(ctx, bin, "handoff", role).CombinedOutput() //nolint:gosec // G204: the installed binary, a fixed role
	if err != nil {
		return fmt.Errorf("%s handoff %s: %w: %s", bin, role, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// State reads the unit's ActiveState, NRestarts, the restarts systemd made by Restart=, MainPID
// and whether its Type is notify.
func (s Systemd) State(ctx context.Context, unit string) (Unit, error) {
	out, err := exec.CommandContext(ctx, s.cmd(), "show", "--property=ActiveState,NRestarts,MainPID,Type", unit).Output() //nolint:gosec // G204: a fixed unit name
	if err != nil {
		return Unit{}, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	var u Unit
	for line := range bytes.Lines(out) {
		k, v, ok := strings.Cut(strings.TrimSpace(string(line)), "=")
		if !ok {
			continue
		}
		switch k {
		case "ActiveState":
			u.Active = v
		case "NRestarts":
			if n, err := strconv.Atoi(v); err == nil {
				u.Restarts = n
			}
		case "Type":
			u.Notify = v == "notify"
		case "MainPID":
			if n, err := strconv.Atoi(v); err == nil {
				u.MainPID = n
			}
		}
	}
	if u.Active == "" {
		return Unit{}, fmt.Errorf("systemctl show %s: no ActiveState", unit)
	}
	return u, nil
}
