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

// Restart runs systemctl restart, which waits until the unit has started.
func (s Systemd) Restart(ctx context.Context, unit string) error {
	out, err := exec.CommandContext(ctx, s.cmd(), "restart", unit).CombinedOutput() //nolint:gosec // G204: a fixed unit name
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// State reads the unit's ActiveState and NRestarts, the restarts systemd made by Restart=.
func (s Systemd) State(ctx context.Context, unit string) (bool, int, error) {
	out, err := exec.CommandContext(ctx, s.cmd(), "show", "--property=ActiveState,NRestarts", unit).Output() //nolint:gosec // G204: a fixed unit name
	if err != nil {
		return false, 0, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	var failed bool
	var restarts int
	for line := range bytes.Lines(out) {
		k, v, ok := strings.Cut(strings.TrimSpace(string(line)), "=")
		if !ok {
			continue
		}
		switch k {
		case "ActiveState":
			failed = v == "failed"
		case "NRestarts":
			if n, err := strconv.Atoi(v); err == nil {
				restarts = n
			}
		}
	}
	return failed, restarts, nil
}
