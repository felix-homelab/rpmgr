// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// liveLogRate is how many lines a live-log operation sends per second at most
// (docs/03-connections.md, "Timeouts, keepalive and backoff"); the others are dropped and counted.
const liveLogRate = 200

// serveLogs runs a live-log operation (docs/03-connections.md, "Control session"): it subscribes
// to the agent's live log at the operation's level and filter, raised to debug if it asks, and
// sends each line until ctx ends. Lines the buffer or the rate dropped are counted in the next
// line's dropped_before; the agent's backlog (D154) is sent first, marked; a slow controller never slows the agent's logging.
func serveLogs(ctx context.Context, live *telemetry.LiveLog, p *agentv1.LogParams, send func(*agentv1.AttachFrame) error) error {
	level, err := telemetry.ParseLevel(p.GetLevel())
	if err != nil {
		return err
	}
	sub := live.Subscribe(level, p.GetFilter(), p.GetRaiseToDebug())
	defer sub.Close()
	tokens, last := float64(liveLogRate), time.Now()
	dropped := 0
	// The backlog goes first, marked, the first line with how many older lines are gone; it is not
	// rate-limited, as it is at most the backlog's bound (docs/03-connections.md).
	earlier, gone := sub.Backlog()
	for _, l := range earlier {
		if err := send(logFrame(l, gone, true)); err != nil {
			return fmt.Errorf("agent: sending a backlog line: %w", err)
		}
		gone = 0
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sub.Ready():
		}
		lines, d := sub.Take()
		dropped += d
		for _, l := range lines {
			now := time.Now()
			tokens = min(float64(liveLogRate), tokens+now.Sub(last).Seconds()*liveLogRate)
			last = now
			if tokens < 1 {
				dropped++
				continue
			}
			tokens--
			if err := send(logFrame(l, dropped, false)); err != nil {
				return fmt.Errorf("agent: sending a log line: %w", err)
			}
			dropped = 0
		}
	}
}

// logFrame is the frame of a line; backlog marks one kept from before the log opened.
func logFrame(l telemetry.Line, dropped int, backlog bool) *agentv1.AttachFrame {
	return &agentv1.AttachFrame{Frame: &agentv1.AttachFrame_Log{Log: &agentv1.LogLine{Time: timestamppb.New(l.Time),
		Level: levelName(l.Level), Text: l.Text, DroppedBefore: uint32(dropped), Truncated: l.Truncated, Backlog: backlog}}} //nolint:gosec // G115: a count of lines
}

// levelName names a level as live logs do.
func levelName(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return "debug"
	case l < slog.LevelWarn:
		return "info"
	case l < slog.LevelError:
		return "warn"
	}
	return "error"
}
