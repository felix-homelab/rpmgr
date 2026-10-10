// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
)

// The data-session report (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	ReportEvery = 60 * time.Second // how often a gateway reports its data sessions
	reportAfter = time.Second      // how long a report of changes waits for more of them
)

// reporter sends the gateway's data sessions and route counters to the controller: every
// ReportEvery, and a second after the data sessions change.
type reporter struct {
	changed chan struct{}
}

func newReporter() *reporter { return &reporter{changed: make(chan struct{}, 1)} }

// change notes that the data sessions changed.
func (r *reporter) change() {
	select {
	case r.changed <- struct{}{}:
	default:
	}
}

// run reports until ctx ends; a report the control session cannot take is dropped, as the next
// one lists every session again.
func (r *reporter) run(ctx context.Context, every time.Duration, send func(*agentv1.AgentMessage) bool, report func() *agentv1.Status) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.changed:
			select {
			case <-ctx.Done():
				return
			case <-time.After(reportAfter):
			}
		}
		send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: report()}})
	}
}
