// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"fmt"
	"time"

	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// StatusGap is the least time between two status events of one subject (docs/03-connections.md,
// "Timeouts, keepalive and backoff"): a subject that changes state faster reports its state once the
// gap passed, or nothing if it is back in the state last reported.
const StatusGap = time.Minute

// The kinds of status the job follows, the first part of a mark's ID.
const (
	StatusAgent = "agent" // connected or not: agent.connect, agent.disconnect
	StatusApply = "apply" // the snapshot sent last was rejected or not: apply.reject
	StatusRoute = "route" // the route's status: route.status
)

// States of the agent kind and of the apply kind.
const (
	StateOnline  = "online"
	StateOffline = "offline"
	StateOK      = "ok"
)

// StatusObservation is the state of one subject now. Unknown says the job cannot tell (an offline
// agent's configuration): its mark stays as it is. A subject without an observation is gone, and
// its mark goes.
type StatusObservation struct {
	OrgID       string // empty: an instance event
	Kind        string
	SubjectType string
	SubjectID   string
	SubjectName string
	State       string
	Unknown     bool
}

func markID(o StatusObservation) string { return o.Kind + ":" + o.SubjectID }

// ApplyStatus writes the status events of obs in tx, the job's fenced transaction, and moves the
// marks. A subject seen for the first time reports nothing, except an agent that is online and an
// apply that is rejected: those are news. A change inside StatusGap of the last one waits for it.
// Marks of subjects without an observation are deleted.
func ApplyStatus(ctx context.Context, tx *ent.Tx, now time.Time, obs []StatusObservation) ([]events.Event, error) {
	marks, err := tx.StatusMark.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*ent.StatusMark, len(marks))
	for _, m := range marks {
		byID[m.ID] = m
	}
	var out []events.Event
	seen := map[string]bool{}
	for _, o := range obs {
		id := markID(o)
		if seen[id] {
			continue
		}
		seen[id] = true
		if o.Unknown {
			continue
		}
		m := byID[id]
		if m == nil {
			c := tx.StatusMark.Create().SetID(id).SetState(o.State).SetChangedAt(now)
			if o.OrgID != "" {
				c.SetOrgID(o.OrgID)
			}
			// A first sight is news only where the state itself is: an agent's first connection and
			// a rejected snapshot. A route's first status, an agent first seen offline, are not.
			news := o.State == StateOnline || o.Kind == StatusApply && o.State != StateOK
			if news {
				ev, err := statusEvent(ctx, tx, o, "")
				if err != nil {
					return nil, err
				}
				out = append(out, ev)
			}
			if err := c.Exec(ctx); err != nil {
				return nil, fmt.Errorf("alerts: add mark %s: %w", id, err)
			}
			continue
		}
		if m.State == o.State || now.Sub(m.ChangedAt) < StatusGap {
			continue
		}
		if err := tx.StatusMark.UpdateOne(m).SetState(o.State).SetChangedAt(now).Exec(ctx); err != nil {
			return nil, err
		}
		// Only these changes are events: an agent coming and going, a snapshot rejected, a route's
		// new status. A rejection ending is no event.
		if o.Kind == StatusApply && o.State == StateOK {
			continue
		}
		ev, err := statusEvent(ctx, tx, o, m.State)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	for id, m := range byID {
		if !seen[id] {
			if err := tx.StatusMark.DeleteOne(m).Exec(ctx); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// statusEvent writes the event of o, whose state was from before. It carries names and states,
// never a resource: a receiver fetches the route or agent through the API.
func statusEvent(ctx context.Context, tx *ent.Tx, o StatusObservation, from string) (events.Event, error) {
	e := events.Event{OrgID: o.OrgID, SubjectType: o.SubjectType, SubjectID: o.SubjectID, SubjectName: o.SubjectName}
	name := o.SubjectName
	if name == "" {
		name = o.SubjectID
	}
	switch o.Kind {
	case StatusAgent:
		e.Type = "agent.connect"
		if o.State == StateOffline {
			e.Type = "agent.disconnect"
		}
	case StatusApply:
		e.Type, e.Changed = "apply.reject", []string{"applied_snapshot"}
		e.Summary = fmt.Sprintf("apply.reject %s %s: the snapshot sent last was rejected", o.SubjectType, name)
	default:
		e.Type, e.Changed = "route.status", []string{"status"}
		e.Summary = fmt.Sprintf("route.status route %s: %s", name, o.State)
		if from != "" {
			e.Summary = fmt.Sprintf("route.status route %s: %s, was %s", name, o.State, from)
		}
	}
	return events.Add(ctx, tx, e)
}
