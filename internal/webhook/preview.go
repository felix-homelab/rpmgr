// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/events"
)

// Sample is the body one sample event is posted as.
type Sample struct {
	EventType string
	Body      string // indented JSON
}

// Preview is what an endpoint of format f with the options and instance data of c would post for
// a sample alert that fires, the same alert resolving and a configuration change, for a form that
// shows them before the endpoint exists. It makes the messages as a delivery does, so a preview is
// never a different layout, and it names no URL: an endpoint's URL is no part of a message.
func Preview(f Format, c Context, now time.Time) ([]Sample, error) {
	if !f.Chat() {
		return nil, fmt.Errorf("webhook: %q has no chat message to preview", f)
	}
	if err := ValidateOptions(f, c.Options); err != nil {
		return nil, err
	}
	if c.OrgName == "" {
		c.OrgName = "Example org"
	}
	if c.ActorName == "" {
		c.ActorName = "Ada Admin"
	}
	now = now.UTC().Truncate(time.Second)
	fire := events.Event{ID: "evt_sample1", OrgID: "org_sample", Type: events.AlertFire, Time: now, ActorType: "system", SubjectType: "agent",
		SubjectID: "gw_sample", SubjectName: "gw-eu-1", Summary: "agent_offline: Agent offline fires, gw-eu-1"}
	resolve := fire
	resolve.ID, resolve.Type, resolve.Time, resolve.Summary = "evt_sample2", events.AlertResolve, now.Add(7*time.Minute+30*time.Second), "agent_offline: Agent offline resolved, gw-eu-1"
	change := events.Event{ID: "evt_sample3", OrgID: "org_sample", Type: "route.update", Time: now, ActorType: "user", ActorID: "usr_sample",
		SubjectType: "route", SubjectID: "rte_sample", SubjectName: "web", Summary: "route.update route web", Changed: []string{"enabled"}}
	var out []Sample
	for _, e := range []events.Event{fire, resolve, change} {
		ec := c
		if e.Type == events.AlertResolve {
			ec.FiredAt = fire.Time
		}
		b, err := ChatBody(f, e, ec)
		if err != nil {
			return nil, err
		}
		// Shown for people: <, > and & are written as themselves, which is the same JSON.
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, err
		}
		var pretty bytes.Buffer
		enc := json.NewEncoder(&pretty)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return nil, err
		}
		out = append(out, Sample{EventType: e.Type, Body: strings.TrimRight(pretty.String(), "\n")})
	}
	return out, nil
}
