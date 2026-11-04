// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/felix-homelab/rpmgr/internal/alerts"
	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/event"
)

// Context is what a chat message shows besides the event itself (docs/07-api.md, "Webhooks
// (Phase 2)"; D170). Every field is optional: a message without one omits what it would show.
type Context struct {
	// OrgName and ActorName are shown in place of the IDs the event carries.
	OrgName, ActorName string
	// FiredAt is, for an alert.resolve, when the alert fired.
	FiredAt time.Time
	// PublicURL is the controller's public URL, the base of the link to the subject; without it
	// the message has no link and no button.
	PublicURL string
	// TrustDomain and Version are the footer.
	TrustDomain, Version string
}

// Resolve fills the names of ctx for e from the store: the organisation's, the user's and, for a
// resolved alert, the time it fired. It is meant for the moment a message is made, asks for
// nothing that is cached and never fails: what a lookup cannot find stays empty, and the message
// shows the ID.
func (c *Context) Resolve(ctx context.Context, db *ent.Client, e events.Event) {
	if db == nil {
		return
	}
	if e.OrgID != "" {
		if o, err := db.Org.Get(ctx, e.OrgID); err == nil {
			c.OrgName = o.Name
		}
	}
	if e.ActorType == "user" && e.ActorID != "" {
		if u, err := db.User.Get(ctx, e.ActorID); err == nil {
			c.ActorName = u.DisplayName
		}
	}
	if e.Type == "alert.resolve" {
		kind, _, _ := strings.Cut(e.Summary, ":")
		q := db.Event.Query().Where(event.TypeEQ("alert.fire"), event.SubjectTypeEQ(e.SubjectType), event.SubjectID(e.SubjectID),
			event.SummaryHasPrefix(kind+":"), event.TsLTE(e.Time))
		if e.OrgID != "" {
			q = q.Where(event.OrgID(e.OrgID))
		} else {
			q = q.Where(event.OrgIDIsNil())
		}
		if fire, err := q.Order(ent.Desc(event.FieldTs), ent.Desc(event.FieldID)).First(ctx); err == nil {
			c.FiredAt = fire.Ts
		}
	}
}

// severity orders what a message looks like: its colour.
type severity int

const (
	sevNeutral  severity = iota // audit and other events: grey
	sevInfo                     // blue
	sevWarning                  // amber
	sevCritical                 // red
	sevResolved                 // green
)

// criticalKinds are the alert kinds that need someone now; every other alert is a warning.
var criticalKinds = map[string]bool{alerts.AgentOffline: true, alerts.RouteNoReadyTarget: true,
	alerts.AgentCertExpiring: true, alerts.PublicCertExpiring: true}

type fact struct{ Name, Value string }

// message is an event as people read it, before a service's markup: every text is plain.
type message struct {
	title, text string
	sev         severity
	facts       []fact
	link        string // "" when there is no public URL
	footer      string
	ids         string
	at          time.Time
	critical    bool // an alert of a critical kind (a mention of "critical alerts" fires)
	alert       bool
}

// compose is the message of e. It reads only the envelope and c.
func compose(e events.Event, c Context) message {
	name := firstNonEmpty(e.SubjectName, e.SubjectID)
	m := message{at: e.Time.UTC(), link: linkOf(c.PublicURL, e), sev: sevNeutral}
	org := firstNonEmpty(c.OrgName, e.OrgID, "instance")
	subject := strings.TrimSpace(e.SubjectType + " " + name)
	actor := firstNonEmpty(c.ActorName, strings.TrimSpace(e.ActorType+" "+e.ActorID))
	at := e.Time.UTC().Format("2006-01-02 15:04:05 UTC")
	switch e.Type {
	case "alert.fire", "alert.resolve":
		kind, _, _ := strings.Cut(e.Summary, ":")
		m.alert, m.critical = true, criticalKinds[kind]
		m.title = alertTitle(kind, e.SubjectType, name)
		m.sev = sevWarning
		if m.critical {
			m.sev = sevCritical
		}
		m.text = "Firing since " + at + "."
		m.facts = []fact{{"Organisation", org}, {"Subject", subject}, {"Alert", firstNonEmpty(kind, e.Type)}}
		if e.Type == "alert.resolve" {
			m.title, m.sev, m.text = "Resolved: "+m.title, sevResolved, "Resolved."
			if !c.FiredAt.IsZero() && !e.Time.Before(c.FiredAt) {
				d := humanDuration(e.Time.Sub(c.FiredAt))
				m.text = "Resolved after " + d + "."
				m.facts = append(m.facts, fact{"Lasted", d})
			}
		}
	default:
		m.title, m.text = eventTitle(e, name), e.Summary
		switch e.Type {
		case "webhook.disable", "apply.reject", "agent.disconnect":
			m.sev = sevWarning
		case "webhook.test", "agent.connect", "route.status":
			m.sev = sevInfo
		}
		m.facts = []fact{{"Organisation", org}, {"Actor", actor}, {"Subject", subject}}
		if len(e.Changed) > 0 {
			m.facts = append(m.facts, fact{"Changed", strings.Join(e.Changed, ", ")})
		}
	}
	var ids []string
	for _, id := range []string{e.OrgID, e.SubjectID, e.ID} {
		if id != "" {
			ids = append(ids, id)
		}
	}
	m.ids = strings.Join(ids, " · ")
	foot := []string{}
	if c.TrustDomain != "" {
		foot = append(foot, c.TrustDomain)
	}
	if c.Version != "" {
		foot = append(foot, "rpmgr "+c.Version)
	}
	m.footer = strings.Join(foot, " · ")
	return m
}

func alertTitle(kind, subjectType, name string) string {
	if kind == alerts.AgentOffline {
		return capital(firstNonEmpty(subjectType, "agent")) + " " + name + " is offline"
	}
	return alerts.Title(kind) + ": " + name
}

var pastTense = map[string]string{"create": "created", "update": "updated", "delete": "deleted", "enable": "enabled",
	"disable": "disabled", "revoke": "revoked", "rotate": "rotated", "approve": "approved", "reject": "rejected"}

// eventTitle is the title of an event that is no alert: <Resource> <name> <verb in the past>.
func eventTitle(e events.Event, name string) string {
	switch e.Type {
	case "webhook.test":
		return "Test event from rpmgr"
	case "webhook.disable":
		return "Webhook " + name + " was disabled"
	case "agent.connect":
		return "Agent " + name + " connected"
	case "agent.disconnect":
		return "Agent " + name + " disconnected"
	case "apply.reject":
		return "Configuration rejected on " + name
	case "route.status":
		return "Route " + name + " changed status"
	}
	res, verb, ok := strings.Cut(e.Type, ".")
	if !ok {
		return capital(strings.ReplaceAll(e.Type, "_", " ")) + " " + name
	}
	res = strings.ReplaceAll(res, "_", " ")
	if p, ok := pastTense[verb]; ok {
		verb = p
	}
	return strings.TrimSpace(capital(res) + " " + name + " " + strings.ReplaceAll(verb, "_", " "))
}

func capital(s string) string {
	for i, r := range s {
		return string(unicode.ToUpper(r)) + s[i+len(string(r)):]
	}
	return s
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// humanDuration is d in its two largest units, with a space: 5 m 3 s, 2 h 10 m, 3 d 4 h.
func humanDuration(d time.Duration) string {
	d = d.Round(time.Second)
	units := []struct {
		n    time.Duration
		name string
	}{{24 * time.Hour, "d"}, {time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}}
	var parts []string
	for _, u := range units {
		if d >= u.n {
			parts = append(parts, fmt.Sprintf("%d %s", d/u.n, u.name))
			d %= u.n
		}
		if len(parts) == 2 {
			break
		}
	}
	if len(parts) == 0 {
		return "0 s"
	}
	return strings.Join(parts, " ")
}

// linkOf is the address of the event's subject in the web UI, built from public, or "" when there
// is no public URL. The paths are those of the web router (web/src/router.tsx).
func linkOf(public string, e events.Event) string {
	u, err := url.Parse(strings.TrimSpace(public))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return ""
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/") + subjectPath(e)
}

// subjectPath is the path of the page that shows e's subject.
func subjectPath(e events.Event) string {
	id := url.PathEscape(e.SubjectID)
	switch e.SubjectType {
	case "route":
		if id != "" {
			return "/routes/" + id
		}
		return "/routes"
	case "connector":
		if id != "" {
			return "/connectors/" + id
		}
		return "/connectors"
	case "agent":
		if strings.HasPrefix(e.SubjectID, "con_") {
			return "/connectors/" + id
		}
		return "/gateways"
	case "gateway", "gateway_group":
		return "/gateways"
	case "domain":
		return "/domains"
	case "policy":
		return "/policies"
	case "webhook":
		if e.OrgID == "" {
			return "/settings/webhooks"
		}
		return "/webhooks"
	case "org":
		return "/org"
	case "user":
		return "/settings/users"
	case "pki", "certificate":
		return "/settings/pki"
	}
	if strings.HasPrefix(e.Type, "alert.") {
		return "/"
	}
	return "/audit"
}
