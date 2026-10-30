// SPDX-License-Identifier: Apache-2.0

// Package events writes the outbox of events that webhooks deliver (docs/07-api.md, "Webhooks
// (Phase 2)"; docs/06-data-model.md, "Observability (Phase 2)"). An event is written in the
// transaction of the change it reports, so it exists exactly when the change committed: the audit
// append writes one for every change it records as a success, and status changes write their own.
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/event"
)

// Keep is how long events are kept (docs/03-connections.md, "Timeouts, keepalive and backoff").
const Keep = 7 * 24 * time.Hour

// Caps on the free-text fields of an event; longer values are cut, never refused.
const (
	maxName    = 255
	maxSummary = 500
)

// Event is one event: the envelope of D144, which names its subject and the changed fields but
// carries no resource, secret or other org's data.
type Event struct {
	ID          string
	OrgID       string // empty: an instance event
	Type        string
	Time        time.Time
	ActorType   string // user, agent, system or anonymous
	ActorID     string
	SubjectType string
	SubjectID   string
	SubjectName string
	Summary     string
	Changed     []string
}

// Add writes e in tx, the transaction of the change it reports, and returns it with its ID and
// time. The IDs of one process's events sort in the order Add made them, which is not the order
// their transactions commit in: a reader must not page through events by "ID after the last one
// read", or it skips an event whose transaction committed late.
func Add(ctx context.Context, tx *ent.Tx, e Event) (Event, error) {
	if e.Type == "" {
		return Event{}, fmt.Errorf("events: an event without a type")
	}
	if e.ActorType == "" {
		e.ActorType = "system"
	}
	e.ID = ids.New("evt")
	e.Time = time.Now().UTC().Truncate(time.Microsecond)
	e.SubjectName = cut(e.SubjectName, maxName)
	if e.Summary == "" {
		e.Summary = summary(e)
	}
	e.Summary = cut(e.Summary, maxSummary)
	var org, changed any
	if e.OrgID != "" {
		org = e.OrgID
	}
	if len(e.Changed) > 0 {
		b, err := json.Marshal(e.Changed)
		if err != nil {
			return Event{}, err
		}
		changed = string(b)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO events (id, org_id, type, ts, actor_type, actor_id, subject_type,
		subject_id, subject_name, summary, changed) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		e.ID, org, e.Type, e.Time, e.ActorType, e.ActorID, e.SubjectType, e.SubjectID, e.SubjectName, e.Summary, changed)
	if err != nil {
		return Event{}, fmt.Errorf("events: add %s: %w", e.Type, err)
	}
	return e, nil
}

// summary is a short line for people: the type and the subject.
func summary(e Event) string {
	subject := e.SubjectName
	if subject == "" {
		subject = e.SubjectID
	}
	return strings.TrimSpace(strings.Join([]string{e.Type, e.SubjectType, subject}, " "))
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// notChanges are the audited actions that change no configuration and so are no events: signing
// in and out, a step-up, asking for a reset link, the use of a token or a system scope, opening a
// live log, pruning the audit log, and a test send to a webhook, which is its own event.
var notChanges = map[string]bool{
	"rpmgr.v1.AuthService.Login": true, "rpmgr.v1.AuthService.StepUp": true, "rpmgr.v1.AuthService.Logout": true,
	"rpmgr.v1.AuthService.RequestPasswordReset": true, "session.login": true, "token.use": true,
	"system_scope.grant": true, "job.run": true, "agent.logs_open": true, "audit.prune": true,
	// TestWebhook sends its own webhook.test event to the endpoint it tests.
	"rpmgr.v1.WebhookService.TestWebhook": true, "rpmgr.v1.InstanceWebhookService.TestInstanceWebhook": true,
}

// FromAudit reports whether an audit entry of action with result is an event: every change its
// chain records as a success (docs/07-api.md, "Webhooks (Phase 2)").
func FromAudit(action, result string) bool {
	return result == "success" && !notChanges[action]
}

// TypeOf is the event type of an audit action. A service's own action, such as route.update, is
// its type; an API request's, the method's full name, becomes <resource>.<verb>:
// rpmgr.v1.RouteService.UpdateRoute is route.update, CreateRouteTarget route_target.create. A
// method that is a verb alone takes its service's name: rpmgr.v1.AuthService.RevokeSession is
// session.revoke, but Logout of AuthService is auth.logout.
func TypeOf(action string) string {
	if !strings.HasPrefix(action, "rpmgr.") {
		return action
	}
	parts := strings.Split(action, ".")
	method := parts[len(parts)-1]
	i := 1
	for i < len(method) && !unicode.IsUpper(rune(method[i])) {
		i++
	}
	verb, noun := method[:i], method[i:]
	if noun == "" && len(parts) >= 2 {
		noun = strings.TrimSuffix(parts[len(parts)-2], "Service")
	}
	return snake(noun) + "." + snake(verb)
}

// snake turns CamelCase into snake_case: RouteTarget is route_target, DNSZone dns_zone.
func snake(s string) string {
	var b strings.Builder
	r := []rune(s)
	for i, c := range r {
		if unicode.IsUpper(c) {
			if i > 0 && (unicode.IsLower(r[i-1]) || i+1 < len(r) && unicode.IsLower(r[i+1]) && unicode.IsUpper(r[i-1])) {
				b.WriteByte('_')
			}
			c = unicode.ToLower(c)
		}
		b.WriteRune(c)
	}
	return b.String()
}

// Purge deletes the events written before before, in tx; the system scope's retention job calls it.
func Purge(ctx context.Context, tx *ent.Tx, before time.Time) (int, error) {
	return tx.Event.Delete().Where(event.TsLT(before)).Exec(ctx)
}
