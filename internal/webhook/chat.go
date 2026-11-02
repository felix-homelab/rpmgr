// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/felix-homelab/rpmgr/internal/events"
)

// Format is how an endpoint's events are posted (docs/07-api.md, "Webhooks (Phase 2)"; D162).
type Format string

// The formats: rpmgr is the signed envelope, the others are chat messages.
const (
	FormatRPMgr   Format = "rpmgr"
	FormatDiscord Format = "discord"
	FormatSlack   Format = "slack"
	FormatTeams   Format = "teams"
)

// Chat reports whether f is a chat format: its URL holds the service's token, it has no signing
// secret and its message is cut to the service's limits.
func (f Format) Chat() bool {
	return f == FormatDiscord || f == FormatSlack || f == FormatTeams
}

// The limits of a chat message, in characters (docs/03-connections.md, "Timeouts, keepalive and
// backoff").
const (
	DiscordTitle      = 256
	DiscordFieldValue = 1024
	SlackText         = 3000
	SlackFieldValue   = 2000
	TeamsTitle        = 500
	TeamsFactValue    = 500
	// RetryAfterMin and RetryAfterMax bound how long a 429 delays the next attempt.
	RetryAfterMin = time.Second
	RetryAfterMax = 15 * time.Minute
)

// ChatBody is the message of e in the chat format f.
func ChatBody(f Format, e events.Event) ([]byte, error) {
	fields := factsOf(e)
	switch f {
	case FormatDiscord:
		return discord(e, fields)
	case FormatSlack:
		return slack(e, fields)
	case FormatTeams:
		return teams(e, fields)
	}
	return nil, fmt.Errorf("webhook: %q is not a chat format", f)
}

type fact struct{ Name, Value string }

// factsOf are the fields every chat message shows: the event's type, organisation, actor, subject
// and time. The envelope's fields and nothing more (D144).
func factsOf(e events.Event) []fact {
	org := e.OrgID
	if org == "" {
		org = "instance"
	}
	actor := e.ActorType
	if e.ActorID != "" {
		actor += " " + e.ActorID
	}
	subject := e.SubjectType
	switch {
	case e.SubjectName != "" && e.SubjectID != "":
		subject += " " + e.SubjectName + " (" + e.SubjectID + ")"
	case e.SubjectName != "" || e.SubjectID != "":
		subject += " " + e.SubjectName + e.SubjectID
	}
	return []fact{{"Type", e.Type}, {"Organisation", org}, {"Actor", actor}, {"Subject", subject},
		{"Time", e.Time.UTC().Format(time.RFC3339)}}
}

// Alert colours: an alert firing is red and resolving green; no other event is coloured.
const (
	colourNone = iota
	colourRed
	colourGreen
)

func colourOf(e events.Event) int {
	switch e.Type {
	case "alert.fire":
		return colourRed
	case "alert.resolve":
		return colourGreen
	}
	return colourNone
}

// cut returns s, escaped by esc if not nil, in at most n characters: a longer text is cut at a
// character and ends in "…". It never cuts an escape sequence, and returns valid UTF-8.
func cut(s string, n int, esc func(string) string) string {
	s = strings.ToValidUTF8(s, "�")
	if esc == nil {
		esc = func(r string) string { return r }
	}
	if full := esc(s); utf8.RuneCountInString(full) <= n {
		return full
	}
	var b strings.Builder
	count := 0
	for _, r := range s {
		part := esc(string(r))
		k := utf8.RuneCountInString(part)
		if count+k > n-1 {
			break
		}
		b.WriteString(part)
		count += k
	}
	b.WriteString("…")
	return b.String()
}

func discord(e events.Event, facts []fact) ([]byte, error) {
	var fs []map[string]any
	for _, f := range facts {
		fs = append(fs, map[string]any{"name": f.Name, "value": cut(f.Value, DiscordFieldValue, nil), "inline": true})
	}
	embed := map[string]any{"title": cut(e.Summary, DiscordTitle, nil), "timestamp": e.Time.UTC().Format(time.RFC3339), "fields": fs}
	switch colourOf(e) {
	case colourRed:
		embed["color"] = 0xED4245
	case colourGreen:
		embed["color"] = 0x57F287
	}
	// No mention in a summary or a name pings anyone.
	return json.Marshal(map[string]any{"embeds": []any{embed}, "allowed_mentions": map[string]any{"parse": []string{}}})
}

// slackEscape escapes the characters Slack reads as markup, so that <!channel> or <@U1> in a
// name is text.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func slack(e events.Event, facts []fact) ([]byte, error) {
	var fs []map[string]any
	for _, f := range facts {
		fs = append(fs, map[string]any{"type": "mrkdwn", "text": "*" + f.Name + "*\n" + cut(f.Value, SlackFieldValue-len(f.Name)-3, slackEscape)})
	}
	blocks := []any{
		map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "*" + cut(e.Summary, SlackText-2, slackEscape) + "*"}},
		map[string]any{"type": "section", "fields": fs},
	}
	att := map[string]any{"blocks": blocks}
	switch colourOf(e) {
	case colourRed:
		att["color"] = "#D1242F"
	case colourGreen:
		att["color"] = "#1A7F37"
	}
	// text is what a notification shows; it is plain, so it is escaped too.
	return json.Marshal(map[string]any{"text": cut(e.Summary, SlackText, slackEscape), "attachments": []any{att}})
}

func teams(e events.Event, facts []fact) ([]byte, error) {
	var fs []map[string]any
	for _, f := range facts {
		fs = append(fs, map[string]any{"title": f.Name, "value": cut(f.Value, TeamsFactValue, nil)})
	}
	title := map[string]any{"type": "TextBlock", "text": cut(e.Summary, TeamsTitle, nil), "weight": "Bolder", "size": "Medium", "wrap": true}
	switch colourOf(e) {
	case colourRed:
		title["color"] = "Attention"
	case colourGreen:
		title["color"] = "Good"
	}
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
		"body": []any{title, map[string]any{"type": "FactSet", "facts": fs}}}
	return json.Marshal(map[string]any{"type": "message", "attachments": []any{
		map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}})
}

// RedactURL is raw as it is shown everywhere but in the sealed column: its scheme and host. A
// chat service's token is in the path or the query.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "https://[redacted]"
	}
	return u.Scheme + "://" + u.Host
}

// ValidateChatURL checks the URL of a chat endpoint: ValidateURL (ValidateOrgURL for an org's)
// and a path, as the token is in it.
func ValidateChatURL(raw string, instance bool) error {
	check := ValidateOrgURL
	if instance {
		check = ValidateURL
	}
	if err := check(raw); err != nil {
		return err
	}
	if u, _ := url.Parse(raw); len(u.Path) <= 1 && u.RawQuery == "" {
		return errors.New("webhook: the url of a chat service has a path that holds its token, and this has none")
	}
	return nil
}

// RateLimitedError is a chat service's 429. After is how long it asked to wait, within
// RetryAfterMin and RetryAfterMax, or 0 if it named no time.
type RateLimitedError struct{ After time.Duration }

func (e *RateLimitedError) Error() string {
	if e.After == 0 {
		return "webhook: not delivered: the receiver is rate limiting (429)"
	}
	return fmt.Sprintf("webhook: not delivered: the receiver is rate limiting (429); the next attempt is in %s", e.After)
}

// Unwrap makes a rate limit a failed delivery too.
func (e *RateLimitedError) Unwrap() error { return ErrNotDelivered }

// retryAfter reads how long a 429 asks to wait: the Retry-After header, seconds or an HTTP date,
// else the retry_after of Discord's JSON answer, in seconds. 0 means it named no usable time.
func retryAfter(h http.Header, body []byte, now time.Time) time.Duration {
	var secs float64
	ok := false
	if v := strings.TrimSpace(h.Get("Retry-After")); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			secs, ok = n, true
		} else if t, err := http.ParseTime(v); err == nil {
			secs, ok = t.Sub(now).Seconds(), true
		}
	}
	if !ok {
		var d struct {
			RetryAfter float64 `json:"retry_after"`
		}
		if json.Unmarshal(body, &d) == nil && d.RetryAfter > 0 {
			secs, ok = d.RetryAfter, true
		}
	}
	if !ok || math.IsNaN(secs) || math.IsInf(secs, 0) {
		return 0
	}
	// Clamp as a number first: a huge value overflows a Duration.
	return time.Duration(min(max(secs, RetryAfterMin.Seconds()), RetryAfterMax.Seconds()) * float64(time.Second))
}
