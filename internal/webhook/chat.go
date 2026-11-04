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

// The cuts of a chat message, in characters (docs/03-connections.md, "Timeouts, keepalive and
// backoff"): each is at most the service's limit, and together they keep a maximal message within
// the service's total.
const (
	DiscordTitle       = 256
	DiscordDescription = 1000
	DiscordFieldValue  = 256
	DiscordFooter      = 256
	SlackHeader        = 150
	SlackText          = 1000
	SlackFieldValue    = 300
	SlackFallback      = 300
	TeamsTitle         = 300
	TeamsText          = 1000
	TeamsFactValue     = 300
	// RetryAfterMin and RetryAfterMax bound how long a 429 delays the next attempt.
	RetryAfterMin = time.Second
	RetryAfterMax = 15 * time.Minute
)

// ChatBody is the message of e in the chat format f; c is what it shows besides the event.
func ChatBody(f Format, e events.Event, c Context) ([]byte, error) {
	m := compose(e, c)
	switch f {
	case FormatDiscord:
		return discord(m)
	case FormatSlack:
		return slack(m)
	case FormatTeams:
		return teams(m)
	}
	return nil, fmt.Errorf("webhook: %q is not a chat format", f)
}

// The colours of a severity, by service.
var (
	discordColours = map[severity]int{sevNeutral: 0x99AAB5, sevInfo: 0x3498DB, sevWarning: 0xFAA61A, sevCritical: 0xED4245, sevResolved: 0x57F287}
	slackColours   = map[severity]string{sevNeutral: "#6E7781", sevInfo: "#0969DA", sevWarning: "#BF8700", sevCritical: "#D1242F", sevResolved: "#1A7F37"}
	teamsStyles    = map[severity]string{sevNeutral: "emphasis", sevInfo: "accent", sevWarning: "warning", sevCritical: "attention", sevResolved: "good"}
	teamsColours   = map[severity]string{sevNeutral: "Default", sevInfo: "Accent", sevWarning: "Warning", sevCritical: "Attention", sevResolved: "Good"}
)

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

// mdEscape escapes the characters Discord and Teams read as Markdown, so that a name such as
// [x](https://evil) or **bold** is shown as text. A backslash before each one is the escape of both.
func mdEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\*_~`|>#[]()<", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func discord(m message) ([]byte, error) {
	var fs []map[string]any
	for _, f := range m.facts {
		fs = append(fs, map[string]any{"name": f.Name, "value": cut(f.Value, DiscordFieldValue, mdEscape), "inline": true})
	}
	embed := map[string]any{"title": cut(m.title, DiscordTitle, mdEscape), "description": cut(m.text, DiscordDescription, mdEscape),
		"color": discordColours[m.sev], "timestamp": m.at.Format(time.RFC3339), "fields": fs}
	if m.link != "" {
		embed["url"] = m.link
	}
	if foot := strings.Join(nonEmpty(m.footer, m.ids), " · "); foot != "" {
		embed["footer"] = map[string]any{"text": cut(foot, DiscordFooter, mdEscape)}
	}
	// No mention in a summary or a name pings anyone.
	return json.Marshal(map[string]any{"embeds": []any{embed}, "allowed_mentions": map[string]any{"parse": []string{}}})
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// slackEscape escapes the characters Slack reads as markup, so that <!channel> or <@U1> in a
// name is text.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func angle(s string) string { return strings.NewReplacer("<", "‹", ">", "›").Replace(s) }

func slack(m message) ([]byte, error) {
	var fs []map[string]any
	for _, f := range m.facts {
		fs = append(fs, map[string]any{"type": "mrkdwn", "text": "*" + f.Name + "*\n" + cut(f.Value, SlackFieldValue, slackEscape)})
	}
	// The unix time makes Slack show the time in the reader's zone; the fallback is for old clients.
	when := fmt.Sprintf("<!date^%d^{date_short_pretty} {time_secs}|%s>", m.at.Unix(), m.at.Format(time.RFC3339))
	ctx := []any{map[string]any{"type": "mrkdwn", "text": when}}
	if foot := strings.Join(nonEmpty(m.footer, m.ids), " · "); foot != "" {
		ctx = append(ctx, map[string]any{"type": "mrkdwn", "text": cut(foot, SlackText, slackEscape)})
	}
	// A header is plain text, which Slack is not documented to parse, so it takes no entities; its
	// angle brackets, which start a mention, are shown as guillemets instead.
	blocks := []any{
		map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": cut(m.title, SlackHeader, angle)}},
		map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": cut(m.text, SlackText, slackEscape)}},
		map[string]any{"type": "section", "fields": fs},
		map[string]any{"type": "context", "elements": ctx},
	}
	if m.link != "" {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{map[string]any{"type": "button",
			"text": map[string]any{"type": "plain_text", "text": "Open in rpmgr"}, "url": m.link}}})
	}
	att := map[string]any{"color": slackColours[m.sev], "blocks": blocks}
	// text is what a notification shows; it is escaped like any mrkdwn.
	return json.Marshal(map[string]any{"text": cut(m.title, SlackFallback, slackEscape), "attachments": []any{att}})
}

func teams(m message) ([]byte, error) {
	var fs []map[string]any
	for _, f := range m.facts {
		fs = append(fs, map[string]any{"title": f.Name, "value": cut(f.Value, TeamsFactValue, mdEscape)})
	}
	// The card's own time function shows the time in the reader's zone; its argument is plain text
	// when a client does not know it.
	ts := m.at.Format(time.RFC3339)
	fs = append(fs, map[string]any{"title": "Time", "value": "{{DATE(" + ts + ", SHORT)}} {{TIME(" + ts + ")}}"})
	items := []any{
		map[string]any{"type": "TextBlock", "text": cut(m.title, TeamsTitle, mdEscape), "weight": "Bolder", "size": "Medium", "wrap": true,
			"color": teamsColours[m.sev]},
		map[string]any{"type": "TextBlock", "text": cut(m.text, TeamsText, mdEscape), "wrap": true, "spacing": "Small"},
		map[string]any{"type": "FactSet", "facts": fs},
	}
	if foot := strings.Join(nonEmpty(m.footer, m.ids), " · "); foot != "" {
		items = append(items, map[string]any{"type": "TextBlock", "text": cut(foot, TeamsText, mdEscape), "wrap": true, "size": "Small",
			"isSubtle": true})
	}
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.5",
		"msteams": map[string]any{"width": "Full"},
		"body":    []any{map[string]any{"type": "Container", "style": teamsStyles[m.sev], "items": items}}}
	if m.link != "" {
		card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": "Open in rpmgr", "url": m.link}}
	}
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
