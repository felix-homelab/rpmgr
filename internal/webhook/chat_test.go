// SPDX-License-Identifier: Apache-2.0

package webhook_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

var update = flag.Bool("update", false, "rewrite the golden files of the chat payloads")

var at = time.Date(2026, 11, 2, 9, 30, 0, 0, time.UTC)

// chatEvents are the events the golden files show: a firing alert, a resolved one, an ordinary
// change, an instance event with a non-ASCII name, and one with markup in its texts.
var chatEvents = map[string]events.Event{
	"alert-fire": {ID: "evt_1", OrgID: "org_1", Type: "alert.fire", Time: at, ActorType: "system", SubjectType: "agent", SubjectID: "gw_1",
		SubjectName: "gw1", Summary: "agent_offline: Agent offline fires, gw1"},
	"alert-resolve": {ID: "evt_2", OrgID: "org_1", Type: "alert.resolve", Time: at, ActorType: "system", SubjectType: "agent", SubjectID: "gw_1",
		SubjectName: "gw1", Summary: "agent_offline: Agent offline resolved, gw1"},
	"change": {ID: "evt_3", OrgID: "org_1", Type: "route.update", Time: at, ActorType: "user", ActorID: "usr_1", SubjectType: "route",
		SubjectID: "rt_1", SubjectName: "web", Summary: "route.update route web", Changed: []string{"enabled"}},
	"instance-unicode": {ID: "evt_4", Type: "release.create", Time: at, ActorType: "user", ActorID: "usr_2", SubjectType: "release",
		SubjectID: "rel_1", SubjectName: "Größe 日本語 🚀", Summary: "release.create Größe 日本語 🚀"},
	"markup": {ID: "evt_5", OrgID: "org_1", Type: "route.create", Time: at, ActorType: "user", ActorID: "usr_1", SubjectType: "route",
		SubjectID: "rt_2", SubjectName: "<!channel> & @everyone", Summary: "route.create <!channel> & @everyone <@U123>"},
}

// TestChatBody_Golden: each service gets its documented message shape for each event; run with
// -update to rewrite the files after a deliberate change.
func TestChatBody_Golden(t *testing.T) {
	for _, f := range []webhook.Format{webhook.FormatDiscord, webhook.FormatSlack, webhook.FormatTeams} {
		for name, e := range chatEvents {
			t.Run(string(f)+"/"+name, func(t *testing.T) {
				b, err := webhook.ChatBody(f, e)
				if err != nil {
					t.Fatal(err)
				}
				var pretty bytes.Buffer
				if err := json.Indent(&pretty, b, "", "  "); err != nil {
					t.Fatal(err)
				}
				pretty.WriteByte('\n')
				path := filepath.Join("testdata", "chat", string(f)+"-"+name+".json")
				if *update {
					if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, pretty.Bytes(), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(path) //nolint:gosec // G304: the test's own golden file
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(want, pretty.Bytes()) {
					t.Fatalf("%s differs from the message:\n%s", path, pretty.Bytes())
				}
			})
		}
	}
}

// TestChatBody_Colours: only an alert firing is red and an alert resolving green; other events
// carry no colour, whichever service.
func TestChatBody_Colours(t *testing.T) {
	for _, c := range []struct {
		f         webhook.Format
		fire, ok  string
		neutralNo string
	}{
		{webhook.FormatDiscord, `"color":15548997`, `"color":5763719`, `"color"`},
		{webhook.FormatSlack, `"color":"#D1242F"`, `"color":"#1A7F37"`, `"color"`},
		{webhook.FormatTeams, `"color":"Attention"`, `"color":"Good"`, `"color"`},
	} {
		for name, want := range map[string]string{"alert-fire": c.fire, "alert-resolve": c.ok, "change": ""} {
			b, _ := webhook.ChatBody(c.f, chatEvents[name])
			if want != "" && !strings.Contains(string(b), want) || want == "" && strings.Contains(string(b), c.neutralNo) {
				t.Errorf("%s %s: %s", c.f, name, b)
			}
		}
	}
}

// TestChatBody_Limits: a summary and a name longer than a service's limit are cut at a character,
// end in an ellipsis, stay valid UTF-8 whatever they hold, and leave the body far below the cap.
func TestChatBody_Limits(t *testing.T) {
	for name, text := range map[string]string{
		"ascii":     strings.Repeat("a", 10000),
		"two bytes": strings.Repeat("é", 10000),
		"emoji":     strings.Repeat("🚀", 10000),
		"markup":    strings.Repeat("<&>", 5000),
		"invalid":   strings.Repeat("\xffa", 5000),
	} {
		e := events.Event{ID: "evt_1", OrgID: "org_1", Type: "route.update", Time: at, ActorType: "user", ActorID: "usr_1",
			SubjectType: "route", SubjectID: "rt_1", SubjectName: text, Summary: text}
		for f, limits := range map[webhook.Format]struct{ title, value int }{
			webhook.FormatDiscord: {webhook.DiscordTitle, webhook.DiscordFieldValue},
			webhook.FormatSlack:   {webhook.SlackText, webhook.SlackFieldValue},
			webhook.FormatTeams:   {webhook.TeamsTitle, webhook.TeamsFactValue},
		} {
			b, err := webhook.ChatBody(f, e)
			if err != nil || !utf8.Valid(b) || len(b) > webhook.MaxBody/2 {
				t.Fatalf("%s %s: %d bytes, valid %v, %v", f, name, len(b), utf8.Valid(b), err)
			}
			var texts []string
			collect(t, "", mustJSON(t, b), &texts)
			cutOne := false
			for _, s := range texts {
				if n := utf8.RuneCountInString(s); n > max(limits.title, limits.value) {
					t.Errorf("%s %s: a text of %d characters, over %d", f, name, n, max(limits.title, limits.value))
				}
				cutOne = cutOne || strings.HasSuffix(s, "…") || strings.HasSuffix(s, "…*")
			}
			if !cutOne {
				t.Errorf("%s %s: nothing was cut", f, name)
			}
		}
	}
	// A text at the limit is not cut.
	e := events.Event{ID: "evt_1", Type: "route.update", Time: at, ActorType: "user", SubjectType: "route", Summary: strings.Repeat("é", webhook.DiscordTitle)}
	if b, _ := webhook.ChatBody(webhook.FormatDiscord, e); strings.Contains(string(b), "…") {
		t.Errorf("a title of exactly %d characters was cut", webhook.DiscordTitle)
	}
	// An escape sequence is never cut in half.
	e.Summary = strings.Repeat("&", 5000)
	b, _ := webhook.ChatBody(webhook.FormatSlack, e)
	var texts []string
	collect(t, "", mustJSON(t, b), &texts)
	for _, s := range texts {
		if strings.Contains(strings.ReplaceAll(strings.ReplaceAll(s, "&amp;", ""), "…", ""), "&") && strings.Contains(s, "&amp") {
			t.Errorf("an escape sequence cut: %q", s[len(s)-20:])
		}
	}
}

func mustJSON(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// collect gathers every string of v that a service shows as text.
func collect(t *testing.T, _ string, v any, out *[]string) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			if s, ok := y.(string); ok && (k == "title" || k == "value" || k == "text" || k == "name") {
				*out = append(*out, s)
				continue
			}
			collect(t, k, y, out)
		}
	case []any:
		for _, y := range x {
			collect(t, "", y, out)
		}
	}
}

// TestChatBody_NoPings: a name or summary that holds a mention pings nobody: Discord is told to
// parse none, and Slack's markup characters are escaped.
func TestChatBody_NoPings(t *testing.T) {
	b, _ := webhook.ChatBody(webhook.FormatDiscord, chatEvents["markup"])
	if !strings.Contains(string(b), `"allowed_mentions":{"parse":[]}`) {
		t.Errorf("discord: %s", b)
	}
	b, _ = webhook.ChatBody(webhook.FormatSlack, chatEvents["markup"])
	var texts []string
	collect(t, "", mustJSON(t, b), &texts)
	all := strings.Join(texts, "\n")
	if strings.Contains(all, "<!channel>") || strings.Contains(all, "<@U123>") || !strings.Contains(all, "&lt;!channel&gt;") {
		t.Errorf("slack: %s", all)
	}
}

func TestChatBody_NotAChatFormat(t *testing.T) {
	for _, f := range []webhook.Format{webhook.FormatRPMgr, "", "mattermost"} {
		if _, err := webhook.ChatBody(f, chatEvents["change"]); err == nil {
			t.Errorf("format %q has a chat body", f)
		}
		if f.Chat() {
			t.Errorf("format %q is a chat format", f)
		}
	}
}

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://discord.com/api/webhooks/1/tok":                    "https://discord.com",
		"https://hooks.slack.com/services/T/B/tok?x=1":              "https://hooks.slack.com",
		"https://prod-1.westus.logic.azure.com:443/workflows/a?sig": "https://prod-1.westus.logic.azure.com:443",
		"://broken":    "https://[redacted]",
		"not a url":    "https://[redacted]",
		"/only/a/path": "https://[redacted]",
	} {
		if got := webhook.RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateChatURL(t *testing.T) {
	for in, ok := range map[string]bool{
		"https://discord.com/api/webhooks/1/tok":           true,
		"https://example.com/?sig=abc":                     true, // the token may be a query alone
		"https://discord.com":                              false,
		"https://discord.com/":                             false,
		"http://discord.com/api/webhooks/1/tok":            false,
		"https://u:p@discord.com/api/webhooks/1/tok":       false,
		"https://discord.com/api/webhooks/1/tok#frag":      false,
		"https://localhost/api/webhooks/1/tok":             false,
		"https://127.0.0.1/api/webhooks/1/tok":             false,
		"":                                                 false,
		"https://discord.com/" + strings.Repeat("a", 2100): false,
	} {
		err := webhook.ValidateChatURL(in, false)
		if (err == nil) != ok {
			t.Errorf("ValidateChatURL(%.50q) = %v, want ok %v", in, err, ok)
		}
		if err != nil && strings.Contains(err.Error(), "discord.com") {
			t.Errorf("the error names the URL: %v", err)
		}
	}
	// An instance endpoint may reach loopback.
	if err := webhook.ValidateChatURL("https://127.0.0.1/hook/tok", true); err != nil {
		t.Errorf("instance endpoint on loopback: %v", err)
	}
}

const chatToken = "SECRETTOKEN-abcdef0123456789" //nolint:gosec // G101: a test token

// TestSend_Chat: a chat delivery posts the message to the URL's path and query, sends no signature
// or Rpmgr header, and a transport error that embeds the URL names none of it.
func TestSend_Chat(t *testing.T) {
	var got atomic.Pointer[http.Request]
	var body atomic.Pointer[[]byte]
	_, s, base := receiver(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store(r)
		body.Store(&b)
		w.WriteHeader(http.StatusNoContent)
	})
	b, _ := webhook.ChatBody(webhook.FormatDiscord, chatEvents["alert-fire"])
	target := secret.New(strings.TrimSuffix(base, "/hook") + "/api/webhooks/1/" + chatToken + "?wait=true")
	code, err := s.Send(context.Background(), webhook.Delivery{URL: "https://example.com", Target: target, EventID: "evt_1", EventType: "alert.fire", Body: b, Policy: internal})
	if err != nil || code != http.StatusNoContent {
		t.Fatalf("send: %d %v", code, err)
	}
	r := got.Load()
	if r.URL.Path != "/api/webhooks/1/"+chatToken || r.URL.RawQuery != "wait=true" || !bytes.Equal(*body.Load(), b) || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("request %s %s: %s", r.URL, r.Header, *body.Load())
	}
	for _, h := range []string{webhook.HeaderSignature, webhook.HeaderEventID, webhook.HeaderEventType} {
		if r.Header.Get(h) != "" {
			t.Errorf("a chat delivery sends %s", h)
		}
	}

	// Errors name none of the URL, whichever step fails.
	for name, mod := range map[string]func(*webhook.Sender){
		"proxy": func(s *webhook.Sender) {
			s.Proxy = func(r *http.Request) (*url.URL, error) { return nil, fmt.Errorf("no proxy for %s", r.URL) }
		},
		"proxy path": func(s *webhook.Sender) {
			s.Proxy = func(r *http.Request) (*url.URL, error) {
				return nil, fmt.Errorf("no proxy for %s", r.URL.EscapedPath())
			}
		},
		"lookup": func(s *webhook.Sender) {
			s.Lookup = func(context.Context, string) ([]netip.Addr, error) {
				return nil, errors.New("lookup of https://example.com/api/webhooks/1/" + chatToken + "?wait=true failed")
			}
		},
	} {
		s2 := *s
		mod(&s2)
		_, err := s2.Send(context.Background(), webhook.Delivery{Target: target, Body: b, Policy: internal})
		if err == nil || !errors.Is(err, webhook.ErrNotDelivered) || strings.Contains(err.Error(), chatToken) || strings.Contains(webhook.Describe(err), chatToken) {
			t.Errorf("%s: %v", name, err)
		}
		if name != "lookup" && !strings.Contains(err.Error(), "[redacted]") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An unparseable URL, an http one and an oversized body say nothing of the URL either.
	for name, d := range map[string]webhook.Delivery{
		"unparseable": {Target: secret.New("https://exa mple.com/" + chatToken), Body: b},
		"http":        {Target: secret.New("http://example.com/" + chatToken), Body: b},
		"credentials": {Target: secret.New("https://u:" + chatToken + "@example.com/x"), Body: b},
		"too large":   {Target: target, Body: make([]byte, webhook.MaxBody+1)},
	} {
		if _, err := s.Send(context.Background(), d); err == nil || strings.Contains(err.Error(), chatToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestSend_RateLimited: a chat service's 429 is a RateLimitedError that carries the wait it asked
// for in Retry-After (seconds or a date) or Discord's retry_after, within the bounds; one without a
// time carries none; an rpmgr endpoint's 429 stays an ordinary failure.
func TestSend_RateLimited(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for name, c := range map[string]struct {
		header, body string
		want         time.Duration
	}{
		"seconds":              {"30", "", 30 * time.Second},
		"fraction":             {"1.5", "", 1500 * time.Millisecond},
		"a date":               {now.Add(90 * time.Second).UTC().Format(http.TimeFormat), "", 90 * time.Second},
		"a date in the past":   {now.Add(-time.Hour).UTC().Format(http.TimeFormat), "", webhook.RetryAfterMin},
		"zero":                 {"0", "", webhook.RetryAfterMin},
		"negative":             {"-5", "", webhook.RetryAfterMin},
		"too long":             {"86400", "", webhook.RetryAfterMax},
		"huge":                 {"1e300", "", webhook.RetryAfterMax},
		"discord body":         {"", `{"message":"You are being rate limited.","retry_after":2.5,"global":false}`, 2500 * time.Millisecond},
		"discord body, long":   {"", `{"retry_after":99999}`, webhook.RetryAfterMax},
		"header before body":   {"7", `{"retry_after":2.5}`, 7 * time.Second},
		"no time":              {"", "", 0},
		"garbage":              {"soon", "not json", 0},
		"not a number in body": {"", `{"retry_after":"soon"}`, 0},
		"infinity":             {"Inf", "", 0},
		"nan":                  {"NaN", "", 0},
	} {
		_, s, u := receiver(t, func(w http.ResponseWriter, _ *http.Request) {
			if c.header != "" {
				w.Header().Set("Retry-After", c.header)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, c.body)
		})
		s.Now = func() time.Time { return now }
		code, err := s.Send(context.Background(), webhook.Delivery{Target: secret.New(u), Body: []byte("{}"), Policy: internal})
		var rl *webhook.RateLimitedError
		if code != 429 || !errors.As(err, &rl) || rl.After != c.want || !errors.Is(err, webhook.ErrNotDelivered) {
			t.Errorf("%s: %d %v, want a wait of %s", name, code, err, c.want)
		}
		if c.want > 0 && !strings.Contains(webhook.Describe(err), c.want.String()) {
			t.Errorf("%s: %q", name, webhook.Describe(err))
		}
		// The same answer to an rpmgr endpoint is an ordinary failure.
		code, err = s.Send(context.Background(), webhook.Delivery{URL: u, Body: []byte("{}"), Secrets: []secret.Value{secret.New(key)}, Policy: internal})
		if code != 429 || errors.As(err, &rl) || err == nil {
			t.Errorf("%s, rpmgr: %d %v", name, code, err)
		}
	}
}
