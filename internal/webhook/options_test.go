// SPDX-License-Identifier: Apache-2.0

package webhook_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// TestValidateOptions: each option is checked against the format it is for, and one a format has
// no use for is refused, never ignored.
func TestValidateOptions(t *testing.T) {
	long := strings.Repeat("a", 81)
	for name, c := range map[string]struct {
		f  webhook.Format
		o  webhook.Options
		ok bool
	}{
		"none":                  {webhook.FormatDiscord, webhook.Options{}, true},
		"rpmgr none":            {webhook.FormatRPMgr, webhook.Options{MentionWhen: "never"}, true},
		"rpmgr mention":         {webhook.FormatRPMgr, webhook.Options{Mention: "here"}, false},
		"rpmgr username":        {webhook.FormatRPMgr, webhook.Options{Username: "x"}, false},
		"discord role":          {webhook.FormatDiscord, webhook.Options{Mention: "role:123456789012345678", MentionWhen: "critical"}, true},
		"discord user":          {webhook.FormatDiscord, webhook.Options{Mention: "user:42", MentionWhen: "all"}, true},
		"discord everyone":      {webhook.FormatDiscord, webhook.Options{Mention: "everyone", MentionWhen: "all"}, false},
		"discord @everyone":     {webhook.FormatDiscord, webhook.Options{Mention: "role:everyone", MentionWhen: "all"}, false},
		"discord long id":       {webhook.FormatDiscord, webhook.Options{Mention: "role:123456789012345678901"}, false},
		"discord markup":        {webhook.FormatDiscord, webhook.Options{Mention: "role:1> @everyone <@&2"}, false},
		"discord here":          {webhook.FormatDiscord, webhook.Options{Mention: "here"}, false},
		"when needs mention":    {webhook.FormatDiscord, webhook.Options{MentionWhen: "all"}, false},
		"when unknown":          {webhook.FormatDiscord, webhook.Options{Mention: "role:1", MentionWhen: "sometimes"}, false},
		"mention, never":        {webhook.FormatDiscord, webhook.Options{Mention: "role:1", MentionWhen: "never"}, true},
		"slack here":            {webhook.FormatSlack, webhook.Options{Mention: "here", MentionWhen: "critical"}, true},
		"slack subteam":         {webhook.FormatSlack, webhook.Options{Mention: "subteam:S0614TZR7", MentionWhen: "all"}, true},
		"slack user":            {webhook.FormatSlack, webhook.Options{Mention: "user:U024BE7LH", MentionWhen: "all"}, true},
		"slack bot user":        {webhook.FormatSlack, webhook.Options{Mention: "user:B024BE7LH"}, false},
		"slack channel":         {webhook.FormatSlack, webhook.Options{Mention: "channel"}, false},
		"slack injection":       {webhook.FormatSlack, webhook.Options{Mention: "user:U1>|<!channel"}, false},
		"slack subteam as user": {webhook.FormatSlack, webhook.Options{Mention: "subteam:U024BE7LH"}, false},
		"slack discord opts":    {webhook.FormatSlack, webhook.Options{Username: "x"}, false},
		"slack thread":          {webhook.FormatSlack, webhook.Options{ThreadName: "x"}, false},
		"teams upn":             {webhook.FormatTeams, webhook.Options{Mention: "user:ada@example.com", MentionWhen: "all"}, true},
		"teams guid":            {webhook.FormatTeams, webhook.Options{Mention: "user:3f2504e0-4f89-11d3-9a0c-0305e82c3301", MentionWhen: "all"}, true},
		"teams name":            {webhook.FormatTeams, webhook.Options{Mention: "user:Ada Admin"}, false},
		"teams tag":             {webhook.FormatTeams, webhook.Options{Mention: "user:a@b.example</at><at>x"}, false},
		"teams avatar":          {webhook.FormatTeams, webhook.Options{AvatarURL: "https://x.example/a.png"}, false},
		"username":              {webhook.FormatDiscord, webhook.Options{Username: "rpmgr alerts"}, true},
		"username 80":           {webhook.FormatDiscord, webhook.Options{Username: strings.Repeat("é", 80)}, true},
		"username 81":           {webhook.FormatDiscord, webhook.Options{Username: long}, false},
		"username clyde":        {webhook.FormatDiscord, webhook.Options{Username: "My Clyde"}, false},
		"username discord":      {webhook.FormatDiscord, webhook.Options{Username: "DISCORD bot"}, false},
		"username control":      {webhook.FormatDiscord, webhook.Options{Username: "a\nb"}, false},
		"avatar https":          {webhook.FormatDiscord, webhook.Options{AvatarURL: "https://cdn.example/a.png"}, true},
		"avatar http":           {webhook.FormatDiscord, webhook.Options{AvatarURL: "http://cdn.example/a.png"}, false},
		"avatar credentials":    {webhook.FormatDiscord, webhook.Options{AvatarURL: "https://u:p@cdn.example/a.png"}, false}, //nolint:gosec // G101: a URL with credentials is the rejected input
		"avatar fragment":       {webhook.FormatDiscord, webhook.Options{AvatarURL: "https://cdn.example/a.png#x"}, false},
		"avatar no host":        {webhook.FormatDiscord, webhook.Options{AvatarURL: "https:///a.png"}, false},
		"avatar javascript":     {webhook.FormatDiscord, webhook.Options{AvatarURL: "javascript:alert(1)"}, false},
		"avatar space":          {webhook.FormatDiscord, webhook.Options{AvatarURL: "https://cdn.example/a b.png"}, false},
		"avatar too long":       {webhook.FormatDiscord, webhook.Options{AvatarURL: "https://cdn.example/" + strings.Repeat("a", 2048)}, false},
		"thread 100":            {webhook.FormatDiscord, webhook.Options{ThreadName: strings.Repeat("t", 100)}, true},
		"thread 101":            {webhook.FormatDiscord, webhook.Options{ThreadName: strings.Repeat("t", 101)}, false},
		"thread invalid utf8":   {webhook.FormatDiscord, webhook.Options{ThreadName: "a\xffb"}, false},
	} {
		err := webhook.ValidateOptions(c.f, c.o)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && (strings.Contains(err.Error(), "everyone") || strings.Contains(err.Error(), "<")) {
			t.Errorf("%s: the error echoes the value: %v", name, err)
		}
	}
}

// flat is every key and every string value of the JSON b, so that a test looks for text as a
// service reads it and not as it is escaped in the JSON.
func flat(t *testing.T, b string) string {
	t.Helper()
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case []any:
			for _, y := range x {
				walk(y)
			}
		case map[string]any:
			for k, y := range x {
				out = append(out, "key:"+k)
				walk(y)
			}
		}
	}
	walk(mustJSON(t, []byte(b)))
	return strings.Join(out, "\n")
}

// rawControl finds a mention control that no backslash escapes.
var rawControl = regexp.MustCompile(`(^|[^\\])(<!here|<!channel|<!everyone|<!subteam|<@|<at>)`)

func opt(mention, when string) webhook.Context {
	c := chatCtx
	c.Options = webhook.Options{Mention: mention, MentionWhen: when}
	return c
}

// TestChatBody_Mentions: the mention is made for an alert that fires, for the alerts the endpoint
// is set to, and never for a resolve, an audit event or a status event.
func TestChatBody_Mentions(t *testing.T) {
	warn := chatEvents["alert-fire"]
	warn.Summary = "clock_skew: Clock skew fires, gw1"
	targets := map[webhook.Format]struct{ mention, ping string }{
		webhook.FormatDiscord: {"role:123", "<@&123>"},
		webhook.FormatSlack:   {"subteam:S123", "<!subteam^S123>"},
		webhook.FormatTeams:   {"user:ada@example.com", "<at>ada@example.com</at>"},
	}
	evs := map[string]events.Event{"critical fire": chatEvents["alert-fire"], "warning fire": warn, "resolve": chatEvents["alert-resolve"],
		"audit": chatEvents["change"], "status": chatEvents["status"]}
	// when -> the events that mention
	want := map[string]map[string]bool{
		"":         {},
		"never":    {},
		"critical": {"critical fire": true},
		"all":      {"critical fire": true, "warning fire": true},
	}
	for f, tg := range targets {
		for when, hit := range want {
			for name, e := range evs {
				b := flat(t, body(t, f, e, opt(tg.mention, when)))
				if got := strings.Contains(b, tg.ping); got != hit[name] {
					t.Errorf("%s when %q, %s: mentioned %v, want %v", f, when, name, got, hit[name])
				}
			}
		}
		// Without a configured mention no text of any event carries one.
		for _, h := range hostile {
			e := chatEvents["alert-fire"]
			e.SubjectName, e.Summary = h, "agent_offline: "+h
			c := chatCtx
			c.OrgName, c.ActorName = h, h
			b := flat(t, body(t, f, e, c))
			bads := []string{"key:roles", "key:users", "key:entities"}
			if f == webhook.FormatDiscord {
				bads = append(bads, "key:content\n")
			}
			for _, bad := range bads {
				if strings.Contains(b+"\n", bad) {
					t.Errorf("%s %q: %q with no mention configured", f, h, bad)
				}
			}
			// A control the service parses is one not escaped with a backslash.
			if raw := rawControl.FindString(b); raw != "" {
				t.Errorf("%s %q: an unescaped %q with no mention configured", f, h, raw)
			}
		}
	}
	// Discord allows exactly the one mention and nothing else; a user mention is a users entry.
	var d struct {
		Content string
		Allowed struct {
			Parse []string
			Roles []string
			Users []string
		} `json:"allowed_mentions"`
	}
	if err := json.Unmarshal([]byte(body(t, webhook.FormatDiscord, chatEvents["alert-fire"], opt("user:42", "all"))), &d); err != nil {
		t.Fatal(err)
	}
	if d.Content != "<@42>" || len(d.Allowed.Parse) != 0 || len(d.Allowed.Users) != 1 || d.Allowed.Users[0] != "42" || len(d.Allowed.Roles) != 0 {
		t.Errorf("discord user mention: %+v", d)
	}
	// Hostile text next to a configured mention adds none: the ping appears the expected times.
	for _, h := range hostile {
		e := chatEvents["alert-fire"]
		e.SubjectName, e.Summary = h, "agent_offline: "+h
		for f, tg := range targets {
			b := flat(t, body(t, f, e, opt(tg.mention, "all")))
			// The configured ping is there; no other mention is, and the hostile text is no ping.
			for _, other := range []string{"<@&456>", "<!here>", "<!channel>", "<@123>", "<!subteam^S1>", "<!everyone>", "<at>Admin</at>"} {
				if strings.Contains(b, other) {
					t.Errorf("%s: hostile %q made %q: %s", f, h, other, b)
				}
			}
			if !strings.Contains(b, tg.ping) {
				t.Errorf("%s: the configured mention is missing", f)
			}
		}
	}
}

// TestChatBody_DiscordOptions: the username, avatar and thread name go into a post, and an edit
// carries none of them.
func TestChatBody_DiscordOptions(t *testing.T) {
	c := chatCtx
	c.Options = webhook.Options{Username: "rpmgr alerts", AvatarURL: "https://cdn.example/a.png", ThreadName: "alerts"}
	var d map[string]any
	if err := json.Unmarshal([]byte(body(t, webhook.FormatDiscord, chatEvents["alert-fire"], c)), &d); err != nil {
		t.Fatal(err)
	}
	if d["username"] != "rpmgr alerts" || d["avatar_url"] != "https://cdn.example/a.png" || d["thread_name"] != "alerts" {
		t.Errorf("%v", d)
	}
	for _, f := range []webhook.Format{webhook.FormatSlack, webhook.FormatTeams} {
		if b := body(t, f, chatEvents["alert-fire"], c); strings.Contains(b, "rpmgr alerts") || strings.Contains(b, "thread_name") {
			t.Errorf("%s shows a Discord option: %s", f, b)
		}
	}
	b, err := webhook.DiscordEditBody(chatEvents["alert-resolve"], c)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "username") || strings.Contains(s, "thread_name") || strings.Contains(s, "avatar_url") || !strings.Contains(s, `"content":""`) ||
		!strings.Contains(s, `"color":5763719`) || !strings.Contains(s, `"allowed_mentions":{"parse":[]}`) {
		t.Errorf("edit body: %s", s)
	}
}

// fakeDiscord is a Discord webhook endpoint that records what it is asked.
type fakeDiscord struct {
	mu     sync.Mutex
	reqs   []string // METHOD path?query
	bodies [][]byte
	answer func(n int, r *http.Request) (int, string)
}

func (f *fakeDiscord) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	n := len(f.reqs)
	f.reqs = append(f.reqs, r.Method+" "+r.URL.RequestURI())
	f.bodies = append(f.bodies, b)
	f.mu.Unlock()
	code, reply := f.answer(n, r)
	w.WriteHeader(code)
	_, _ = io.WriteString(w, reply)
}

// TestSend_DiscordWaitAndEdit: a post with Wait asks for the message and reports its ID, an edit
// patches that message, an edit of a message Discord no longer has posts the body as a new one, and
// the ID of an answer is taken only when it is a number.
func TestSend_DiscordWaitAndEdit(t *testing.T) {
	f := &fakeDiscord{}
	_, s, u := receiver(t, f.handler)
	target := secret.New(strings.TrimSuffix(u, "/hook") + "/api/webhooks/9/" + chatToken)
	post, edit := []byte(`{"post":1}`), []byte(`{"edit":1}`)
	ctx := context.Background()

	f.answer = func(int, *http.Request) (int, string) {
		return 200, `{"id":"1234567890","channel_id":"555","content":""}`
	}
	var res webhook.Result
	code, err := s.Send(ctx, webhook.Delivery{Target: target, Body: post, Policy: internal, Wait: true, Result: &res})
	if err != nil || code != 200 || res.MessageID != "1234567890" || res.ThreadID != "" || res.Edited {
		t.Fatalf("post: %d %v %+v", code, err, res)
	}
	if want := "POST /api/webhooks/9/" + chatToken + "?wait=true"; f.reqs[0] != want {
		t.Errorf("request %q, want %q", f.reqs[0], want)
	}
	// A thread's ID is the answer's channel, taken only when the post started a thread.
	res = webhook.Result{}
	if _, err := s.Send(ctx, webhook.Delivery{Target: target, Body: post, Policy: internal, Wait: true, Threaded: true, Result: &res}); err != nil || res.ThreadID != "555" {
		t.Errorf("threaded: %v %+v", err, res)
	}
	// Without Wait nothing is asked for.
	res = webhook.Result{}
	if _, err := s.Send(ctx, webhook.Delivery{Target: target, Body: post, Policy: internal, Result: &res}); err != nil || res != (webhook.Result{}) ||
		strings.Contains(f.reqs[len(f.reqs)-1], "wait") {
		t.Errorf("no wait: %v %+v %v", err, res, f.reqs)
	}
	// An ID that is no number is not kept.
	f.answer = func(int, *http.Request) (int, string) { return 200, `{"id":"../x","channel_id":"5"}` }
	res = webhook.Result{}
	if _, err := s.Send(ctx, webhook.Delivery{Target: target, Body: post, Policy: internal, Wait: true, Result: &res}); err != nil || res.MessageID != "" {
		t.Errorf("bad id: %v %+v", err, res)
	}
	f.answer = func(int, *http.Request) (int, string) { return 200, `not json` }
	if _, err := s.Send(ctx, webhook.Delivery{Target: target, Body: post, Policy: internal, Wait: true, Result: &res}); err != nil || res.MessageID != "" {
		t.Errorf("no json: %v %+v", err, res)
	}

	// An edit patches the message, in its thread when it has one, and sends the edit's body.
	f.reqs, f.bodies = nil, nil
	f.answer = func(int, *http.Request) (int, string) { return 200, `{}` }
	res = webhook.Result{}
	code, err = s.Send(ctx, webhook.Delivery{Target: target, Body: post, Policy: internal, Result: &res,
		Edit: &webhook.Edit{MessageID: "1234567890", ThreadID: "555", Body: edit}})
	if err != nil || code != 200 || !res.Edited || len(f.reqs) != 1 || string(f.bodies[0]) != string(edit) {
		t.Fatalf("edit: %d %v %+v %v", code, err, res, f.reqs)
	}
	if want := "PATCH /api/webhooks/9/" + chatToken + "/messages/1234567890?thread_id=555"; f.reqs[0] != want {
		t.Errorf("request %q, want %q", f.reqs[0], want)
	}

	// 404: the message is gone, so the delivery's body is posted, into the thread if it is known.
	f.reqs, f.bodies = nil, nil
	f.answer = func(_ int, r *http.Request) (int, string) {
		if r.Method == http.MethodPatch {
			return 404, `{"message":"Unknown Message","code":10008}`
		}
		return 204, ""
	}
	res = webhook.Result{}
	code, err = s.Send(ctx, webhook.Delivery{Target: target, Body: post, Policy: internal, Result: &res,
		Edit: &webhook.Edit{MessageID: "1234567890", ThreadID: "555", Body: edit}})
	if err != nil || code != 204 || res.Edited || len(f.reqs) != 2 || string(f.bodies[1]) != string(post) {
		t.Fatalf("fallback: %d %v %+v %v", code, err, res, f.reqs)
	}
	if want := "POST /api/webhooks/9/" + chatToken + "?thread_id=555"; f.reqs[1] != want {
		t.Errorf("fallback request %q, want %q", f.reqs[1], want)
	}
	// Both fail with 404 (the webhook itself is gone): an error, not a loop.
	f.reqs = nil
	f.answer = func(int, *http.Request) (int, string) { return 404, `{}` }
	if code, err := s.Send(ctx, webhook.Delivery{Target: target, Body: post, Policy: internal, Edit: &webhook.Edit{MessageID: "1", Body: edit}}); err == nil || code != 404 || len(f.reqs) != 2 {
		t.Errorf("both 404: %d %v %v", code, err, f.reqs)
	}
	// An edit that is not a number is not sent at all: the delivery is a post.
	f.reqs = nil
	f.answer = func(int, *http.Request) (int, string) { return 204, "" }
	if _, err := s.Send(ctx, webhook.Delivery{Target: target, Body: post, Policy: internal, Edit: &webhook.Edit{MessageID: "../../x", Body: edit}}); err != nil ||
		len(f.reqs) != 1 || !strings.HasPrefix(f.reqs[0], "POST ") {
		t.Errorf("bad message id: %v %v", err, f.reqs)
	}
	// A 5xx on the edit is a failure that retries the edit, not a post.
	f.reqs = nil
	f.answer = func(int, *http.Request) (int, string) { return 500, "" }
	if code, err := s.Send(ctx, webhook.Delivery{Target: target, Body: post, Policy: internal, Edit: &webhook.Edit{MessageID: "1", Body: edit}}); err == nil || code != 500 || len(f.reqs) != 1 {
		t.Errorf("5xx edit: %d %v %v", code, err, f.reqs)
	}
	// A 429 on the edit names its wait, from the JSON body.
	f.answer = func(int, *http.Request) (int, string) { return 429, `{"retry_after":4.5,"global":false}` }
	var rl *webhook.RateLimitedError
	if code, err := s.Send(ctx, webhook.Delivery{Target: target, Body: post, Policy: internal, Edit: &webhook.Edit{MessageID: "1", Body: edit}}); code != 429 ||
		!asRateLimited(err, &rl) || rl.After != 4500*time.Millisecond {
		t.Errorf("429 edit: %d %v", code, err)
	}
}

// TestSend_DiscordResetAfterHeader: Discord's X-RateLimit-Reset-After names the wait when neither
// Retry-After nor the JSON retry_after does, and they come first when they do.
func TestSend_DiscordResetAfterHeader(t *testing.T) {
	for name, c := range map[string]struct {
		h    map[string]string
		body string
		want time.Duration
	}{
		"reset after":       {map[string]string{"X-RateLimit-Reset-After": "3.25"}, "", 3250 * time.Millisecond},
		"retry-after first": {map[string]string{"Retry-After": "9", "X-RateLimit-Reset-After": "3"}, "", 9 * time.Second},
		"json first":        {map[string]string{"X-RateLimit-Reset-After": "3"}, `{"retry_after":6}`, 6 * time.Second},
		"too long":          {map[string]string{"X-RateLimit-Reset-After": "99999"}, "", webhook.RetryAfterMax},
		"zero":              {map[string]string{"X-RateLimit-Reset-After": "0"}, "", 0},
		"garbage":           {map[string]string{"X-RateLimit-Reset-After": "soon"}, "", 0},
	} {
		_, s, u := receiver(t, func(w http.ResponseWriter, _ *http.Request) {
			for k, v := range c.h {
				w.Header().Set(k, v)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, c.body)
		})
		_, err := s.Send(context.Background(), webhook.Delivery{Target: secret.New(u), Body: []byte("{}"), Policy: internal})
		var rl *webhook.RateLimitedError
		if !asRateLimited(err, &rl) || rl.After != c.want {
			t.Errorf("%s: %v, want a wait of %s", name, err, c.want)
		}
	}
}

func asRateLimited(err error, rl **webhook.RateLimitedError) bool {
	return errors.As(err, rl)
}
