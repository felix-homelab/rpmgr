// SPDX-License-Identifier: Apache-2.0

package webhook_test

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

var chatFormats = []webhook.Format{webhook.FormatDiscord, webhook.FormatSlack, webhook.FormatTeams}

func body(t *testing.T, f webhook.Format, e events.Event, c webhook.Context) string {
	t.Helper()
	b, err := webhook.ChatBody(f, e, c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestChatBody_Titles: a readable title and the names, not the IDs, of the org and the actor; the
// IDs stay in the small context line.
func TestChatBody_Titles(t *testing.T) {
	for typ, want := range map[string]string{
		"route.update":     "Route web updated",
		"route_target.add": "Route target web add",
		"webhook.disable":  "Webhook web was disabled",
		"agent.disconnect": "Agent web disconnected",
		"webhook.test":     "Test event from rpmgr",
	} {
		e := events.Event{ID: "evt_9", OrgID: "org_1", Type: typ, Time: at, ActorType: "user", ActorID: "usr_1", SubjectType: "route", SubjectID: "rt_1", SubjectName: "web"}
		got := body(t, webhook.FormatSlack, e, chatCtx)
		if !strings.Contains(got, `"text":"`+want+`"`) {
			t.Errorf("%s: want the title %q in %s", typ, want, got)
		}
	}
	got := body(t, webhook.FormatDiscord, chatEvents["change"], chatCtx)
	for _, want := range []string{`"value":"Acme"`, `"value":"Ada Admin"`, `org\\_1 · rt\\_1 · evt\\_3`, `td.example · rpmgr 0.4.0`} {
		if !strings.Contains(got, want) {
			t.Errorf("want %s in %s", want, got)
		}
	}
	// Without names the IDs are shown, an instance event is the instance.
	got = body(t, webhook.FormatDiscord, chatEvents["instance-unicode"], webhook.Context{})
	if !strings.Contains(got, `"value":"instance"`) || !strings.Contains(got, `"value":"user usr\\_2"`) || strings.Contains(got, `"footer":{"text":"td`) {
		t.Errorf("instance event: %s", got)
	}
}

// TestChatBody_Link: the subject's page is built from the public URL, and there is no link
// without a usable one.
func TestChatBody_Link(t *testing.T) {
	e := chatEvents["change"]
	for public, want := range map[string]string{
		"https://rpmgr.example.com":      "https://rpmgr.example.com/routes/rt_1",
		"https://rpmgr.example.com/":     "https://rpmgr.example.com/routes/rt_1",
		"https://example.com/proxy/rpm/": "https://example.com/proxy/rpm/routes/rt_1",
	} {
		c := chatCtx
		c.PublicURL = public
		for _, f := range chatFormats {
			if got := body(t, f, e, c); !strings.Contains(got, want) || !strings.Contains(got, "Open in rpmgr") && f != webhook.FormatDiscord {
				t.Errorf("%s %s: no %s in %s", f, public, want, got)
			}
		}
	}
	for _, public := range []string{"", "  ", "not a url", "ftp://x.example", "javascript:alert(1)", "https://u:p@x.example", "https:///x"} {
		c := chatCtx
		c.PublicURL = public
		for _, f := range chatFormats {
			if got := body(t, f, e, c); strings.Contains(got, "Open in rpmgr") || strings.Contains(got, `"url"`) || strings.Contains(got, "/routes/") {
				t.Errorf("%s with public URL %q has a link: %s", f, public, got)
			}
		}
	}
}

// TestChatBody_LinksAreWebRoutes: every path a message links to is a route of the web router.
func TestChatBody_LinksAreWebRoutes(t *testing.T) {
	src, err := os.ReadFile("../../web/src/router.tsx")
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]bool{}
	for _, m := range regexp.MustCompile(`path: "([^"]+)"`).FindAllStringSubmatch(string(src), -1) {
		routes[regexp.MustCompile(`\$\w+`).ReplaceAllString(m[1], "*")] = true
	}
	for _, typ := range []string{"route", "connector", "agent", "gateway", "gateway_group", "domain", "policy", "webhook", "org", "user", "pki", "release", "unknown", ""} {
		for _, id := range []string{"x_1", "con_1", ""} {
			for _, org := range []string{"org_1", ""} {
				for _, et := range []string{"route.update", "alert.fire"} {
					e := events.Event{ID: "evt_1", OrgID: org, Type: et, Time: at, SubjectType: typ, SubjectID: id, Summary: "k: s"}
					var d struct {
						Embeds []struct{ URL string }
					}
					if err := json.Unmarshal([]byte(body(t, webhook.FormatDiscord, e, chatCtx)), &d); err != nil {
						t.Fatal(err)
					}
					u, err := url.Parse(d.Embeds[0].URL)
					if err != nil {
						t.Fatal(err)
					}
					path := u.Path
					if id != "" {
						path = strings.Replace(path, "/"+id, "/*", 1)
					}
					if path == "" {
						path = "/"
					}
					if !routes[path] {
						t.Errorf("%s %q %q %s: %s is no route of the web router (%v)", typ, id, org, et, path, routes)
					}
				}
			}
		}
	}
}

// TestChatBody_AlertDuration: a resolved alert says how long it lasted, and nothing wrong when the
// time it fired is unknown or later than the resolve.
func TestChatBody_AlertDuration(t *testing.T) {
	for fired, want := range map[time.Duration]string{
		-42 * time.Second:                "Resolved after 42 s.",
		-(5*time.Minute + 3*time.Second): "Resolved after 5 m 3 s.",
		-(26*time.Hour + 10*time.Minute): "Resolved after 1 d 2 h.",
		-(2*time.Hour + 59*time.Second):  "Resolved after 2 h 59 s.",
		0:                                "Resolved after 0 s.",
		time.Minute:                      "Resolved.",
		time.Duration(1<<63 - 1):         "Resolved.",
	} {
		c := chatCtx
		c.FiredAt = at.Add(fired)
		if got := body(t, webhook.FormatSlack, chatEvents["alert-resolve"], c); !strings.Contains(got, want) {
			t.Errorf("fired %s from the resolve: want %q in %s", fired, want, got)
		}
	}
	if got := body(t, webhook.FormatSlack, chatEvents["alert-resolve"], webhook.Context{}); !strings.Contains(got, `"text":"Resolved."`) || strings.Contains(got, "Lasted") {
		t.Errorf("unknown start: %s", got)
	}
}

// hostile are texts that would ping or format if they reached a service unescaped.
var hostile = []string{"@everyone", "@here", "<!channel>", "<!here>", "<!everyone>", "<@123>", "<@&456>", "<!subteam^S1>", "<at>Admin</at>",
	"[x](https://evil.example)", "**b**", "&amp;", "```", "‮"}

// TestChatBody_Hostile: no text of an event, org or actor can mention anyone or break the markup,
// in any field of any service.
func TestChatBody_Hostile(t *testing.T) {
	for _, h := range hostile {
		for _, typ := range []string{"alert.fire", "alert.resolve", "route.update", "agent.disconnect"} {
			e := events.Event{ID: "evt_1", OrgID: "org_1", Type: typ, Time: at, ActorType: "user", ActorID: h, SubjectType: "route", SubjectID: "rt_1",
				SubjectName: h, Summary: "agent_offline: " + h, Changed: []string{h}}
			c := chatCtx
			c.OrgName, c.ActorName, c.TrustDomain, c.Version = h, h, h, h
			c.FiredAt = at.Add(-time.Hour)
			for _, f := range chatFormats {
				b := body(t, f, e, c)
				var texts []string
				collect(t, "", mustJSON(t, []byte(b)), &texts)
				for _, s := range texts {
					switch f {
					case webhook.FormatDiscord:
						// Discord needs the markup escaped: a mention is <…>, a link [..](..).
						unescapedCheck(t, f, h, s)
					case webhook.FormatSlack:
						// Only the date control of the message's own context is a control.
						s = strings.ReplaceAll(s, "<!date^", "")
						if strings.ContainsAny(strings.ReplaceAll(strings.ReplaceAll(s, "&amp;", ""), "&lt;", ""), "<") {
							t.Errorf("slack %q: an unescaped < in %q", h, s)
						}
					case webhook.FormatTeams:
						if strings.Contains(s, "<at>") && !strings.Contains(s, `\<at`) {
							t.Errorf("teams %q: a raw <at> in %q", h, s)
						}
						unescapedCheck(t, f, h, s)
					}
				}
				if f == webhook.FormatDiscord && !strings.Contains(b, `"allowed_mentions":{"parse":[]}`) {
					t.Errorf("discord %q: %s", h, b)
				}
				if strings.Contains(b, `"msteams":{"entities"`) || strings.Contains(b, `"mentions"`) {
					t.Errorf("%s %q: a mention without one configured: %s", f, h, b)
				}
			}
		}
	}
}

// unescapedCheck fails if s holds one of the Markdown characters of the hostile text h unescaped.
func unescapedCheck(t *testing.T, f webhook.Format, h, s string) {
	t.Helper()
	if strings.Contains(s, "{{DATE(") || strings.Contains(h, "&amp;") {
		return
	}
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case strings.ContainsRune("*`[]<>", r) && strings.ContainsRune(h, r):
			t.Errorf("%s %q: %q holds an unescaped %q", f, h, s, r)
			return
		}
	}
}

// maximal is an event with every text at a length no limit allows, and a context to match.
func maximal() (events.Event, webhook.Context) {
	long := strings.Repeat("🚀<&>*", 3000)
	e := events.Event{ID: "evt_" + long, OrgID: "org_" + long, Type: "alert.fire", Time: at, ActorType: "user", ActorID: long, SubjectType: long,
		SubjectID: long, SubjectName: long, Summary: "agent_offline: " + long, Changed: []string{long, long, long}}
	c := webhook.Context{OrgName: long, ActorName: long, PublicURL: "https://rpmgr.example.com/" + strings.Repeat("p/", 100), TrustDomain: long, Version: long}
	return e, c
}

// TestChatBody_Maximal: an event whose texts are all far too long still makes a message within the
// limits of the service (docs/03-connections.md), for every severity.
func TestChatBody_Maximal(t *testing.T) {
	e, c := maximal()
	c.FiredAt = at.Add(-time.Hour)
	for _, typ := range []string{"alert.fire", "alert.resolve", "route.update"} {
		e.Type = typ
		for _, f := range chatFormats {
			b, err := webhook.ChatBody(f, e, c)
			if err != nil || !utf8.Valid(b) {
				t.Fatalf("%s %s: %v", f, typ, err)
			}
			var v map[string]any
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatal(err)
			}
			switch f {
			case webhook.FormatDiscord:
				emb := v["embeds"].([]any)
				if len(emb) != 1 {
					t.Fatalf("%d embeds", len(emb))
				}
				em := emb[0].(map[string]any)
				total := 0
				count := func(s any, limit int, what string) {
					n := utf8.RuneCountInString(s.(string))
					total += n
					if n > limit {
						t.Errorf("discord %s: %s has %d characters, over %d", typ, what, n, limit)
					}
				}
				count(em["title"], 256, "title")
				count(em["description"], 4096, "description")
				count(em["footer"].(map[string]any)["text"], 2048, "footer")
				fs := em["fields"].([]any)
				if len(fs) > 25 {
					t.Errorf("discord: %d fields", len(fs))
				}
				for _, f := range fs {
					count(f.(map[string]any)["name"], 256, "field name")
					count(f.(map[string]any)["value"], 1024, "field value")
				}
				if total > 6000 {
					t.Errorf("discord %s: the embed has %d characters, over 6000", typ, total)
				}
			case webhook.FormatSlack:
				blocks := v["attachments"].([]any)[0].(map[string]any)["blocks"].([]any)
				if len(blocks) > 50 {
					t.Errorf("slack: %d blocks", len(blocks))
				}
				for _, bl := range blocks {
					bm := bl.(map[string]any)
					if tx, ok := bm["text"].(map[string]any); ok {
						limit := 3000
						if bm["type"] == "header" {
							limit = 150
						}
						if n := utf8.RuneCountInString(tx["text"].(string)); n > limit {
							t.Errorf("slack %s: a %s text of %d characters, over %d", typ, bm["type"], n, limit)
						}
					}
					if fs, ok := bm["fields"].([]any); ok {
						if len(fs) > 10 {
							t.Errorf("slack: %d fields", len(fs))
						}
						for _, f := range fs {
							if n := utf8.RuneCountInString(f.(map[string]any)["text"].(string)); n > 2000 {
								t.Errorf("slack: a field of %d characters", n)
							}
						}
					}
					if el, ok := bm["elements"].([]any); ok && len(el) > 10 {
						t.Errorf("slack: %d elements", len(el))
					}
				}
			case webhook.FormatTeams:
				if len(b) > 28*1024 {
					t.Errorf("teams %s: %d bytes, over 28 KiB", typ, len(b))
				}
			}
			if len(b) > webhook.MaxBody {
				t.Errorf("%s %s: %d bytes, over what a delivery sends", f, typ, len(b))
			}
		}
	}
}

// TestContext_Resolve: names come from the store at render time, and a lookup that finds nothing
// leaves the ID, never an error.
func TestContext_Resolve(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "acme")
		usr := db.Client().User.Create().SetEmail("ada@example.com").SetDisplayName("Ada Admin").SaveX(sys)
		fire := db.Client().Event.Create().SetOrgID(org).SetType("alert.fire").SetTs(at.Add(-10 * time.Minute)).SetActorType("system").
			SetSubjectType("agent").SetSubjectID("gw_1").SetSummary("agent_offline: Agent offline fires, gw1").SaveX(sys)
		// Another alert's firing, and an older one, must not be taken for the firing that ended.
		db.Client().Event.Create().SetOrgID(org).SetType("alert.fire").SetTs(at.Add(-5 * time.Minute)).SetActorType("system").
			SetSubjectType("agent").SetSubjectID("gw_2").SetSummary("agent_offline: x").SaveX(sys)
		db.Client().Event.Create().SetOrgID(org).SetType("alert.fire").SetTs(at.Add(-5 * time.Minute)).SetActorType("system").
			SetSubjectType("agent").SetSubjectID("gw_1").SetSummary("clock_skew: x").SaveX(sys)

		e := events.Event{OrgID: org, Type: "alert.resolve", Time: at, ActorType: "user", ActorID: usr.ID, SubjectType: "agent", SubjectID: "gw_1",
			Summary: "agent_offline: Agent offline resolved, gw1"}
		var c webhook.Context
		c.Resolve(sys, db.Client(), e)
		if c.OrgName != "acme" || c.ActorName != "Ada Admin" || !c.FiredAt.Equal(fire.Ts) {
			t.Errorf("resolved %+v", c)
		}

		// Nothing found, a nil client and a failed lookup: the zero Context, no panic.
		for name, e := range map[string]events.Event{
			"unknown ids": {OrgID: "org_none", Type: "alert.resolve", ActorType: "user", ActorID: "usr_none", SubjectType: "agent", SubjectID: "gw_9", Summary: "agent_offline: x", Time: at},
			"other kinds": {Type: "route.update", ActorType: "agent", ActorID: "gw_1"},
		} {
			var c webhook.Context
			c.Resolve(sys, db.Client(), e)
			if c != (webhook.Context{}) {
				t.Errorf("%s: %+v", name, c)
			}
		}
		var c2 webhook.Context
		c2.Resolve(sys, nil, e)
		if c2 != (webhook.Context{}) {
			t.Errorf("nil client: %+v", c2)
		}
		cctx, cancel := contextCancelled()
		defer cancel()
		c2.Resolve(cctx, db.Client(), e)
		if c2 != (webhook.Context{}) {
			t.Errorf("cancelled: %+v", c2)
		}
	})
}

func contextCancelled() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, cancel
}
