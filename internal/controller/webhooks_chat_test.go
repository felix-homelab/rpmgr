// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"os"
	"path/filepath"

	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	ewebhook "github.com/felix-homelab/rpmgr/internal/store/ent/webhook"
	"github.com/felix-homelab/rpmgr/internal/store/ent/webhookdelivery"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
	"github.com/felix-homelab/rpmgr/internal/webhook"
)

const chatToken = "CHATTOKEN-abcdefghijklmnop" //nolint:gosec // G101: a test token

// chatHook makes a chat endpoint of org at path: its URL sealed in url_enc, its url the scheme and
// host, and no signing secret, as the API makes it.
func (e *hookEnv) chatHook(org, path string, f ewebhook.Format, types ...string) *ent.Webhook {
	e.t.Helper()
	id := ids.New("whk")
	sealed, err := e.sealer.Seal(secret.Context{Table: "webhooks", Column: "url_enc", RowID: id}, secret.New(e.url+path+"/"+chatToken))
	if err != nil {
		e.t.Fatal(err)
	}
	return e.db.Client().Webhook.Create().SetID(id).SetOrgID(org).SetURL(e.url).SetURLEnc(sealed).SetSecretEnc([]byte{}).SetFormat(f).
		SetEventTypes(types).SetEnabledAt(e.clock).SaveX(e.sys)
}

// TestWebhookJob_Chat (D162): a chat endpoint gets each service's message, not the envelope, with
// no signature, from its sealed URL; a failure's record and the job's log never name the URL.
func TestWebhookJob_Chat(t *testing.T) {
	e := newHookEnv(t, false)
	org := storetest.Org(t, e.db, "org-a")
	for path, f := range map[string]ewebhook.Format{"/discord": ewebhook.FormatDiscord, "/slack": ewebhook.FormatSlack, "/teams": ewebhook.FormatTeams, "/plain": ewebhook.FormatRpmgr} {
		if f == ewebhook.FormatRpmgr {
			e.hook(org, path)
		} else {
			e.chatHook(org, path, f)
		}
	}
	time.Sleep(2 * time.Millisecond)
	e.change(org, "route.update")
	e.mustRun()
	want := map[string]string{"/discord/" + chatToken: `"embeds"`, "/slack/" + chatToken: `"blocks"`, "/teams/" + chatToken: `"AdaptiveCard"`, "/plain": `"summary"`}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.got) != 4 {
		t.Fatalf("%d requests, want 4", len(e.got))
	}
	for _, g := range e.got {
		sub, ok := want[g.path]
		if !ok || !strings.Contains(string(g.body), sub) {
			t.Errorf("%s got %s", g.path, g.body)
		}
		if signed := g.sig != "" || g.id != "" || g.typ != ""; signed != (g.path == "/plain") {
			t.Errorf("%s: signed %v", g.path, signed)
		}
		if g.path != "/plain" && !strings.Contains(string(g.body), "route.update route rte") {
			t.Errorf("%s: the message lacks the summary: %s", g.path, g.body)
		}
	}
	for _, d := range e.db.Client().WebhookDelivery.Query().AllX(e.sys) {
		if d.StatusCode != 204 || d.Error != "" {
			t.Errorf("delivery %+v", d)
		}
	}
}

// TestWebhookJob_ChatFailureNamesNoURL: a failing chat endpoint's delivery record and the job's log
// hold neither its URL nor its token, whether the service answers 500 or the sealed URL is bad.
func TestWebhookJob_ChatFailureNamesNoURL(t *testing.T) {
	e := newHookEnv(t, false)
	org := storetest.Org(t, e.db, "org-a")
	e.answer = func(string, int) int { return http.StatusInternalServerError }
	h := e.chatHook(org, "/slack", ewebhook.FormatSlack)
	bad := e.chatHook(org, "/broken", ewebhook.FormatSlack)
	e.db.Client().Webhook.UpdateOneID(bad.ID).SetURLEnc([]byte("not sealed at all")).ExecX(e.sys)
	time.Sleep(2 * time.Millisecond)
	e.change(org, "route.update")
	e.mustRun()
	rows := e.db.Client().WebhookDelivery.Query().AllX(e.sys)
	if len(rows) != 2 {
		t.Fatalf("%d deliveries", len(rows))
	}
	for _, r := range rows {
		if strings.Contains(r.Error, chatToken) || strings.Contains(r.Error, "example.com") || r.Error == "" {
			t.Errorf("delivery of %s: %q", r.WebhookID, r.Error)
		}
	}
	if strings.Contains(e.logs.String(), chatToken) {
		t.Errorf("the log holds the token: %s", e.logs.String())
	}
	if hk := e.db.Client().Webhook.GetX(e.sys, h.ID); hk.FailingSince == nil {
		t.Error("a 500 is a failure of the endpoint")
	}
}

// TestWebhookJob_ChatRateLimit (D162): a 429 delays the next attempt by Retry-After or Discord's
// retry_after, within the bounds, does not start the endpoint's failing period or count towards
// its disabling, and without a time takes the ordinary backoff; an rpmgr endpoint's 429 is an
// ordinary failure.
func TestWebhookJob_ChatRateLimit(t *testing.T) {
	for name, c := range map[string]struct {
		header    string
		body      string
		wantAfter time.Duration
	}{
		"Retry-After":   {"30", "", 30 * time.Second},
		"Discord":       {"", `{"retry_after": 4.5}`, webhook.RetryFirst}, // the ordinary backoff is longer,
		"too long":      {"86400", "", webhook.RetryAfterMax},
		"a short one":   {"0", "", webhook.RetryFirst},
		"no time":       {"", "", webhook.RetryFirst},
		"unusable time": {"later", "", webhook.RetryFirst},
	} {
		t.Run(name, func(t *testing.T) {
			e := newHookEnv(t, false)
			org := storetest.Org(t, e.db, "org-a")
			h := e.chatHook(org, "/discord", ewebhook.FormatDiscord)
			e.answer = func(string, int) int { return http.StatusTooManyRequests }
			e.reply, e.replyBody = http.Header{}, c.body
			if c.header != "" {
				e.reply.Set("Retry-After", c.header)
			}
			time.Sleep(2 * time.Millisecond)
			e.change(org, "alert.fire")
			e.mustRun()
			d := e.db.Client().WebhookDelivery.Query().OnlyX(e.sys)
			if d.StatusCode != 429 || d.NextAttemptAt == nil || d.NextAttemptAt.Sub(d.SentAt) != c.wantAfter || !strings.Contains(d.Error, "rate limiting") {
				t.Fatalf("attempt %+v, want a retry in %s", d, c.wantAfter)
			}
			if hk := e.db.Client().Webhook.GetX(e.sys, h.ID); hk.FailingSince != nil || hk.LastSuccessAt != nil || !hk.Enabled {
				t.Fatalf("endpoint %+v: a rate limit is no failure", hk)
			}
			// Not before it was asked to wait, then once, and a success clears the schedule.
			n := len(e.ids("/discord/" + chatToken))
			e.clock = e.clock.Add(c.wantAfter - time.Millisecond)
			e.mustRun()
			if len(e.ids("/discord/"+chatToken)) != n {
				t.Fatal("retried before the wait was over")
			}
			e.answer = func(string, int) int { return http.StatusNoContent }
			e.clock = e.clock.Add(time.Millisecond)
			e.mustRun()
			rows := e.db.Client().WebhookDelivery.Query().Order(ent.Asc(webhookdelivery.FieldAttempt)).AllX(e.sys)
			if len(rows) != 2 || rows[1].Attempt != 2 || rows[1].StatusCode != 204 || rows[0].NextAttemptAt != nil || rows[1].NextAttemptAt != nil {
				t.Fatalf("attempts %+v", rows)
			}
			if hk := e.db.Client().Webhook.GetX(e.sys, h.ID); hk.LastSuccessAt == nil || hk.FailingSince != nil {
				t.Fatalf("endpoint %+v", hk)
			}
		})
	}

	// A service that answers 429 with a wait of 0 s for ever is not asked every pass: the spacing
	// is at least the ordinary backoff, doubling, and from the attempt webhook.RateLimitFailAfter on
	// each 429 counts as a failure, so the endpoint's failing period starts and it is disabled after
	// the period in docs/03 like any failing endpoint.
	t.Run("a flood of 429s backs off and then counts", func(t *testing.T) {
		e := newHookEnv(t, false)
		org := storetest.Org(t, e.db, "org-a")
		h := e.chatHook(org, "/discord", ewebhook.FormatDiscord)
		e.answer = func(string, int) int { return http.StatusTooManyRequests }
		e.reply = http.Header{"Retry-After": {"0"}}
		time.Sleep(2 * time.Millisecond)
		e.change(org, "alert.fire")
		var gaps []time.Duration
		for i := 1; i <= webhook.RateLimitFailAfter+3; i++ {
			e.mustRun()
			d := e.db.Client().WebhookDelivery.Query().Where(webhookdelivery.Attempt(i)).OnlyX(e.sys)
			if d.NextAttemptAt == nil {
				t.Fatalf("attempt %d has no retry: %+v", i, d)
			}
			gaps = append(gaps, d.NextAttemptAt.Sub(d.SentAt))
			failing := e.db.Client().Webhook.GetX(e.sys, h.ID).FailingSince != nil
			if failing != (i >= webhook.RateLimitFailAfter) {
				t.Fatalf("after attempt %d the endpoint's failing is %v", i, failing)
			}
			e.clock = *d.NextAttemptAt
		}
		want := webhook.RetryFirst
		for i, g := range gaps {
			if g != want {
				t.Errorf("gap %d is %s, want %s: %v", i+1, g, want, gaps)
			}
			want *= 2
		}
		if n := e.db.Client().WebhookDelivery.Query().CountX(e.sys); n != len(gaps) {
			t.Errorf("%d deliveries after %d passes", n, len(gaps))
		}
		// Three days of 429s disable it, as of any failure.
		e.db.Client().Webhook.UpdateOneID(h.ID).SetFailingSince(e.clock.Add(-webhook.DisableAfter)).ExecX(e.sys)
		e.mustRun()
		if e.db.Client().Webhook.GetX(e.sys, h.ID).Enabled {
			t.Error("an endpoint that kept answering 429 was not disabled")
		}
	})

	t.Run("never disables", func(t *testing.T) {
		e := newHookEnv(t, false)
		org := storetest.Org(t, e.db, "org-a")
		h := e.chatHook(org, "/discord", ewebhook.FormatDiscord)
		e.db.Client().Webhook.UpdateOneID(h.ID).SetFailingSince(e.clock.Add(-webhook.DisableAfter - time.Hour)).ExecX(e.sys)
		e.answer = func(string, int) int { return http.StatusTooManyRequests }
		time.Sleep(2 * time.Millisecond)
		e.change(org, "alert.fire")
		e.mustRun()
		hk := e.db.Client().Webhook.GetX(e.sys, h.ID)
		if !hk.Enabled || hk.FailingSince == nil {
			t.Fatalf("endpoint %+v: a rate limit disabled it or cleared its failing period", hk)
		}
	})

	t.Run("an rpmgr endpoint", func(t *testing.T) {
		e := newHookEnv(t, false)
		org := storetest.Org(t, e.db, "org-a")
		h := e.hook(org, "/plain")
		e.answer = func(string, int) int { return http.StatusTooManyRequests }
		e.reply = http.Header{"Retry-After": {"600"}}
		time.Sleep(2 * time.Millisecond)
		e.change(org, "route.update")
		e.mustRun()
		d := e.db.Client().WebhookDelivery.Query().OnlyX(e.sys)
		if d.NextAttemptAt == nil || d.NextAttemptAt.Sub(d.SentAt) != webhook.RetryFirst || e.db.Client().Webhook.GetX(e.sys, h.ID).FailingSince == nil {
			t.Fatalf("attempt %+v: an rpmgr endpoint's 429 is an ordinary failure", d)
		}
	})
}

// TestKEK_RotateKeepsChatURLDeliverable: `kek rotate` re-wraps the sealed URL of a chat endpoint, so
// after it the URL opens under the new KEK, under its own context only, and not under the old KEK.
func TestKEK_RotateKeepsChatURLDeliverable(t *testing.T) {
	ctx := context.Background()
	h, _ := initHost(t)
	k1, err := secret.LoadKEKFile(h.kek)
	if err != nil {
		t.Fatal(err)
	}
	s1, _ := secret.NewSealer(k1)
	const url = "https://discord.com/api/webhooks/1/" + chatToken
	id := ids.New("whk")
	sealed, err := s1.Seal(secret.Context{Table: "webhooks", Column: "url_enc", RowID: id}, secret.New(url))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	db.Client().Webhook.Create().SetID(id).SetURL("https://discord.com").SetURLEnc(sealed).SetSecretEnc([]byte{}).
		SetFormat(ewebhook.FormatDiscord).SaveX(storetest.SystemCtx(t))
	_ = db.Close()

	prev := filepath.Join(t.TempDir(), "old-kek")
	if err := os.Rename(h.kek, prev); err != nil {
		t.Fatal(err)
	}
	k2 := writeKEK(t, h.kek, 0o600)
	if _, _, err := controller.RotateKEK(ctx, h.cfg, prev, noEnv); err != nil {
		t.Fatal(err)
	}
	db, err = store.OpenSQLite(ctx, h.db, store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	row := db.Client().Webhook.GetX(storetest.SystemCtx(t), id)
	own, other := secret.Context{Table: "webhooks", Column: "url_enc", RowID: id}, secret.Context{Table: "webhooks", Column: "url_enc", RowID: ids.New("whk")}
	s2, _ := secret.NewSealer(k2)
	if v, err := s2.Open(own, *row.URLEnc); err != nil || !v.EqualString(url) {
		t.Fatalf("the URL under the new KEK: %v", err)
	}
	if _, err := s2.Open(other, *row.URLEnc); err == nil {
		t.Error("the URL opens in another row's context")
	}
	if _, err := s1.Open(own, *row.URLEnc); err == nil {
		t.Error("the URL still opens under the old KEK")
	}
}
