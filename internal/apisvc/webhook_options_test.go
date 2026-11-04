// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// TestWebhooks_ChatOptions (D170): the mention and the Discord options are validated against the
// format on create and on update, come back in every answer, default to none, and a delete takes
// the endpoint's stored messages with it.
func TestWebhooks_ChatOptions(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	d, s, tm := rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_DISCORD, rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_SLACK, rpmgrv1.WebhookFormat_WEBHOOK_FORMAT_TEAMS
	crit, all := rpmgrv1.WebhookMentionWhen_WEBHOOK_MENTION_WHEN_CRITICAL, rpmgrv1.WebhookMentionWhen_WEBHOOK_MENTION_WHEN_ALL
	for name, c := range map[string]*rpmgrv1.Webhook{
		"discord everyone":       {Format: d, SecretUrl: discordURL, Mention: "role:everyone", MentionWhen: all},
		"discord markup":         {Format: d, SecretUrl: discordURL, Mention: "role:1> @everyone <@&2", MentionWhen: all},
		"slack mention, discord": {Format: s, SecretUrl: slackURL, Mention: "role:123", MentionWhen: all},
		"when without mention":   {Format: d, SecretUrl: discordURL, MentionWhen: crit},
		"username on slack":      {Format: s, SecretUrl: slackURL, DiscordUsername: "x"},
		"thread on teams":        {Format: tm, SecretUrl: teamsURL, ThreadName: "x"},
		"avatar over http":       {Format: d, SecretUrl: discordURL, DiscordAvatarUrl: "http://cdn.example/a.png"},
		"username with discord":  {Format: d, SecretUrl: discordURL, DiscordUsername: "my discord"},
		"username too long":      {Format: d, SecretUrl: discordURL, DiscordUsername: strings.Repeat("a", 81)},
		"thread too long":        {Format: d, SecretUrl: discordURL, ThreadName: strings.Repeat("a", 101)},
		"mention on rpmgr":       {Url: hookURL, Mention: "here", MentionWhen: all},
		"username on rpmgr":      {Url: hookURL, DiscordUsername: "x"},
	} {
		_, err := ada.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org, Webhook: c}))
		if code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		} else if strings.Contains(err.Error(), "everyone") || strings.Contains(err.Error(), "TOKEN") {
			t.Errorf("%s: the error echoes a value: %v", name, err)
		}
	}
	if n := e.db.Client().Webhook.Query().CountX(e.sys); n != 0 {
		t.Fatalf("%d endpoints after the refusals", n)
	}

	// Valid options are stored and come back; a request without any has none.
	r, err := ada.wh.CreateWebhook(ctx, connect.NewRequest(&rpmgrv1.CreateWebhookRequest{OrgId: org, Webhook: &rpmgrv1.Webhook{Format: d, SecretUrl: discordURL,
		Mention: "role:123456789012345678", MentionWhen: crit, DiscordUsername: "rpmgr alerts", DiscordAvatarUrl: "https://cdn.example/a.png", ThreadName: "alerts"}}))
	if err != nil {
		t.Fatal(err)
	}
	w := r.Msg.GetWebhook()
	if w.GetMention() != "role:123456789012345678" || w.GetMentionWhen() != crit || w.GetDiscordUsername() != "rpmgr alerts" ||
		w.GetDiscordAvatarUrl() != "https://cdn.example/a.png" || w.GetThreadName() != "alerts" {
		t.Fatalf("options of the answer: %v", w)
	}
	plain, err := newChat(t, e, ada, org, s, slackURL)
	if err != nil {
		t.Fatal(err)
	}
	if p := plain.GetWebhook(); p.GetMention() != "" || p.GetMentionWhen() != rpmgrv1.WebhookMentionWhen_WEBHOOK_MENTION_WHEN_NEVER || p.GetDiscordUsername() != "" {
		t.Fatalf("a request without options: %v", p)
	}

	// Update: options by mask, checked against the format; the others are left alone.
	id, etag := w.GetId(), w.GetEtag()
	up, err := updateHook(ada, &rpmgrv1.Webhook{Id: id, MentionWhen: all}, etag, "mention_when")
	if err != nil || up.GetMentionWhen() != all || up.GetMention() != "role:123456789012345678" || up.GetDiscordUsername() != "rpmgr alerts" {
		t.Fatalf("when only: %v %v", up, err)
	}
	if _, err := updateHook(ada, &rpmgrv1.Webhook{Id: id, Mention: "here"}, up.GetEtag(), "mention"); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a Slack mention on Discord: %v", err)
	}
	if _, err := updateHook(ada, &rpmgrv1.Webhook{Id: id, DiscordAvatarUrl: "http://x.example/a"}, up.GetEtag(), "discord_avatar_url"); code(err) != connect.CodeInvalidArgument {
		t.Errorf("an http avatar: %v", err)
	}
	// Moving to Slack with Discord's options left set is refused, not ignored.
	if _, err := updateHook(ada, &rpmgrv1.Webhook{Id: id, Format: s, SecretUrl: slackURL}, up.GetEtag(), "format", "secret_url"); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a format change that keeps options of the old one: %v", err)
	}
	// ... and works once they are cleared in the same update.
	moved, err := updateHook(ada, &rpmgrv1.Webhook{Id: id, Format: s, SecretUrl: slackURL, Mention: "subteam:S123", MentionWhen: crit},
		up.GetEtag(), "format", "secret_url", "mention", "mention_when", "discord_username", "discord_avatar_url", "thread_name")
	if err != nil || moved.GetMention() != "subteam:S123" || moved.GetDiscordUsername() != "" || moved.GetThreadName() != "" {
		t.Fatalf("moved: %v %v", moved, err)
	}
	// Clearing the mention.
	cleared, err := updateHook(ada, &rpmgrv1.Webhook{Id: id}, moved.GetEtag(), "mention", "mention_when")
	if err != nil || cleared.GetMention() != "" || cleared.GetMentionWhen() != rpmgrv1.WebhookMentionWhen_WEBHOOK_MENTION_WHEN_NEVER {
		t.Fatalf("cleared: %v %v", cleared, err)
	}
	// An rpmgr endpoint takes no option.
	h, _ := newHook(t, e, ada, org, hookURL)
	if _, err := updateHook(ada, &rpmgrv1.Webhook{Id: h.GetId(), Mention: "here"}, h.GetEtag(), "mention"); code(err) != connect.CodeInvalidArgument {
		t.Errorf("a mention on an rpmgr endpoint: %v", err)
	}

	// A delete takes the stored messages of the endpoint, and only its own.
	for _, wid := range []string{id, plain.GetWebhook().GetId()} {
		e.db.Client().WebhookMessage.Create().SetWebhookID(wid).SetOrgID(org).SetAlertKey("k|a|" + wid).SetMessageID("7").ExecX(e.sys)
	}
	if _, err := ada.wh.DeleteWebhook(ctx, connect.NewRequest(&rpmgrv1.DeleteWebhookRequest{WebhookId: id})); err != nil {
		t.Fatal(err)
	}
	if ms := e.db.Client().WebhookMessage.Query().AllX(e.sys); len(ms) != 1 || ms[0].WebhookID != plain.GetWebhook().GetId() {
		t.Errorf("messages after the delete: %+v", ms)
	}
}
