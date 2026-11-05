// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The mention conditions of an endpoint (D170).
const (
	MentionNever    = "never"
	MentionCritical = "critical" // an alert of a critical kind that fires
	MentionAll      = "all"      // every alert that fires
)

// The limits of the options (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	DiscordUsername   = 80
	DiscordAvatarURL  = 2048
	DiscordThreadName = 100
	MentionMax        = 300
)

// Options are what a person tunes of a chat endpoint (docs/07-api.md, "Webhooks (Phase 2)"; D170).
// The zero Options changes nothing: no mention and the service's own name, avatar and thread.
type Options struct {
	// Mention is who the message mentions, by format: Discord role:<id> or user:<id>, Slack here,
	// subteam:<id> or user:<id>, Teams user:<UPN or Entra object id>. Empty: no one.
	Mention string
	// MentionWhen is MentionNever (also ""), MentionCritical or MentionAll.
	MentionWhen string
	// Username, AvatarURL and ThreadName are Discord's.
	Username, AvatarURL, ThreadName string
}

// OptionsOf are the options stored on an endpoint.
func OptionsOf(h *ent.Webhook) Options {
	return Options{Mention: h.Mention, MentionWhen: string(h.MentionWhen), Username: h.DiscordUsername,
		AvatarURL: h.DiscordAvatarURL, ThreadName: h.ThreadName}
}

var (
	snowflake = regexp.MustCompile(`^[0-9]{1,20}$`)
	slackID   = regexp.MustCompile(`^[A-Z0-9]{2,20}$`)
	// upn is a user principal name, an address such as ada@example.com; guid an Entra object id.
	upn  = regexp.MustCompile(`^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,63}$`)
	guid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// ValidateOptions checks o for an endpoint of format f. A format that has no such option refuses
// it, so that nothing a person set is silently ignored. The errors name no value but the field.
func ValidateOptions(f Format, o Options) error {
	if !f.Chat() {
		if o != (Options{}) && o != (Options{MentionWhen: MentionNever}) {
			return errors.New("webhook: mention and the Discord options are for a chat format")
		}
		return nil
	}
	switch o.MentionWhen {
	case "", MentionNever, MentionCritical, MentionAll:
	default:
		return errors.New("webhook: mention_when is never, critical or all")
	}
	if o.Mention == "" && (o.MentionWhen == MentionCritical || o.MentionWhen == MentionAll) {
		return errors.New("webhook: mention_when needs a mention")
	}
	if o.Mention != "" {
		if err := validMention(f, o.Mention); err != nil {
			return err
		}
	}
	if f != FormatDiscord {
		if o.Username != "" || o.AvatarURL != "" || o.ThreadName != "" {
			return errors.New("webhook: discord_username, discord_avatar_url and thread_name are for the discord format")
		}
		return nil
	}
	if n := utf8.RuneCountInString(o.Username); n > DiscordUsername {
		return fmt.Errorf("webhook: discord_username has at most %d characters", DiscordUsername)
	}
	if l := strings.ToLower(o.Username); strings.Contains(l, "clyde") || strings.Contains(l, "discord") {
		return errors.New("webhook: discord_username must not contain clyde or discord")
	}
	if n := utf8.RuneCountInString(o.ThreadName); n > DiscordThreadName {
		return fmt.Errorf("webhook: thread_name has at most %d characters", DiscordThreadName)
	}
	for _, s := range []string{o.Username, o.ThreadName} {
		if strings.IndexFunc(s, unicode.IsControl) >= 0 || !utf8.ValidString(s) {
			return errors.New("webhook: discord_username and thread_name have no control characters")
		}
	}
	if o.AvatarURL != "" {
		u, err := url.Parse(o.AvatarURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || len(o.AvatarURL) > DiscordAvatarURL ||
			strings.ContainsAny(o.AvatarURL, " \t\r\n") {
			return errors.New("webhook: discord_avatar_url is an https:// URL without credentials or a fragment")
		}
	}
	return nil
}

// validMention checks the target of a mention for format f.
func validMention(f Format, m string) error {
	kind, id, _ := strings.Cut(m, ":")
	ok := false
	switch f {
	case FormatDiscord:
		ok = (kind == "role" || kind == "user") && snowflake.MatchString(id)
	case FormatSlack:
		ok = m == "here" || kind == "subteam" && slackID.MatchString(id) && strings.HasPrefix(id, "S") ||
			kind == "user" && slackID.MatchString(id) && (strings.HasPrefix(id, "U") || strings.HasPrefix(id, "W"))
	case FormatTeams:
		ok = kind == "user" && len(id) <= MentionMax && (upn.MatchString(id) || guid.MatchString(id))
	}
	if !ok {
		return fmt.Errorf("webhook: mention is not valid for the %s format", f)
	}
	return nil
}

// mentioned reports whether a message of m mentions o's target: an alert firing, and for
// MentionCritical one of a critical kind. A resolve mentions no one.
func (o Options) mentioned(m message) bool {
	if o.Mention == "" || !m.alert || m.sev == sevResolved {
		return false
	}
	return o.MentionWhen == MentionAll || o.MentionWhen == MentionCritical && m.critical
}
