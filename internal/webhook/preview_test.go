// SPDX-License-Identifier: Apache-2.0

package webhook_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/webhook"
)

// TestPreview: the sample messages are the ones a delivery makes, for an alert firing, resolving
// and a change, readable (markup written as itself), valid JSON, and refused for a format that has
// no message or options that do not fit it.
func TestPreview(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	c := chatCtx
	c.Options = webhook.Options{Mention: "subteam:S123", MentionWhen: "all"}
	got, err := webhook.Preview(webhook.FormatSlack, c, now)
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	for i, typ := range []string{"alert.fire", "alert.resolve", "route.update"} {
		if got[i].EventType != typ || !json.Valid([]byte(got[i].Body)) || strings.Contains(got[i].Body, `\u003c`) || strings.HasSuffix(got[i].Body, "\n") {
			t.Errorf("%s: not readable JSON (%d bytes)", typ, len(got[i].Body))
		}
	}
	if !strings.Contains(got[0].Body, "<!subteam^S123>") || strings.Contains(got[1].Body, "<!subteam^S123>") || !strings.Contains(got[1].Body, "Resolved after 7 m 30 s") {
		t.Errorf("mention or duration: %s %s", got[0].Body, got[1].Body)
	}
	// Names are made up when none is given, and the sample never names a real URL.
	got, err = webhook.Preview(webhook.FormatTeams, webhook.Context{}, now)
	if err != nil || !strings.Contains(got[2].Body, "Ada Admin") || !strings.Contains(got[0].Body, "Example org") || strings.Contains(got[0].Body, "https://") {
		t.Errorf("%v %v", got, err)
	}
	for name, c := range map[string]struct {
		f webhook.Format
		o webhook.Options
	}{
		"rpmgr":      {webhook.FormatRPMgr, webhook.Options{}},
		"empty":      {"", webhook.Options{}},
		"bad":        {webhook.FormatDiscord, webhook.Options{Mention: "role:everyone", MentionWhen: "all"}},
		"wrong kind": {webhook.FormatTeams, webhook.Options{ThreadName: "x"}},
	} {
		if _, err := webhook.Preview(c.f, webhook.Context{Options: c.o}, now); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
