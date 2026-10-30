// SPDX-License-Identifier: Apache-2.0

package webhook_test

import (
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/webhook"
)

func TestValidateURL(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", webhook.MaxURL-len("https://example.com/"))
	for u, ok := range map[string]bool{
		"https://example.com/hook":       true,
		"https://example.com:8443/h?t=1": true,
		"https://[2001:db8::1]/h":        true,
		long:                             true, // exactly MaxURL bytes
		long + "a":                       false,
		"":                               false,
		"http://example.com/":            false,
		"HTTP://example.com/":            false,
		"//example.com/":                 false,
		"example.com/hook":               false,
		"https://":                       false,
		"https:///path":                  false,
		"https://user@example.com/":      false,
		"https://user:pw@example.com/":   false,
		"https://example.com/#frag":      false,
		"https://example.com/%zz":        false,
		"javascript:alert(1)":            false,
		"https://exa mple.com/":          false,
	} {
		if err := webhook.ValidateURL(u); (err == nil) != ok {
			t.Errorf("%.40q: %v, want ok=%v", u, err, ok)
		}
	}
}

func TestValidateEventTypes(t *testing.T) {
	many := make([]string, webhook.MaxEventTypes)
	for i := range many {
		many[i] = "t" + strings.Repeat("a", i)
	}
	for name, c := range map[string]struct {
		types []string
		ok    bool
	}{
		"none":            {nil, true},
		"a name":          {[]string{"route.update"}, true},
		"a prefix":        {[]string{"route.*", "token.revoke", "route_target.create", "webhook.disable"}, true},
		"the limit":       {many, true},
		"over the limit":  {append(many, "x"), false},
		"empty":           {[]string{""}, false},
		"a bare star":     {[]string{"*"}, false},
		"upper case":      {[]string{"Route.update"}, false},
		"a space":         {[]string{"route update"}, false},
		"a star inside":   {[]string{"ro*ute.x"}, false},
		"a trailing dot":  {[]string{"route."}, false},
		"a leading digit": {[]string{"1route"}, false},
		"duplicates":      {[]string{"route.*", "route.*"}, false},
		"too long":        {[]string{strings.Repeat("a", webhook.MaxEventType+1)}, false},
	} {
		if err := webhook.ValidateEventTypes(c.types); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", name, err, c.ok)
		}
	}
}

func TestNewSecret(t *testing.T) {
	a, err := webhook.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := webhook.NewSecret()
	if s := a.Reveal(); !strings.HasPrefix(s, webhook.SecretPrefix) || len(s) != len(webhook.SecretPrefix)+52 || s == b.Reveal() { //nolint:forbidigo // the test reads the secret it made
		t.Fatalf("secrets of %d and %d bytes", len(s), len(b.Reveal())) //nolint:forbidigo // lengths only
	}
	if strings.Contains(a.String(), webhook.SecretPrefix) {
		t.Error("a secret prints itself")
	}
}
