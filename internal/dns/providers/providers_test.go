// SPDX-License-Identifier: Apache-2.0

package providers_test

import (
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

func TestExpiring(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { x := now.Add(d); return &x }
	for _, c := range []struct {
		name string
		exp  *time.Time
		want bool
	}{
		{"no expiry", nil, false},
		{"far away", at(providers.ExpiryWarning + time.Second), false},
		{"on the boundary", at(providers.ExpiryWarning), true},
		{"soon", at(24 * time.Hour), true},
		{"just now", at(0), true},
		{"past", at(-time.Hour), true},
	} {
		if got := providers.Expiring(c.exp, now); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestDialRefusesUnknownKind(t *testing.T) {
	if _, err := providers.Dial("route53", "", secretOf("x")); err == nil {
		t.Fatal("an unknown kind")
	}
}

func secretOf(s string) secret.Value { return secret.New(s) }
