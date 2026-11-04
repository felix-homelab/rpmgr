// SPDX-License-Identifier: Apache-2.0

package dns_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
)

func TestBatch_Len(t *testing.T) {
	if (dns.Batch{}).Len() != 0 {
		t.Fatal("empty batch")
	}
	b := dns.Batch{Deletes: []string{"a"}, Patches: make([]dns.Record, 2), Puts: make([]dns.Record, 3), Posts: make([]dns.Record, 4)}
	if b.Len() != 10 {
		t.Fatalf("%d", b.Len())
	}
}

func TestTokenInfo_Active(t *testing.T) {
	for s, want := range map[string]bool{"active": true, "Active": true, "expired": false, "disabled": false, "": false} {
		if got := (dns.TokenInfo{Status: s}).Active(); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
}

func TestProviderError(t *testing.T) {
	until := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	rl := &dns.ProviderError{Status: 429, Err: dns.RateLimited{Until: until}, Messages: []string{"a", "b"}}
	var got dns.RateLimited
	if !errors.As(fmt.Errorf("wrapped: %w", rl), &got) || !got.Until.Equal(until) {
		t.Fatal("RateLimited is not found")
	}
	if s := rl.Error(); !strings.Contains(s, "2030-01-02T03:04:05Z") || !strings.Contains(s, "429") || !strings.Contains(s, "a; b") {
		t.Fatal(s)
	}
	if s := (&dns.ProviderError{Status: 500}).Error(); s != "dns: provider answered HTTP 500" {
		t.Fatal(s)
	}
	for _, e := range []error{dns.ErrUnauthorized, dns.ErrForbidden, dns.ErrNotFound} {
		if !errors.Is(&dns.ProviderError{Status: 400, Err: e}, e) {
			t.Fatalf("%v", e)
		}
	}
	if errors.Is(&dns.ProviderError{Status: 401, Err: dns.ErrUnauthorized}, dns.ErrForbidden) {
		t.Fatal("kinds mixed up")
	}
}
