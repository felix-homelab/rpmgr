// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package providers_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/dns/providers"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

const (
	token   = "a-token-of-the-test-0123456789"
	account = "0123456789abcdef0123456789abcdef"
)

func client(t *testing.T, f *cftest.Server, tok, account string) dns.Provider {
	t.Helper()
	c, err := cloudflare.NewForTest(cloudflare.Config{Token: secret.New(tok), AccountID: account}, f.URL(), f.RootCAs())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestCheck: the verdict on a token from what Cloudflare answers: accepted with and without an
// expiry; refused by 401 and 403; reported expired or disabled; and no verdict at all when the
// provider rate-limits or fails.
func TestCheck(t *testing.T) {
	f := cftest.New(t, token)
	ctx := context.Background()
	if o := providers.Check(ctx, client(t, f, token, "")); !o.OK || o.Expires != nil || o.Err != nil {
		t.Fatalf("a token without an expiry: %+v", o)
	}
	f.SetTokenStatus("active", "2030-01-02T03:04:05Z")
	o := providers.Check(ctx, client(t, f, token, ""))
	if !o.OK || o.Expires == nil || !o.Expires.Equal(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("a token with an expiry: %+v", o)
	}
	if o := providers.Check(ctx, client(t, f, "another-token-of-the-test-0123", "")); o.OK || o.Err != nil || o.Reason == "" {
		t.Fatalf("a token the provider does not know: %+v", o)
	}
	f.Fail(cftest.Fault{Status: 403})
	if o := providers.Check(ctx, client(t, f, token, "")); o.OK || o.Err != nil {
		t.Fatalf("a 403: %+v", o)
	}
	for _, status := range []string{"expired", "disabled"} {
		f.SetTokenStatus(status, "")
		o := providers.Check(ctx, client(t, f, token, ""))
		if o.OK || o.Err != nil || !strings.Contains(o.Reason, "not active") {
			t.Fatalf("a %s token: %+v", status, o)
		}
	}
	f.SetTokenStatus("active", "")
	f.Fail(cftest.Fault{Status: 429, RetryAfter: "30"}, cftest.Fault{Status: 500})
	for _, what := range []string{"429", "500"} {
		if o := providers.Check(ctx, client(t, f, token, "")); o.OK || o.Err == nil || o.Reason != "" {
			t.Fatalf("a %s gives a verdict: %+v", what, o)
		}
	}
	f.SetAccountToken(account)
	if o := providers.Check(ctx, client(t, f, token, account)); !o.OK {
		t.Fatalf("an account-owned token: %+v", o)
	}
	if o := providers.Check(ctx, client(t, f, token, "")); o.OK {
		t.Fatalf("an account-owned token checked as a user token: %+v", o)
	}
	if o := providers.Check(ctx, client(t, f, token, "not-an-account-id")); o.OK || o.Err != nil || o.Reason == "" {
		t.Fatalf("an account ID that is not one: %+v", o)
	}
}
