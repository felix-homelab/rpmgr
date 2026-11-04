// SPDX-License-Identifier: Apache-2.0

package cloudflare

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/proxyenv"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

const testToken = "test-token-for-the-fake-api"

// setup starts the fake and returns it with a client that trusts its test CA.
func setup(t *testing.T, account string) (*cftest.Server, *Client) {
	t.Helper()
	fake := cftest.New(t, testToken)
	if account != "" {
		fake.SetAccountToken(account)
	}
	c, err := newClient(Config{Token: secret.New(testToken), AccountID: account}, fake.URL(),
		&http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: fake.RootCAs()}})
	if err != nil {
		t.Fatal(err)
	}
	return fake, c
}

func TestVerify_UserAndAccountTokens(t *testing.T) {
	ctx := context.Background()
	fake, user := setup(t, "")
	fake.SetTokenStatus("active", "2031-01-02T03:04:05Z")
	info, err := user.Verify(ctx)
	if err != nil || !info.Active() || info.ExpiresAt.Year() != 2031 {
		t.Fatalf("user token: %+v, %v", info, err)
	}
	if got := fake.Requests(); len(got) != 1 || got[0] != "GET /client/v4/user/tokens/verify" {
		t.Fatalf("requests %v", got)
	}

	fake, acct := setup(t, "acc/1")
	info, err = acct.Verify(ctx)
	if err != nil || !info.Active() || !info.ExpiresAt.IsZero() {
		t.Fatalf("account token: %+v, %v", info, err)
	}
	if got := fake.Requests(); got[0] != "GET /client/v4/accounts/acc%2F1/tokens/verify" {
		t.Fatalf("the account id is not escaped: %v", got)
	}

	// An account-owned token is not a user token, and the other way round.
	wrong, err := newClient(Config{Token: secret.New(testToken)}, fake.URL(),
		&http.Transport{TLSClientConfig: &tls.Config{RootCAs: fake.RootCAs()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Verify(ctx); !errors.Is(err, dns.ErrUnauthorized) {
		t.Fatalf("account token at the user endpoint: %v", err)
	}

	fake.SetTokenStatus("expired", "")
	if info, err := acct.Verify(ctx); err != nil || info.Active() || info.Status != "expired" {
		t.Fatalf("expired token: %+v, %v", info, err)
	}
}

func TestNew_NeedsAToken(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("a client without a token")
	}
}

func TestListZones_Paging(t *testing.T) {
	for _, tc := range []struct{ zones, pages int }{{0, 1}, {1, 1}, {50, 1}, {51, 2}, {101, 3}} {
		t.Run(fmt.Sprint(tc.zones), func(t *testing.T) {
			fake, c := setup(t, "")
			for i := range tc.zones {
				fake.AddZone(fmt.Sprintf("Z%d.example", i))
			}
			zs, err := c.ListZones(context.Background())
			if err != nil || len(zs) != tc.zones {
				t.Fatalf("%d zones, %v", len(zs), err)
			}
			if n := fake.Count("GET /client/v4/zones?"); n != tc.pages {
				t.Fatalf("%d requests, want %d", n, tc.pages)
			}
			if tc.zones > 0 && (zs[0].Name != "z0.example" || zs[0].Status != "active" || zs[0].Type != "full") {
				t.Fatalf("zone %+v", zs[0])
			}
		})
	}
}

func TestListRecords_Paging(t *testing.T) {
	for _, tc := range []struct{ records, pages int }{{0, 1}, {50, 1}, {51, 2}, {120, 3}} {
		t.Run(fmt.Sprint(tc.records), func(t *testing.T) {
			fake, c := setup(t, "")
			z, other := fake.AddZone("example.org"), fake.AddZone("other.org")
			fake.AddRecord(other.ID, cftest.Record{Type: "A", Name: "x.other.org", Content: "192.0.2.9"})
			for i := range tc.records {
				fake.AddRecord(z.ID, cftest.Record{Type: "A", Name: fmt.Sprintf("h%d.example.org", i),
					Content: "192.0.2.1", Proxied: i == 0, Comment: "rpmgr"})
			}
			rs, err := c.ListRecords(context.Background(), z.ID)
			if err != nil || len(rs) != tc.records {
				t.Fatalf("%d records, %v", len(rs), err)
			}
			if n := fake.Count("GET /client/v4/zones/" + z.ID + "/dns_records?"); n != tc.pages {
				t.Fatalf("%d requests, want %d", n, tc.pages)
			}
			if tc.records > 0 && (!rs[0].Proxied || rs[0].Comment != "rpmgr" || rs[0].Type != "A") {
				t.Fatalf("record %+v", rs[0])
			}
		})
	}
}

func TestListRecords_UnknownZone(t *testing.T) {
	_, c := setup(t, "")
	_, err := c.ListRecords(context.Background(), "nope")
	var pe *dns.ProviderError
	if !errors.Is(err, dns.ErrNotFound) || !errors.As(err, &pe) || pe.Status != 404 {
		t.Fatalf("%v", err)
	}
}

func TestApply_Batch(t *testing.T) {
	ctx := context.Background()
	fake, c := setup(t, "")
	z := fake.AddZone("example.org")
	keep := fake.AddRecord(z.ID, cftest.Record{Type: "A", Name: "keep.example.org", Content: "192.0.2.1"})
	gone := fake.AddRecord(z.ID, cftest.Record{Type: "A", Name: "gone.example.org", Content: "192.0.2.2"})
	err := c.Apply(ctx, z.ID, dns.Batch{
		Deletes: []string{gone.ID},
		Patches: []dns.Record{{ID: keep.ID, Type: "A", Name: "keep.example.org", Content: "192.0.2.3", TTL: 300, Comment: "rpmgr"}},
		Posts:   []dns.Record{{Type: "CNAME", Name: "www.example.org", Content: "keep.example.org", TTL: 1, Proxied: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := fake.Records(z.ID)
	if len(got) != 2 || got[0].Content != "192.0.2.3" || got[0].Comment != "rpmgr" || got[0].TTL != 300 ||
		got[1].Type != "CNAME" || !got[1].Proxied {
		t.Fatalf("records %+v", got)
	}
	if err := c.Apply(ctx, z.ID, dns.Batch{}); err != nil || fake.Count("POST") != 1 {
		t.Fatalf("an empty batch sent a request: %v", err)
	}
}

func TestApply_AllOrNothingAndErrors(t *testing.T) {
	ctx := context.Background()
	fake, c := setup(t, "")
	z := fake.AddZone("example.org")
	r := fake.AddRecord(z.ID, cftest.Record{Type: "A", Name: "a.example.org", Content: "192.0.2.1"})
	err := c.Apply(ctx, z.ID, dns.Batch{
		Deletes: []string{r.ID},
		Posts:   []dns.Record{{Type: "A", Name: "b.example.org", Content: "192.0.2.2"}, {Type: "A", Name: "c.example.org"}},
	})
	var pe *dns.ProviderError
	if !errors.As(err, &pe) || pe.Status != 400 || errors.Is(err, dns.ErrInvalid) || len(pe.Messages) != 1 {
		t.Fatalf("%v", err)
	}
	if got := fake.Records(z.ID); len(got) != 1 || got[0].ID != r.ID {
		t.Fatalf("a failed batch changed the zone: %+v", got)
	}
	if err := c.Apply(ctx, "nope", dns.Batch{Deletes: []string{"x"}}); !errors.Is(err, dns.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestApply_RefusedBeforeSending(t *testing.T) {
	post := func(comment string) dns.Batch {
		return dns.Batch{Posts: []dns.Record{{Type: "TXT", Name: "a.example.org", Content: "x", Comment: comment}}}
	}
	ops := func(n int) dns.Batch {
		b := dns.Batch{}
		for range n {
			b.Deletes = append(b.Deletes, "id")
		}
		return b
	}
	for _, tc := range []struct {
		name    string
		batch   dns.Batch
		refused bool
	}{
		{"comment of 100", post(strings.Repeat("a", 100)), false},
		{"comment of 100 multibyte characters", post(strings.Repeat("ä", 100)), false},
		{"comment of 101", post(strings.Repeat("a", 101)), true},
		{"comment of 101 multibyte characters", post(strings.Repeat("ä", 101)), true},
		{"comment with a line break", post("a\nb"), true},
		{"200 operations", ops(200), false},
		{"201 operations", ops(201), true},
		{"long comment in a patch", dns.Batch{Patches: []dns.Record{{ID: "i", Comment: strings.Repeat("a", 101)}}}, true},
		{"long comment in a put", dns.Batch{Puts: []dns.Record{{ID: "i", Comment: strings.Repeat("a", 101)}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, c := setup(t, "")
			z := fake.AddZone("example.org")
			err := c.Apply(context.Background(), z.ID, tc.batch)
			if tc.refused {
				if !errors.Is(err, dns.ErrInvalid) || len(fake.Requests()) != 0 {
					t.Fatalf("err %v, requests %v", err, fake.Requests())
				}
				return
			}
			// Sent: the fake answers (an unknown record is a 400), but it is no refusal.
			if errors.Is(err, dns.ErrInvalid) || len(fake.Requests()) != 1 {
				t.Fatalf("err %v, requests %v", err, fake.Requests())
			}
		})
	}
}

func TestErrors_Mapping(t *testing.T) {
	now := time.Date(2030, 5, 6, 7, 8, 9, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		fault  cftest.Fault
		is     error
		status int
		until  time.Time // for a 429
	}{
		{"401", cftest.Fault{Status: 401}, dns.ErrUnauthorized, 401, time.Time{}},
		{"403", cftest.Fault{Status: 403}, dns.ErrForbidden, 403, time.Time{}},
		{"404", cftest.Fault{Status: 404}, dns.ErrNotFound, 404, time.Time{}},
		{"429 with seconds", cftest.Fault{Status: 429, RetryAfter: "120"}, nil, 429, now.Add(2 * time.Minute)},
		{"429 with zero", cftest.Fault{Status: 429, RetryAfter: "0"}, nil, 429, now},
		{"429 with a date", cftest.Fault{Status: 429, RetryAfter: "Mon, 06 May 2030 08:00:00 GMT"}, nil, 429,
			time.Date(2030, 5, 6, 8, 0, 0, 0, time.UTC)},
		{"429 without Retry-After", cftest.Fault{Status: 429}, nil, 429, now.Add(5 * time.Minute)},
		{"429 with garbage", cftest.Fault{Status: 429, RetryAfter: "soon"}, nil, 429, now.Add(5 * time.Minute)},
		{"429 with a negative number", cftest.Fault{Status: 429, RetryAfter: "-5"}, nil, 429, now.Add(5 * time.Minute)},
		{"429 with an HTML body", cftest.Fault{Status: 429, Body: "<html>slow down</html>"}, nil, 429, now.Add(5 * time.Minute)},
		{"500", cftest.Fault{Status: 500}, nil, 500, time.Time{}},
		{"success false", cftest.Fault{Status: 200, Body: `{"success":false,"errors":[{"code":1,"message":"no"}],"result":null}`}, nil, 200, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, c := setup(t, "")
			c.now = func() time.Time { return now }
			fake.Fail(tc.fault)
			_, err := c.ListZones(context.Background())
			var pe *dns.ProviderError
			if !errors.As(err, &pe) || pe.Status != tc.status {
				t.Fatalf("%v", err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("%v is not %v", err, tc.is)
			}
			var rl dns.RateLimited
			if got := errors.As(err, &rl); got != (tc.status == 429) {
				t.Fatalf("RateLimited %v for %v", got, err)
			}
			if tc.status == 429 && !rl.Until.Equal(tc.until) {
				t.Fatalf("until %v, want %v", rl.Until, tc.until)
			}
			if tc.status != 429 && tc.is == nil && (errors.Is(err, dns.ErrUnauthorized) || errors.Is(err, dns.ErrForbidden) || errors.Is(err, dns.ErrNotFound)) {
				t.Fatalf("%v is typed", err)
			}
		})
	}
}

func TestErrors_MalformedResponses(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":             `{"success": tru`,
		"HTML":                 `<html></html>`,
		"result of wrong type": `{"success":true,"result":{"id":"x"},"result_info":{"total_pages":1}}`,
		"zone of wrong type":   `{"success":true,"result":[{"id":5}],"result_info":{"total_pages":1}}`,
		"no result":            `{"success":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			fake, c := setup(t, "")
			fake.Fail(cftest.Fault{Status: 200, Body: body})
			zs, err := c.ListZones(context.Background())
			var pe *dns.ProviderError
			if err == nil || zs != nil || errors.As(err, &pe) {
				t.Fatalf("%v, %v", zs, err)
			}
			if !strings.Contains(err.Error(), "malformed") {
				t.Fatalf("%v", err)
			}
		})
	}
	fake, c := setup(t, "")
	fake.Fail(cftest.Fault{Status: 200, Body: `{"success":true,"result":"x"}`})
	if _, err := c.Verify(context.Background()); err == nil {
		t.Fatal("a verify result of the wrong type")
	}
}

func TestErrors_Network(t *testing.T) {
	fake, c := setup(t, "")
	c.base = strings.Replace(fake.URL(), "127.0.0.1", "127.0.0.1:1", 1) // not listening
	_, err := c.ListZones(context.Background())
	if err == nil {
		t.Fatal("no error")
	}
	var pe *dns.ProviderError
	if errors.As(err, &pe) {
		t.Fatalf("a network failure is no provider answer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, c2 := setup(t, "")
	if _, err := c2.ListZones(ctx); !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("%v", err)
	}
}

func TestClient_UntrustedCertificateIsRefused(t *testing.T) {
	fake := cftest.New(t, testToken)
	c, err := newClient(Config{Token: secret.New(testToken)}, fake.URL(), nil) // system roots, not the test CA
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(context.Background()); err == nil || len(fake.Requests()) != 0 {
		t.Fatalf("a server of an unknown CA was accepted: %v", err)
	}
}

func TestClient_RedirectIsNotFollowed(t *testing.T) {
	fake, c := setup(t, "")
	fake.Fail(cftest.Fault{Status: 307, Body: "{}"})
	if _, err := c.ListZones(context.Background()); err == nil || fake.Count("GET") != 1 {
		t.Fatalf("%v, %v", err, fake.Requests())
	}
}

// secrets lists every way a value gets formatted.
func TestToken_NeverInErrorsOrFormattedValues(t *testing.T) {
	fake, c := setup(t, "")
	ctx := context.Background()
	var texts []string
	// The provider echoes the token in its messages, the worst case.
	for _, f := range []cftest.Fault{
		{Status: 401, Body: `{"success":false,"errors":[{"code":1,"message":"bad token ` + testToken + `"}]}`},
		{Status: 200, Body: `{"success":true,"result":"` + testToken + `"}`},
		{Status: 200, Body: `{"success":true,"result":[{"id":"` + testToken + `"}`},
	} {
		fake.Fail(f)
		_, err := c.ListZones(ctx)
		texts = append(texts, fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err))
	}
	c.base = "https://127.0.0.1:1/" + "client/v4"
	_, err := c.Verify(ctx)
	texts = append(texts, fmt.Sprint(err))
	cfg := Config{Token: secret.New(testToken), AccountID: "acc"}
	for _, v := range []any{c, *c, cfg, &cfg, c.token} {
		texts = append(texts, fmt.Sprint(v), fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v),
			fmt.Sprintf("%s", v), fmt.Sprintf("%q", v), fmt.Sprintf("%x", v))
	}
	for _, s := range texts {
		if strings.Contains(s, testToken) {
			t.Fatalf("the token is in %q", s)
		}
	}
	if len(texts) < 10 || !strings.Contains(texts[0], "[redacted]") {
		t.Fatalf("redaction did not run: %q", texts[0])
	}
}

func TestRequests_CarryTheTokenAsBearer(t *testing.T) {
	fake, c := setup(t, "")
	fake.AddZone("example.org")
	if _, err := c.ListZones(context.Background()); err != nil {
		t.Fatal(err) // the fake answers 401 to any other Authorization header
	}
}

func TestTransport_TLSAndProxy(t *testing.T) {
	c, err := New(Config{Token: secret.New(testToken)})
	if err != nil {
		t.Fatal(err)
	}
	tr := c.hc.Transport.(*http.Transport)
	if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 || tr.TLSClientConfig.RootCAs != nil {
		t.Fatalf("TLS settings %+v", tr.TLSClientConfig)
	}
	if reflect.ValueOf(tr.Proxy).Pointer() != reflect.ValueOf(proxyenv.FromEnvironment).Pointer() {
		t.Fatal("the client does not follow the proxy variables of proxyenv")
	}
}

// TestDNS_TokenWriteOnlyAndBaseURLFixed_BaseURL is the base-URL clause of
// TestDNS_TokenWriteOnlyAndBaseURLFixed (docs/12): a production client cannot be pointed at any
// other server. The token clause belongs to slice 6.4, which is why the registry entry is not done.
func TestDNS_TokenWriteOnlyAndBaseURLFixed_BaseURL(t *testing.T) {
	// The URL is a compiled-in constant.
	if BaseURL != "https://api.cloudflare.com/client/v4" {
		t.Fatalf("BaseURL %q", BaseURL)
	}
	// Neither the settings of a client nor the environment name another one.
	for _, k := range []string{"CLOUDFLARE_API_URL", "CLOUDFLARE_BASE_URL", "CF_API_URL", "CF_API_BASE_URL", "RPMGR_CLOUDFLARE_URL", "RPMGR_DNS_BASE_URL"} {
		t.Setenv(k, "https://evil.example/client/v4")
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(Config{}), reflect.TypeOf(Client{})} {
		for f := range typ.Fields() {
			if f.IsExported() && strings.Contains(strings.ToLower(f.Name), "url") {
				t.Fatalf("%s has the setting %s", typ.Name(), f.Name)
			}
		}
	}
	// A request of the production client goes to api.cloudflare.com, whatever else is set; its
	// transport is replaced by one that records and refuses to connect.
	c, err := New(Config{Token: secret.New(testToken), AccountID: "acc"})
	if err != nil {
		t.Fatal(err)
	}
	var urls []string
	c.hc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		urls = append(urls, r.URL.String())
		return nil, errors.New("offline")
	})
	ctx := context.Background()
	_, _ = c.Verify(ctx)
	_, _ = c.ListZones(ctx)
	_, _ = c.ListRecords(ctx, "z")
	_ = c.Apply(ctx, "z", dns.Batch{Deletes: []string{"i"}})
	if len(urls) != 4 {
		t.Fatalf("%v", urls)
	}
	for _, u := range urls {
		if !strings.HasPrefix(u, "https://api.cloudflare.com/client/v4/") {
			t.Fatalf("request to %s", u)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
