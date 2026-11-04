// SPDX-License-Identifier: Apache-2.0

//go:build rpmgrtest

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/cftest"
	"github.com/felix-homelab/rpmgr/internal/dns/cloudflare"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

const (
	userToken  = "user-token-for-the-fake"
	otherToken = "under-scoped-token-for-the-fake"
)

type fixture struct {
	fake *cftest.Server
	zone cftest.Zone
	env  env
	pre  []cftest.Record // records that exist before the probe
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	fake := cftest.New(t, userToken)
	z := fake.AddZone("probe.example")
	f := &fixture{fake: fake, zone: z}
	f.pre = []cftest.Record{
		fake.AddRecord(z.ID, cftest.Record{Type: "A", Name: "www.probe.example", Content: "192.0.2.10", TTL: 300, Proxied: true, Comment: "someone else"}),
		fake.AddRecord(z.ID, cftest.Record{Type: "TXT", Name: "_dmarc.probe.example", Content: "v=DMARC1; p=none"}),
	}
	f.env = env{
		newProvider: func(tok secret.Value, account string) (dns.Provider, error) {
			return cloudflare.NewForTest(cloudflare.Config{Token: tok, AccountID: account}, fake.URL(), fake.RootCAs())
		},
		raw:   newRaw(fake.URL(), &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: fake.RootCAs()}}),
		sleep: func(context.Context, time.Duration) {},
		now:   time.Now,
	}
	return f
}

func (f *fixture) cfg() config {
	return config{zone: "probe.example", token: secret.New(userToken), underScoped: secret.New(otherToken)}
}

// unchanged fails the test unless the zone holds exactly the records it held before the probe.
func (f *fixture) unchanged(t *testing.T) {
	t.Helper()
	got := f.fake.Records(f.zone.ID)
	if len(got) != len(f.pre) {
		t.Fatalf("the zone holds %d records after the probe, %d before: %+v", len(got), len(f.pre), got)
	}
	for i := range got {
		if got[i] != f.pre[i] {
			t.Fatalf("record %d changed: %+v, was %+v", i, got[i], f.pre[i])
		}
	}
}

func runProbe(t *testing.T, f *fixture, cfg config) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(context.Background(), cfg, f.env, &report{w: &out})
	for _, tok := range []string{userToken, otherToken} {
		if strings.Contains(out.String(), tok) {
			t.Fatalf("the output holds a token:\n%s", out.String())
		}
	}
	return code, out.String()
}

func wantLines(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("the output lacks %q:\n%s", w, out)
		}
	}
}

// The dry run: every check passes against the fake, and the zone is as it was.
func TestProbeAgainstFake(t *testing.T) {
	f := newFixture(t)
	code, out := runProbe(t, f, f.cfg())
	if code != 0 || strings.Contains(out, "FAIL ") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	wantLines(t, out,
		"PASS VB-12 zone probe.example has status active and type full",
		"PASS VB-12 under-scoped token cannot write the zone",
		"PASS VB-10 the marker (51 characters) round-trips unchanged",
		"PASS VB-10 a batch patch changes the comment alone",
		"PASS VB-10 a record without a marker is untouched",
		"PASS VB-10 a comment of 100 characters round-trips",
		"PASS VB-10 a failed batch changes nothing",
		"PASS VB-10 the 2 pre-existing record(s) of the zone are unchanged",
		"PASS VB-11 CNAME with proxied=true",
		"PASS VB-11 CNAME with proxied=false",
		"INFO VB-11 apex CNAME not probed",
		"INFO VB-09 rate-limit burst not run",
		"PASS VB-26 all ",
		"INFO CLEANUP deleted ",
		"leftover-records=0")
	f.unchanged(t)
}

func TestProbeApexCNAME(t *testing.T) {
	f := newFixture(t)
	cfg := f.cfg()
	cfg.apexCNAME = true
	code, out := runProbe(t, f, cfg)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	wantLines(t, out, "PASS VB-11 a CNAME at the zone apex is accepted")
	f.unchanged(t)
}

// An apex that has records is never touched: a CNAME could not share its name anyway.
func TestProbeApexWithRecordsIsSkipped(t *testing.T) {
	f := newFixture(t)
	f.pre = append(f.pre, f.fake.AddRecord(f.zone.ID, cftest.Record{Type: "TXT", Name: "probe.example", Content: "v=spf1 -all"}))
	cfg := f.cfg()
	cfg.apexCNAME = true
	code, out := runProbe(t, f, cfg)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	wantLines(t, out, "INFO VB-11 apex CNAME not probed: the apex already has records")
	f.unchanged(t)
}

// A token that is not under-scoped fails the run, and the record it wrote is removed.
func TestProbeUnderScopedTokenThatWrites(t *testing.T) {
	f := newFixture(t)
	cfg := f.cfg()
	cfg.underScoped = cfg.token
	code, out := runProbe(t, f, cfg)
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	wantLines(t, out, "FAIL VB-12 the under-scoped token WROTE a record")
	f.unchanged(t)
}

func TestProbeBadTokenStopsEarly(t *testing.T) {
	f := newFixture(t)
	cfg := f.cfg()
	cfg.token = secret.New("a-token-the-fake-refuses")
	code, out := runProbe(t, f, cfg)
	if code != 1 || !strings.Contains(out, "FAIL VB-12 token verify failed") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Contains(out, "VB-10 ") {
		t.Fatalf("the probe went on after the token failed:\n%s", out)
	}
	f.unchanged(t)
}

func TestProbeZoneNotVisible(t *testing.T) {
	f := newFixture(t)
	cfg := f.cfg()
	cfg.zone = "other.example"
	code, out := runProbe(t, f, cfg)
	if code != 1 || !strings.Contains(out, "FAIL VB-12 zone other.example is not among the zones") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	f.unchanged(t)
}

func TestProbeRefusesZoneThatIsNotActiveFull(t *testing.T) {
	// The fake has only active/full zones; a provider wrapper reports a partial one.
	f := newFixture(t)
	inner := f.env.newProvider
	f.env.newProvider = func(tok secret.Value, account string) (dns.Provider, error) {
		p, err := inner(tok, account)
		return partialZones{p}, err
	}
	code, out := runProbe(t, f, f.cfg())
	if code != 1 || !strings.Contains(out, `has status "pending" and type "partial"`) {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Contains(out, "VB-10 ") {
		t.Fatalf("the probe wrote to a zone that is not active/full:\n%s", out)
	}
	f.unchanged(t)
}

type partialZones struct{ dns.Provider }

func (p partialZones) ListZones(ctx context.Context) ([]dns.Zone, error) {
	zs, err := p.Provider.ListZones(ctx)
	for i := range zs {
		zs[i].Status, zs[i].Type = "pending", "partial"
	}
	return zs, err
}

// failing wraps a provider and fails writes on demand.
type failing struct {
	dns.Provider
	applies   int
	failAt    int  // the Apply call that fails and cancels the context; 0: none
	noDeletes bool // every batch that deletes fails
	cancel    context.CancelFunc
}

func (f *failing) Apply(ctx context.Context, zone string, b dns.Batch) error {
	f.applies++
	if f.applies == f.failAt {
		f.cancel()
		return errors.New("injected failure")
	}
	if f.noDeletes && len(b.Deletes) > 0 {
		return &dns.ProviderError{Status: 500, Messages: []string{"injected"}}
	}
	return f.Provider.Apply(ctx, zone, b)
}

// A failure and a cancelled context in the middle of the run still end with the zone as it was.
func TestProbeCleansUpAfterFailure(t *testing.T) {
	for _, at := range []int{2, 4, 7} {
		f := newFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		inner := f.env.newProvider
		f.env.newProvider = func(tok secret.Value, account string) (dns.Provider, error) {
			p, err := inner(tok, account)
			if tok.EqualString(userToken) {
				return &failing{Provider: p, failAt: at, cancel: cancel}, err
			}
			return p, err
		}
		var out bytes.Buffer
		run(ctx, f.cfg(), f.env, &report{w: &out})
		cancel()
		f.unchanged(t)
		if strings.Contains(out.String(), "LEFTOVER") {
			t.Fatalf("at %d: %s", at, out.String())
		}
	}
}

// What cannot be deleted is reported, with its ID, and the exit status is not 0.
func TestProbeReportsLeftovers(t *testing.T) {
	f := newFixture(t)
	inner := f.env.newProvider
	f.env.newProvider = func(tok secret.Value, account string) (dns.Provider, error) {
		p, err := inner(tok, account)
		return &failing{Provider: p, noDeletes: true}, err
	}
	code, out := runProbe(t, f, f.cfg())
	if code != 1 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	wantLines(t, out, "FAIL CLEANUP LEFTOVER TXT owned._rpmgr-probe-", "left behind")
	if !strings.Contains(out, "(record ") {
		t.Fatalf("no record ID in the leftover lines:\n%s", out)
	}
}

func TestProbeRateLimitedCleanupWaits(t *testing.T) {
	f := newFixture(t)
	var slept []time.Duration
	f.env.sleep = func(_ context.Context, d time.Duration) { slept = append(slept, d) }
	inner := f.env.newProvider
	n := 0
	f.env.newProvider = func(tok secret.Value, account string) (dns.Provider, error) {
		p, err := inner(tok, account)
		return &rateLimitOnce{Provider: p, n: &n}, err
	}
	code, out := runProbe(t, f, f.cfg())
	if code != 0 || len(slept) == 0 {
		t.Fatalf("exit %d, slept %v:\n%s", code, slept, out)
	}
	f.unchanged(t)
}

// rateLimitOnce answers the first delete with a 429 that blocks for a minute.
type rateLimitOnce struct {
	dns.Provider
	n *int
}

func (r *rateLimitOnce) Apply(ctx context.Context, zone string, b dns.Batch) error {
	if len(b.Deletes) > 0 && *r.n == 0 {
		*r.n++
		return &dns.ProviderError{Status: 429, Err: dns.RateLimited{Until: time.Now().Add(time.Minute)}}
	}
	return r.Provider.Apply(ctx, zone, b)
}

func burstProbe(t *testing.T, f *fixture) (*probe, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	cfg := f.cfg()
	p := &probe{cfg: cfg, env: f.env, rep: &report{w: &out}, zone: dns.Zone{ID: f.zone.ID, Name: f.zone.Name},
		created: map[string]bool{}}
	var err error
	if p.prov, err = f.env.newProvider(cfg.token, ""); err != nil {
		t.Fatal(err)
	}
	return p, &out
}

func TestRateLimitShapes(t *testing.T) {
	date := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	for _, c := range []struct{ retryAfter, want string }{
		{"7", "PASS VB-09 Retry-After is delta-seconds: 7"},
		{date, "PASS VB-09 Retry-After is an HTTP date"},
		{"", "INFO VB-09 the 429 has no Retry-After header"},
		{"soon", `INFO VB-09 Retry-After has an unreadable shape: "soon"`},
	} {
		f := newFixture(t)
		p, out := burstProbe(t, f)
		// One answer for the burst, one for the client's own request that follows.
		f.fake.Fail(cftest.Fault{Status: 429, RetryAfter: c.retryAfter}, cftest.Fault{Status: 429, RetryAfter: c.retryAfter})
		p.checkRateLimit(context.Background(), 5)
		wantLines(t, out.String(), "PASS VB-09 HTTP 429 after 1 requests", c.want,
			"PASS VB-09 the client maps the 429 to dns.RateLimited",
			"under-scoped token answers HTTP 401", "NOW open the Cloudflare dashboard")
		if p.rep.fails != 0 {
			t.Errorf("%q: %d FAIL lines:\n%s", c.retryAfter, p.rep.fails, out)
		}
	}
}

// The burst is bounded: without a 429 it stops after the requests it was allowed.
func TestRateLimitBurstIsBounded(t *testing.T) {
	f := newFixture(t)
	p, out := burstProbe(t, f)
	p.checkRateLimit(context.Background(), 4)
	wantLines(t, out.String(), "INFO VB-09 no 429 after 4 requests")
	if n := f.fake.Count("GET /client/v4/zones/" + f.zone.ID + "/dns_records"); n != 4 {
		t.Fatalf("%d requests sent, want 4", n)
	}
}

func TestRateLimitBurstStopsOnOtherErrors(t *testing.T) {
	f := newFixture(t)
	p, out := burstProbe(t, f)
	f.fake.Fail(cftest.Fault{Status: 500})
	p.checkRateLimit(context.Background(), 10)
	wantLines(t, out.String(), "FAIL VB-09 request 1 answered HTTP 500")
	if n := f.fake.Count("GET /client/v4/zones/" + f.zone.ID + "/dns_records"); n != 1 {
		t.Fatalf("%d requests sent after a 500, want 1", n)
	}
}

func TestProbeBurstThroughRun(t *testing.T) {
	f := newFixture(t)
	cfg := f.cfg()
	cfg.burst = 3
	code, out := runProbe(t, f, cfg)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	wantLines(t, out, "INFO VB-09 no 429 after 3 requests")
	f.unchanged(t)
}
