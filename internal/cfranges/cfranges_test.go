// SPDX-License-Identifier: Apache-2.0

package cfranges

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func body(v4, v6 []string) string {
	q := func(l []string) string {
		var quoted []string
		for _, s := range l {
			quoted = append(quoted, `"`+s+`"`)
		}
		return "[" + strings.Join(quoted, ",") + "]"
	}
	return fmt.Sprintf(`{"result":{"ipv4_cidrs":%s,"ipv6_cidrs":%s,"etag":"x"},"success":true,"errors":[],"messages":[]}`, q(v4), q(v6))
}

func list(t *testing.T, v4, v6 []string) Ranges {
	t.Helper()
	r, err := Parse([]byte(body(v4, v6)), now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFallbackIsUsable(t *testing.T) {
	f := Fallback()
	if len(f.IPv4) == 0 || len(f.IPv6) == 0 || f.At.IsZero() {
		t.Fatalf("fallback is incomplete: %+v", f)
	}
	if !f.Contains(netip.MustParseAddr("104.16.0.1")) || !f.Contains(netip.MustParseAddr("2606:4700::1")) {
		t.Fatal("fallback misses a Cloudflare address")
	}
	if !f.Contains(netip.MustParseAddr("::ffff:104.16.0.1")) {
		t.Fatal("an IPv4-mapped address is not its IPv4 address")
	}
	for _, a := range []string{"192.0.2.1", "10.0.0.1", "2001:db8::1", "127.0.0.1"} {
		if f.Contains(netip.MustParseAddr(a)) {
			t.Fatalf("fallback contains %s", a)
		}
	}
	if err := Accept(f, f); err != nil {
		t.Fatalf("the fallback does not accept itself: %v", err)
	}
}

func TestFromSettings(t *testing.T) {
	if got := FromSettings(&rpmgrv1.InstanceSettings{}); got.At != Fallback().At {
		t.Fatal("no stored list must give the fallback")
	}
	stored := list(t, []string{"192.0.2.0/24"}, []string{"2001:db8::/32"})
	got := FromSettings(&rpmgrv1.InstanceSettings{CloudflareIpRanges: stored.Proto()})
	if !got.Contains(netip.MustParseAddr("192.0.2.9")) || got.Contains(netip.MustParseAddr("104.16.0.1")) || !got.At.Equal(now) {
		t.Fatalf("stored list not used: %+v", got)
	}
	bad := &rpmgrv1.InstanceSettings{CloudflareIpRanges: &rpmgrv1.CloudflareIpRanges{Ipv4Cidrs: []string{"0.0.0.0/0"}}}
	if FromSettings(bad).At != Fallback().At {
		t.Fatal("an unreadable stored list must give the fallback")
	}
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string]string{
		"not json":         `<html>`,
		"no success":       `{"success":false,"result":{"ipv4_cidrs":["1.0.0.0/24"],"ipv6_cidrs":["2001:db8::/32"]}}`,
		"everything":       body([]string{"0.0.0.0/0"}, []string{"2001:db8::/32"}),
		"short v4":         body([]string{"1.0.0.0/7"}, []string{"2001:db8::/32"}),
		"everything v6":    body([]string{"1.0.0.0/24"}, []string{"::/0"}),
		"short v6":         body([]string{"1.0.0.0/24"}, []string{"2000::/15"}),
		"v6 in v4":         body([]string{"2001:db8::/32"}, []string{"2001:db8::/32"}),
		"v4 in v6":         body([]string{"1.0.0.0/24"}, []string{"1.0.0.0/24"}),
		"mapped":           body([]string{"1.0.0.0/24"}, []string{"::ffff:1.0.0.0/120"}),
		"not a prefix":     body([]string{"1.0.0.1"}, []string{"2001:db8::/32"}),
		"garbage":          body([]string{"cloudflare"}, []string{"2001:db8::/32"}),
		"too many entries": body(many(600), []string{"2001:db8::/32"}),
	} {
		if _, err := Parse([]byte(in), now); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want ErrRejected", name, err)
		}
	}
}

func many(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%d.%d.0.0/16", 20+i/256, i%256))
	}
	return out
}

func TestParseMasksAndSorts(t *testing.T) {
	r := list(t, []string{"192.0.2.77/24", "10.0.0.0/8", "192.0.2.0/24"}, []string{"2001:db8::1/32"})
	if got := fmt.Sprint(r.IPv4); got != "[10.0.0.0/8 192.0.2.0/24]" {
		t.Fatalf("IPv4 = %s", got)
	}
	if got := fmt.Sprint(r.IPv6); got != "[2001:db8::/32]" {
		t.Fatalf("IPv6 = %s", got)
	}
}

func TestAcceptBounds(t *testing.T) {
	cur := list(t, []string{"1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24", "4.0.0.0/24"}, []string{"2001:db8::/32", "2001:db9::/32"})
	if len(cur.Prefixes()) != 6 {
		t.Fatal("setup")
	}
	v6 := []string{"2001:db8::/32", "2001:db9::/32"}
	for name, c := range map[string]struct {
		next Ranges
		ok   bool
	}{
		"unchanged":           {list(t, []string{"1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24", "4.0.0.0/24"}, v6), true},
		"one added":           {list(t, []string{"1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24", "4.0.0.0/24", "5.0.0.0/24"}, v6), true},
		"exactly half gone":   {list(t, []string{"1.0.0.0/24"}, v6), true}, // 3 of 6 gone
		"more than half gone": {list(t, nil, v6), false},
		"half and one more":   {list(t, []string{"1.0.0.0/24"}, []string{"2001:db8::/32"}), false}, // 4 of 6 gone
		"all replaced":        {list(t, []string{"5.0.0.0/24", "6.0.0.0/24", "7.0.0.0/24", "8.0.0.0/24"}, []string{"2001:dba::/32", "2001:dbb::/32"}), false},
		"more than half new":  {list(t, []string{"1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24", "4.0.0.0/24", "5.0.0.0/24", "6.0.0.0/24", "7.0.0.0/24", "8.0.0.0/24", "9.0.0.0/24", "10.0.0.0/24", "11.0.0.0/24"}, v6), false},
		"no IPv6":             {Ranges{IPv4: cur.IPv4}, false},
		"no IPv4":             {Ranges{IPv6: cur.IPv6}, false},
		"empty":               {Ranges{}, false},
	} {
		err := Accept(cur, c.next)
		if c.ok && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !c.ok && !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want ErrRejected", name, err)
		}
	}
}

func serve(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s.URL
}

func TestFetch(t *testing.T) {
	ok := body([]string{"192.0.2.0/24"}, []string{"2001:db8::/32"})
	for name, c := range map[string]struct {
		h    http.HandlerFunc
		want error
	}{
		"success": {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(ok)) }, nil},
		"500":     {func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", 500) }, ErrFetch},
		"redirect": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
		}, ErrFetch},
		"too large": {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat(" ", MaxBody+1))) }, ErrFetch},
		"not json":  {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }, ErrRejected},
	} {
		got, err := Fetch(context.Background(), Client(nil), serve(t, c.h), now)
		if !errors.Is(err, c.want) || (c.want == nil && (err != nil || len(got.IPv4) != 1 || !got.At.Equal(now))) {
			t.Errorf("%s: %+v, %v; want %v", name, got, err, c.want)
		}
	}
}

func TestFetchOffline(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	url := s.URL
	s.Close() // nothing listens any more
	if _, err := Fetch(context.Background(), Client(nil), url, now); !errors.Is(err, ErrFetch) {
		t.Fatalf("err = %v, want ErrFetch", err)
	}
}

func TestFetchEndsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	url := serve(t, func(http.ResponseWriter, *http.Request) {})
	if _, err := Fetch(ctx, Client(nil), url, now); !errors.Is(err, ErrFetch) {
		t.Fatalf("err = %v, want ErrFetch", err)
	}
}
