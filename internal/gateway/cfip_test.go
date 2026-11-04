// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"fmt"
	"net/http"
	"net/netip"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/gateway"
)

// cfEcho answers with what the upstream of a route is told of the client: X-Forwarded-For,
// CF-Connecting-IP and Forwarded.
var cfEcho = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Fprintf(w, "xff=%s|cf=%s|fwd=%s", r.Header.Get("X-Forwarded-For"), r.Header.Get("Cf-Connecting-Ip"), r.Header.Get("Forwarded"))
})

// TestGateway_CFConnectingIPOnlyForProxiedFromCloudflare (docs/12-testing-and-quality.md, "Security
// testing", D168): CF-Connecting-IP sets the client address only on a dns_proxied route and only
// from a TCP peer in the Cloudflare ranges of the snapshot. From any other peer, or on another
// route, it is ignored and the IP rules see the TCP peer; a header that is missing, repeated or no
// address leaves the Cloudflare peer as the client; X-Forwarded-For and Forwarded from a Cloudflare
// peer are never read, a trusted proxy among them; a peer outside the ranges follows the trusted
// proxy rule. The test peer is 127.0.0.1; "Cloudflare" is a range that holds it, "elsewhere" one
// that does not.
func TestGateway_CFConnectingIPOnlyForProxiedFromCloudflare(t *testing.T) {
	cloudflare := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("2606:4700::/32")}
	elsewhere := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2606:4700::/32")}
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	const cf = "Cf-Connecting-Ip"
	for _, tc := range []struct {
		name    string
		proxied bool
		ranges  []netip.Prefix
		trusted []netip.Prefix
		allow   string // the only clients the route admits
		header  http.Header
		want    int
		body    string // what the upstream sees, if admitted
	}{
		{"a Cloudflare peer names the client", true, cloudflare, nil, "203.0.113.0/24",
			http.Header{cf: {"203.0.113.7"}}, 200, "xff=203.0.113.7|cf=203.0.113.7|fwd=for=203.0.113.7;host=\"app.example.com\";proto=https"},
		{"the client may be IPv6", true, cloudflare, nil, "2001:db8::/32",
			http.Header{cf: {"2001:db8::1"}}, 200, "xff=2001:db8::1|cf=2001:db8::1|fwd=for=\"[2001:db8::1]\";host=\"app.example.com\";proto=https"},
		{"an IPv4-mapped client is its IPv4 address", true, cloudflare, nil, "203.0.113.0/24",
			http.Header{cf: {"::ffff:203.0.113.7"}}, 200, "xff=203.0.113.7|cf=203.0.113.7|fwd=for=203.0.113.7;host=\"app.example.com\";proto=https"},
		{"a client outside the rules is refused", true, cloudflare, nil, "203.0.113.0/24",
			http.Header{cf: {"198.51.100.1"}}, 403, ""},
		{"a spoofed header from a peer outside the ranges", true, elsewhere, nil, "203.0.113.0/24",
			http.Header{cf: {"203.0.113.7"}}, 403, ""},
		{"the peer outside the ranges is judged by its own address", true, elsewhere, nil, "127.0.0.0/8",
			http.Header{cf: {"203.0.113.7"}}, 200, "xff=127.0.0.1|cf=|fwd=for=127.0.0.1;host=\"app.example.com\";proto=https"},
		{"a route that is not proxied ignores the header", false, cloudflare, nil, "203.0.113.0/24",
			http.Header{cf: {"203.0.113.7"}}, 403, ""},
		{"a route that is not proxied sends none upstream", false, cloudflare, nil, "127.0.0.0/8",
			http.Header{cf: {"203.0.113.7"}}, 200, "xff=127.0.0.1|cf=203.0.113.7|fwd=for=127.0.0.1;host=\"app.example.com\";proto=https"},
		{"X-Forwarded-For from Cloudflare names no one", true, cloudflare, nil, "203.0.113.0/24",
			http.Header{"X-Forwarded-For": {"203.0.113.7"}}, 403, ""},
		{"X-Forwarded-For from Cloudflare does not outweigh the header", true, cloudflare, nil, "203.0.113.0/24",
			http.Header{"X-Forwarded-For": {"203.0.113.7"}, cf: {"198.51.100.1"}}, 403, ""},
		{"Forwarded from Cloudflare names no one", true, cloudflare, nil, "203.0.113.0/24",
			http.Header{"Forwarded": {"for=203.0.113.7"}}, 403, ""},
		{"X-Forwarded-For from Cloudflare is not extended upstream", true, cloudflare, trusted, "203.0.113.0/24",
			http.Header{"X-Forwarded-For": {"203.0.113.7"}, "X-Forwarded-Proto": {"http"}, "X-Forwarded-Host": {"evil.example"},
				cf: {"203.0.113.7"}}, 200, "xff=203.0.113.7|cf=203.0.113.7|fwd=for=203.0.113.7;host=\"app.example.com\";proto=https"},
		{"a Cloudflare peer that is also a trusted proxy is no trusted proxy", true, cloudflare, trusted, "203.0.113.0/24",
			http.Header{"X-Forwarded-For": {"203.0.113.7"}}, 403, ""},
		{"a peer outside the ranges follows the trusted-proxy rule", true, elsewhere, trusted, "203.0.113.0/24",
			http.Header{"X-Forwarded-For": {"203.0.113.7"}, cf: {"198.51.100.1"}}, 200,
			"xff=203.0.113.7, 127.0.0.1|cf=|fwd=for=127.0.0.1;host=\"app.example.com\";proto=https"},
		{"no header leaves the Cloudflare peer as the client", true, cloudflare, nil, "203.0.113.0/24", nil, 403, ""},
		{"no header: the Cloudflare peer is judged by its address", true, cloudflare, nil, "127.0.0.0/8", nil, 200,
			"xff=127.0.0.1|cf=|fwd=for=127.0.0.1;host=\"app.example.com\";proto=https"},
		{"a header that is no address", true, cloudflare, nil, "203.0.113.0/24", http.Header{cf: {"not an address"}}, 403, ""},
		{"an empty header", true, cloudflare, nil, "203.0.113.0/24", http.Header{cf: {""}}, 403, ""},
		{"an address with a zone", true, cloudflare, nil, "fe80::/10", http.Header{cf: {"fe80::1%eth0"}}, 403, ""},
		{"an address with a port", true, cloudflare, nil, "203.0.113.0/24", http.Header{cf: {"203.0.113.7:443"}}, 403, ""},
		{"the unspecified address", true, cloudflare, nil, "0.0.0.0/0", http.Header{cf: {"0.0.0.0"}}, 200,
			"xff=127.0.0.1|cf=|fwd=for=127.0.0.1;host=\"app.example.com\";proto=https"},
		{"a list of addresses", true, cloudflare, nil, "203.0.113.0/24", http.Header{cf: {"203.0.113.7, 198.51.100.1"}}, 403, ""},
		{"the header twice", true, cloudflare, nil, "203.0.113.0/24", http.Header{cf: {"203.0.113.7", "203.0.113.7"}}, 403, ""},
		{"a proxied route without ranges", true, nil, nil, "203.0.113.0/24", http.Header{cf: {"203.0.113.7"}}, 403, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
				DNSProxied: tc.proxied, CloudflareRanges: tc.ranges, TrustedProxies: tc.trusted, Access: access(t, allow(tc.allow))}
			e := newHTTPEnv(t, cfEcho, route)
			r := get(t, e.client(false), "https://app.example.com/", tc.header)
			if r.status != tc.want || (tc.want == 200 && r.body != tc.body) {
				t.Errorf("%d %q, want %d %q", r.status, r.body, tc.want, tc.body)
			}
		})
	}
}

// TestGateway_CFConnectingIPSnapshotReplacesRanges: a new snapshot's ranges replace the old ones at
// once, so a range Cloudflare adds is believed from the next snapshot and one it drops is not.
func TestGateway_CFConnectingIPSnapshotReplacesRanges(t *testing.T) {
	route := gateway.HTTPRoute{ID: "rt_web", Upstream: "http", Hosts: []gateway.HTTPHost{{Hostname: "app.example.com"}},
		DNSProxied: true, CloudflareRanges: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, Access: access(t, allow("203.0.113.0/24"))}
	e := newHTTPEnv(t, cfEcho, route)
	header := http.Header{"Cf-Connecting-Ip": {"203.0.113.7"}}
	if r := get(t, e.client(false), "https://app.example.com/", header); r.status != http.StatusForbidden {
		t.Fatalf("before the range is known: %d", r.status)
	}
	route.CloudflareRanges = append(route.CloudflareRanges, netip.MustParsePrefix("127.0.0.0/8"))
	e.routes.Apply([]gateway.HTTPRoute{route})
	if r := get(t, e.client(false), "https://app.example.com/", header); r.status != http.StatusOK {
		t.Fatalf("after the range is added: %d", r.status)
	}
	route.CloudflareRanges = route.CloudflareRanges[:1]
	e.routes.Apply([]gateway.HTTPRoute{route})
	if r := get(t, e.client(false), "https://app.example.com/", header); r.status != http.StatusForbidden {
		t.Fatalf("after the range is dropped: %d", r.status)
	}
}
