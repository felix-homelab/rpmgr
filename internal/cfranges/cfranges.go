// SPDX-License-Identifier: Apache-2.0

// Package cfranges holds Cloudflare's published address ranges, which the gateway uses to decide
// whether a TCP peer is Cloudflare on a proxied route, and the rules by which the controller
// accepts a refreshed list (docs/15-dns.md, "Proxied HTTP routes" and "Timers and limits").
package cfranges

import (
	"context"
	_ "embed" // the fallback list
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	neturl "net/url"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// URL is where Cloudflare publishes its ranges.
const URL = "https://api.cloudflare.com/client/v4/ips"

// The limits of the refresh (docs/15-dns.md, "Timers and limits").
const (
	RefreshEvery = 24 * time.Hour // the age at which the list is fetched again
	RetryEvery   = time.Hour      // how often a failed or rejected refresh is tried again
	StaleAfter   = 72 * time.Hour // the age at which the stale alert fires, with a proxied route
	FetchTimeout = 10 * time.Second
	MaxBody      = 64 << 10 // bytes of the response read; more fails the fetch
	maxEntries   = 512
	minBits4     = 8  // the shortest IPv4 prefix a list may hold
	minBits6     = 16 // the shortest IPv6 prefix a list may hold
)

// Errors of a fetched list; each says why it was not taken.
var (
	ErrRejected = errors.New("cfranges: list rejected")
	ErrFetch    = errors.New("cfranges: fetch failed")
)

//go:embed fallback.json
var fallbackJSON []byte

// Ranges are the address ranges of Cloudflare's network at a time.
type Ranges struct {
	IPv4, IPv6 []netip.Prefix
	At         time.Time // when the list was taken from Cloudflare
}

// Fallback is the list built into the binary, used until a refresh succeeds and by installations
// without egress. Its At is the date it was retrieved.
func Fallback() Ranges {
	var f struct {
		Retrieved string   `json:"retrieved"`
		V4        []string `json:"ipv4_cidrs"`
		V6        []string `json:"ipv6_cidrs"`
	}
	if err := json.Unmarshal(fallbackJSON, &f); err != nil {
		panic("cfranges: fallback.json: " + err.Error()) // the embedded file is tested
	}
	at, err := time.Parse(time.DateOnly, f.Retrieved)
	if err != nil {
		panic("cfranges: fallback.json: " + err.Error())
	}
	r, err := build(f.V4, f.V6)
	if err != nil {
		panic("cfranges: fallback.json: " + err.Error())
	}
	r.At = at
	return r
}

// FromSettings returns the list of the instance settings: the one the last accepted refresh
// stored, or Fallback while none was stored or the stored one does not read.
func FromSettings(inst *rpmgrv1.InstanceSettings) Ranges {
	s := inst.GetCloudflareIpRanges()
	if s == nil || (len(s.GetIpv4Cidrs()) == 0 && len(s.GetIpv6Cidrs()) == 0) {
		return Fallback()
	}
	r, err := build(s.GetIpv4Cidrs(), s.GetIpv6Cidrs())
	if err != nil {
		return Fallback()
	}
	if s.GetRefreshedAt() != nil {
		r.At = s.GetRefreshedAt().AsTime()
	}
	return r
}

// Proto is the list as the instance setting stores it.
func (r Ranges) Proto() *rpmgrv1.CloudflareIpRanges {
	out := &rpmgrv1.CloudflareIpRanges{RefreshedAt: timestamppb.New(r.At)}
	for _, p := range r.IPv4 {
		out.Ipv4Cidrs = append(out.Ipv4Cidrs, p.String())
	}
	for _, p := range r.IPv6 {
		out.Ipv6Cidrs = append(out.Ipv6Cidrs, p.String())
	}
	return out
}

// Prefixes returns every range, IPv4 first.
func (r Ranges) Prefixes() []netip.Prefix { return append(slices.Clone(r.IPv4), r.IPv6...) }

// Contains reports whether a lies in one of the ranges; an IPv4-mapped IPv6 address counts as its
// IPv4 address.
func (r Ranges) Contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range r.Prefixes() {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Age is how long ago the list was taken from Cloudflare at now.
func (r Ranges) Age(now time.Time) time.Duration { return max(0, now.Sub(r.At)) }

func build(v4, v6 []string) (Ranges, error) {
	var r Ranges
	var err error
	if r.IPv4, err = prefixes(v4, true); err != nil {
		return Ranges{}, err
	}
	if r.IPv6, err = prefixes(v6, false); err != nil {
		return Ranges{}, err
	}
	return r, nil
}

// prefixes parses CIDR strings of one family, sorted and without duplicates. A prefix of the
// other family, or shorter than the least a Cloudflare range is, fails: a list must never make
// everything Cloudflare.
func prefixes(in []string, four bool) ([]netip.Prefix, error) {
	if len(in) > maxEntries {
		return nil, fmt.Errorf("%w: more than %d entries", ErrRejected, maxEntries)
	}
	shortest := minBits6
	if four {
		shortest = minBits4
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Is4() != four || p.Addr().Is4In6() || p.Bits() < shortest {
			return nil, fmt.Errorf("%w: %q is no usable range", ErrRejected, s)
		}
		out = append(out, p.Masked())
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return slices.Compact(out), nil
}

// Parse reads the response of Cloudflare's IP endpoint. Its ranges are validated but not yet
// compared with the current list: see Accept.
func Parse(body []byte, at time.Time) (Ranges, error) {
	var resp struct {
		Success bool `json:"success"`
		Result  struct {
			V4 []string `json:"ipv4_cidrs"`
			V6 []string `json:"ipv6_cidrs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return Ranges{}, fmt.Errorf("%w: not a Cloudflare response", ErrRejected)
	}
	if !resp.Success {
		return Ranges{}, fmt.Errorf("%w: Cloudflare reports no success", ErrRejected)
	}
	r, err := build(resp.Result.V4, resp.Result.V6)
	if err != nil {
		return Ranges{}, err
	}
	r.At = at
	return r, nil
}

// Accept applies the sanity bounds to a fetched list next to the current one: both families must
// be non-empty, and at most half of the current entries may be gone or at most half of the new
// entries may be new. A list outside them is a Cloudflare outage, a mistake or an attack on the
// fetch, and keeps the current one.
func Accept(current, next Ranges) error {
	if len(next.IPv4) == 0 || len(next.IPv6) == 0 {
		return fmt.Errorf("%w: a family has no range", ErrRejected)
	}
	old := current.Prefixes()
	fresh := next.Prefixes()
	gone, added := 0, 0
	for _, p := range old {
		if !slices.Contains(fresh, p) {
			gone++
		}
	}
	for _, p := range fresh {
		if !slices.Contains(old, p) {
			added++
		}
	}
	if 2*gone > len(old) || 2*added > len(fresh) {
		return fmt.Errorf("%w: %d of %d entries gone and %d of %d new", ErrRejected, gone, len(old), added, len(fresh))
	}
	return nil
}

// Client returns the HTTP client of the refresh: proxy chooses the proxy of the request, nil is
// none; the timeout is FetchTimeout, and a redirect is not followed.
func Client(proxy func(*http.Request) (*neturl.URL, error)) *http.Client {
	return &http.Client{
		Timeout:       FetchTimeout,
		Transport:     &http.Transport{Proxy: proxy, TLSHandshakeTimeout: FetchTimeout},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Fetch reads the list from url with client; the response is read up to MaxBody. A failure to
// reach Cloudflare, a status other than 200 or a body too large is ErrFetch; a body that is no
// usable list is ErrRejected.
func Fetch(ctx context.Context, client *http.Client, url string, now time.Time) (Ranges, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Ranges{}, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Ranges{}, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Ranges{}, fmt.Errorf("%w: status %d", ErrFetch, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	switch {
	case err != nil:
		return Ranges{}, fmt.Errorf("%w: %w", ErrFetch, err)
	case len(body) > MaxBody:
		return Ranges{}, fmt.Errorf("%w: the response is larger than %d bytes", ErrFetch, MaxBody)
	}
	return Parse(body, now)
}
