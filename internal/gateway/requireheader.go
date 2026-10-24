// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// A RequireHeaderRule lets pass only requests that carry its header with one of its values
// (docs/03-connections.md, "Access policies"; docs/04-security.md, "Route edge rules"). The gateway
// holds only the values' SHA-256 and removes the header before the request goes upstream.
type RequireHeaderRule struct {
	// Name is the header's canonical name.
	Name string
	// Sums are the SHA-256 of the accepted values.
	Sums [][sha256.Size]byte
}

// NotRequirable reports why a request header cannot be required, or "": the gateway's own and the
// connection's headers; the credentials and cookies that basic auth and backends read; the trace
// context the gateway reads before it checks access, which would carry a required value into its
// spans and break the trace when removed; and the Rpmgr- headers the gateway sets.
func NotRequirable(name string) string {
	switch c := http.CanonicalHeaderKey(name); {
	case slices.Contains(ReservedHeaders, c):
		return "is the gateway's own"
	case c == "Authorization" || c == "Cookie":
		return "carries credentials of basic auth or the backend"
	case c == "Traceparent" || c == "Tracestate" || c == "Baggage":
		return "carries the trace context"
	case strings.HasPrefix(c, "Rpmgr-"):
		return "is an rpmgr header"
	}
	return ""
}

// requireHeaderOf parses a route's require_header rules: each names a valid header that may be
// required and has 1 to 4 hashes of SHA-256's size.
func requireHeaderOf(rules []*rpmgrv1.RequireHeaderParams) ([]RequireHeaderRule, error) {
	var out []RequireHeaderRule
	for i, r := range rules {
		if !httpguts.ValidHeaderFieldName(r.GetName()) {
			return nil, fmt.Errorf("rule %d: header name %q", i+1, r.GetName())
		}
		if why := NotRequirable(r.GetName()); why != "" {
			return nil, fmt.Errorf("rule %d: header %s %s", i+1, r.GetName(), why)
		}
		if n := len(r.GetValueSha256()); n < 1 || n > 4 {
			return nil, fmt.Errorf("rule %d: %d values, not 1 to 4", i+1, n)
		}
		rule := RequireHeaderRule{Name: http.CanonicalHeaderKey(r.GetName())}
		for _, s := range r.GetValueSha256() {
			if len(s) != sha256.Size {
				return nil, fmt.Errorf("rule %d: a value hash of %d bytes", i+1, len(s))
			}
			rule.Sums = append(rule.Sums, [sha256.Size]byte(s))
		}
		out = append(out, rule)
	}
	return out, nil
}

// compareHashes compares two hashes in constant time; a test counts its calls.
var compareHashes = subtle.ConstantTimeCompare

// requireHeaderPasses reports whether h carries the header of every rule with one of its values.
// A value is hashed and compared with every accepted hash in constant time, so the time taken
// tells nothing about how close a guess came; several values of the header pass if any matches.
func requireHeaderPasses(rules []RequireHeaderRule, h http.Header) bool {
	for _, r := range rules {
		match := 0
		for _, v := range h.Values(r.Name) {
			sum := sha256.Sum256([]byte(v))
			for _, want := range r.Sums {
				match |= compareHashes(sum[:], want[:])
			}
		}
		if match != 1 {
			return false
		}
	}
	return true
}

// sameRequireHeader reports whether two routes have the same require_header rules.
func sameRequireHeader(a, b []RequireHeaderRule) bool {
	return slices.EqualFunc(a, b, func(x, y RequireHeaderRule) bool { return x.Name == y.Name && slices.Equal(x.Sums, y.Sums) })
}
