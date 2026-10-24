// SPDX-License-Identifier: Apache-2.0

// Package headermatch holds the header matches of http routes (docs/03-connections.md, "HTTP
// routes", D135): the rules the API, the store and the gateway share, so that the three agree on
// what a match is, when a set of them is valid, and when two sets are the same.
package headermatch

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// Max is the most matches a route may have.
const Max = 8

// A Match is a request header that must be present, with an exact value unless Present is set.
// It is stored as JSON in route_http.header_matches.
type Match struct {
	// Name is the header's name, compared without regard to case.
	Name string `json:"name"`
	// Value is the exact value one of the header's values must have; unused with Present.
	Value string `json:"value,omitempty"`
	// Present matches any value of the header.
	Present bool `json:"present,omitempty"`
}

// ErrInvalid is the error of a set of matches the rules refuse.
var ErrInvalid = errors.New("headermatch: invalid header matches")

// Check returns an error wrapping ErrInvalid if ms is not a valid set: at most Max matches, each
// with a valid header name that no other match has, and either Present or a non-empty valid
// field value. Host, which Go keeps apart from the other headers, and the identity headers the
// gateway removes cannot be matched.
func Check(ms []Match) error {
	if len(ms) > Max {
		return fmt.Errorf("%w: %d matches, at most %d", ErrInvalid, len(ms), Max)
	}
	seen := map[string]bool{}
	for _, m := range ms {
		name := textproto.CanonicalMIMEHeaderKey(m.Name)
		switch {
		case !httpguts.ValidHeaderFieldName(m.Name):
			return fmt.Errorf("%w: header name %q", ErrInvalid, m.Name)
		case name == "Host" || strings.HasPrefix(name, "Rpmgr-User-"):
			return fmt.Errorf("%w: header %s cannot be matched", ErrInvalid, name)
		case seen[name]:
			return fmt.Errorf("%w: header %s is matched twice", ErrInvalid, name)
		case m.Present && m.Value != "":
			return fmt.Errorf("%w: header %s is matched by presence and by a value", ErrInvalid, name)
		case !m.Present && (m.Value == "" || !httpguts.ValidHeaderFieldValue(m.Value)):
			return fmt.Errorf("%w: header %s needs a valid, non-empty value or presence", ErrInvalid, name)
		}
		seen[name] = true
	}
	return nil
}

// Canonical returns ms with canonical names, sorted by name: the form the store and snapshots
// hold. It returns nil for no matches.
func Canonical(ms []Match) []Match {
	if len(ms) == 0 {
		return nil
	}
	out := make([]Match, len(ms))
	for i, m := range ms {
		out[i] = Match{Name: textproto.CanonicalMIMEHeaderKey(m.Name), Value: m.Value, Present: m.Present}
	}
	slices.SortFunc(out, func(a, b Match) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// Key identifies a set of matches whatever its order and the case of its names: "" for none,
// else the hexadecimal SHA-256 of its canonical form. Two routes of a group may share a hostname
// and path prefix only with different keys.
func Key(ms []Match) string {
	if len(ms) == 0 {
		return ""
	}
	var b strings.Builder
	for _, m := range Canonical(ms) {
		// Names and values hold no NUL (httpguts refuses it), so the encoding is unambiguous.
		if m.Present {
			fmt.Fprintf(&b, "%s\x00p\x00", m.Name)
		} else {
			fmt.Fprintf(&b, "%s\x00v\x00%s\x00", m.Name, m.Value)
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// Holds reports whether every match holds for the request header h: the header is present, and
// for a value match one of its values equals the value exactly.
func Holds(h http.Header, ms []Match) bool {
	for _, m := range ms {
		values := h.Values(m.Name)
		if len(values) == 0 || !m.Present && !slices.Contains(values, m.Value) {
			return false
		}
	}
	return true
}
