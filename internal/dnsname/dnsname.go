// SPDX-License-Identifier: Apache-2.0

// Package dnsname normalises DNS names to the one form rpmgr stores and compares them in: lower-case
// ASCII, without a trailing dot. It has no dependency on the controller or the store, so the roles
// that carry no server code may use it too (docs/04-security.md, "Route and hostname ownership").
package dnsname

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// ErrInvalid is the error of a string that is not a DNS name.
var ErrInvalid = errors.New("dnsname: not a valid DNS name")

// profile is IDNA for names that will be looked up: it maps Unicode to its ASCII form and checks
// the DNS label and name lengths.
var profile = idna.New(idna.MapForLookup(), idna.VerifyDNSLength(true), idna.Transitional(false), idna.BidiRule(), idna.StrictDomainName(true))

// Normalize returns name in the one form the store keeps: lower-case ASCII (IDNA), without a
// trailing dot, of at least two labels, each a letter-digit-hyphen label that neither starts nor
// ends with a hyphen. With wildcard, a hostname may start with "*." for every name one label
// below. An IP address is not a name.
func Normalize(name string, wildcard bool) (string, error) {
	n := strings.TrimSuffix(strings.TrimSpace(name), ".")
	star := wildcard && strings.HasPrefix(n, "*.")
	if star {
		n = n[2:]
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return "", fmt.Errorf("%w: %q is an IP address", ErrInvalid, name)
	}
	ascii, err := profile.ToASCII(n)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrInvalid, name, err)
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: %q has a single label", ErrInvalid, name)
	}
	for _, l := range labels {
		if !ldh(l) {
			return "", fmt.Errorf("%w: label %q of %q", ErrInvalid, l, name)
		}
	}
	if star {
		ascii = "*." + ascii
	}
	if len(ascii) > 253 {
		return "", fmt.Errorf("%w: %q is longer than 253 characters", ErrInvalid, name)
	}
	return ascii, nil
}

func ldh(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
