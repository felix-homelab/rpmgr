// SPDX-License-Identifier: Apache-2.0

// Package dnstarget checks the DNS target of a gateway group: where the DNS records of its names
// point, a CNAME or a list of addresses (docs/15-dns.md, "Publication rules"). It has no
// dependency on the store, so the API and the DNS job apply the same rules.
package dnstarget

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/dnsname"
)

// MaxAddresses is the most addresses a target lists. The value is the one of docs/15-dns.md,
// "Timers and limits".
const MaxAddresses = 16

// ErrInvalid is the error of a target the rules refuse.
var ErrInvalid = errors.New("dnstarget: invalid DNS target")

// Target is a checked target in the form the store keeps. Its zero value publishes nothing.
type Target struct {
	// CNAME is the canonical name: lower-case ASCII, without a trailing dot.
	CNAME string
	// Addresses are IPv4 and IPv6 addresses in their canonical text form, in the order given.
	Addresses []string
}

// Message is the target as the API shows it; nil when it publishes nothing.
func (t Target) Message() *rpmgrv1.DnsTarget {
	switch {
	case t.CNAME != "":
		return &rpmgrv1.DnsTarget{Kind: &rpmgrv1.DnsTarget_Cname{Cname: t.CNAME}}
	case len(t.Addresses) > 0:
		return &rpmgrv1.DnsTarget{Kind: &rpmgrv1.DnsTarget_Addresses{Addresses: &rpmgrv1.DnsAddresses{Addresses: slices.Clone(t.Addresses)}}}
	}
	return nil
}

// acmePrefix starts the names that belong to certmagic and to TLS passthrough backends.
const acmePrefix = "_acme-challenge."

// Check validates m and returns it in the form the store keeps. A nil message, or one with
// neither member set, is no target. reserved lists the names that must never be written, such as
// the controller's own and the gateways' tunnel names; `_acme-challenge.*` is always reserved.
func Check(m *rpmgrv1.DnsTarget, reserved []string) (Target, error) {
	switch k := m.GetKind().(type) {
	case nil:
		return Target{}, nil
	case *rpmgrv1.DnsTarget_Cname:
		name, err := checkCNAME(k.Cname, reserved)
		return Target{CNAME: name}, err
	case *rpmgrv1.DnsTarget_Addresses:
		addrs, err := checkAddresses(k.Addresses.GetAddresses())
		return Target{Addresses: addrs}, err
	}
	return Target{}, fmt.Errorf("%w: unknown kind", ErrInvalid)
}

func checkCNAME(raw string, reserved []string) (string, error) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if n == "" {
		return "", fmt.Errorf("%w: the CNAME is empty", ErrInvalid)
	}
	if strings.HasPrefix(n, acmePrefix) || strings.Contains(n, "."+acmePrefix) {
		return "", fmt.Errorf("%w: %q is reserved (_acme-challenge names belong to certificate validation)", ErrInvalid, raw)
	}
	name, err := dnsname.Normalize(n, false)
	if err != nil {
		return "", fmt.Errorf("%w: the CNAME %q: want a fully qualified name such as lb.example.com", ErrInvalid, raw)
	}
	for _, r := range reserved {
		if strings.EqualFold(strings.TrimSuffix(r, "."), name) {
			return "", fmt.Errorf("%w: %q is reserved: it is a name of the controller or of a gateway", ErrInvalid, name)
		}
	}
	return name, nil
}

func checkAddresses(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: the address list is empty; leave the target unset to publish nothing", ErrInvalid)
	}
	if len(raw) > MaxAddresses {
		return nil, fmt.Errorf("%w: %d addresses, at most %d", ErrInvalid, len(raw), MaxAddresses)
	}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		switch {
		case err != nil:
			return nil, fmt.Errorf("%w: %q is not an IP address", ErrInvalid, s)
		case a.Zone() != "":
			return nil, fmt.Errorf("%w: %q has a zone", ErrInvalid, s)
		case a.Is4In6():
			return nil, fmt.Errorf("%w: %q is an IPv4-mapped IPv6 address; give the IPv4 address %s", ErrInvalid, s, a.Unmap())
		case a.IsUnspecified(), a.IsLoopback(), a.IsMulticast(), a.IsLinkLocalUnicast():
			return nil, fmt.Errorf("%w: %q is not an address that others can reach", ErrInvalid, s)
		}
		c := a.String()
		if slices.Contains(out, c) {
			return nil, fmt.Errorf("%w: %q is listed twice", ErrInvalid, c)
		}
		out = append(out, c)
	}
	return out, nil
}
