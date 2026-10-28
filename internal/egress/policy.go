// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"errors"
	"net/netip"
	"slices"
	"syscall"
)

// Policy is the guard of webhook deliveries and audit sinks (docs/04-security.md, "Webhooks and
// the egress guard (Phase 2)", D138): public addresses pass; loopback, unspecified, link-local,
// metadata, multicast and broadcast addresses and the controller's own never do, in any form that
// embeds one; every other address that is not public passes only inside a listed range, or for
// the Instance Admin's destinations (Internal), which may reach loopback and private ranges too.
type Policy struct {
	// Private are the ranges an Instance Admin listed (webhook_private_ranges).
	Private []netip.Prefix
	// Internal admits loopback and every address that is not public, but none of the rest of the
	// always-denied addresses: instance endpoints and audit sinks (D145, E5).
	Internal bool
	// Own are the controller's own addresses, refused unless Internal.
	Own []netip.Addr
}

// The cloud metadata addresses outside link-local, denied even inside a listed range.
var metadata = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("100.100.100.200")}

var broadcast = netip.MustParseAddr("255.255.255.255")

// The ranges a refused private address is named by, for the UI to offer listing it.
var privateRanges = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7")}

// Check reports nil for an address p admits, else a *RefusedError; a refused address that a
// listed range could admit has its Range set.
func (p Policy) Check(a netip.Addr) error {
	a = a.Unmap().WithZone("")
	forms := []netip.Addr{a}
	if e, ok := embedded(a); ok {
		forms = append(forms, e)
	}
	for _, f := range forms {
		if reason := p.always(f); reason != "" {
			return &RefusedError{Addr: a, Reason: reason}
		}
	}
	err := Check(a)
	if err == nil || p.Internal {
		return nil
	}
	if slices.ContainsFunc(p.Private, func(r netip.Prefix) bool { return r.Contains(a) }) {
		return nil
	}
	var re *RefusedError
	if errors.As(err, &re) {
		re.Range = rangeOf(a)
	}
	return err
}

// always is the reason an address is never admitted under p, or "".
func (p Policy) always(a netip.Addr) string {
	switch {
	case !a.IsValid():
		return "not an address"
	case a.IsUnspecified() || a.Is4() && a.As4()[0] == 0:
		return "unspecified"
	case a.IsLoopback() && !p.Internal:
		return "a loopback address"
	case a.IsLinkLocalUnicast():
		return "a link-local address"
	case slices.Contains(metadata, a):
		return "a cloud metadata address"
	case a.IsMulticast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast():
		return "a multicast address"
	case a == broadcast:
		return "a broadcast address"
	case !p.Internal && slices.Contains(p.Own, a):
		return "an address of the controller"
	}
	return ""
}

// embedded is the IPv4 address an IPv4-compatible, NAT64, IPv4-translated or 6to4 address embeds;
// ::1 and :: embed none.
func embedded(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() || a.IsLoopback() || a.IsUnspecified() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case netip.MustParsePrefix("::/96").Contains(a), nat64.Contains(a), siit.Contains(a):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixTo4.Contains(a):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

// rangeOf is the range that names a refused address: its private or special-purpose range, else
// the address alone.
func rangeOf(a netip.Addr) netip.Prefix {
	for _, r := range privateRanges {
		if r.Contains(a) {
			return r
		}
	}
	for _, b := range blocked {
		if b.prefix.Contains(a) {
			return b.prefix
		}
	}
	return netip.PrefixFrom(a, a.BitLen())
}

// Control is a net.Dialer Control hook that refuses an address p does not admit.
func (p Policy) Control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return &RefusedError{Reason: "not an address"}
	}
	return p.Check(ap.Addr())
}
