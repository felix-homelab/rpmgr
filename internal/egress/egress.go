// SPDX-License-Identifier: Apache-2.0

// Package egress guards the controller's outbound connections to destinations that users name,
// such as the host of an HTTP domain proof (docs/04-security.md, "Route and hostname ownership"):
// a dialer whose Control hook refuses every address that is not public, at the moment of the
// connect, so that a name resolving to an internal address, also after a DNS rebinding, is never
// reached.
package egress

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// ErrRefused is the error of a connection to an address that is not public.
var ErrRefused = errors.New("egress: the address is not public")

// RefusedError names the refused address and why; its message keeps the address, so it is for
// logs, not for users of another trust level.
type RefusedError struct {
	Addr   netip.Addr
	Reason string
}

func (e *RefusedError) Error() string { return fmt.Sprintf("egress: %s is %s", e.Addr, e.Reason) }

// Unwrap makes a RefusedError an ErrRefused.
func (e *RefusedError) Unwrap() error { return ErrRefused }

// blocked are the ranges that IsLoopback, IsPrivate, IsLinkLocalUnicast and the other methods of
// netip.Addr do not cover (RFC 6890 and the IANA special-purpose registries).
var blocked = []struct {
	prefix netip.Prefix
	reason string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "in this network (0.0.0.0/8)"},
	{netip.MustParsePrefix("100.64.0.0/10"), "shared address space (100.64.0.0/10)"},
	{netip.MustParsePrefix("192.0.0.0/24"), "reserved for protocol assignments (192.0.0.0/24)"},
	{netip.MustParsePrefix("192.0.2.0/24"), "a documentation address"},
	{netip.MustParsePrefix("198.18.0.0/15"), "a benchmarking address (198.18.0.0/15)"},
	{netip.MustParsePrefix("198.51.100.0/24"), "a documentation address"},
	{netip.MustParsePrefix("203.0.113.0/24"), "a documentation address"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved or broadcast (240.0.0.0/4)"},
	{netip.MustParsePrefix("::/96"), "an IPv4-compatible address (::/96)"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "a local-use NAT64 address (64:ff9b:1::/48)"},
	{netip.MustParsePrefix("100::/64"), "a discard address (100::/64)"},
	{netip.MustParsePrefix("2001::/32"), "a Teredo address (2001::/32)"},
	{netip.MustParsePrefix("2001:db8::/32"), "a documentation address"},
	{netip.MustParsePrefix("fec0::/10"), "a site-local address (fec0::/10)"},
}

// The prefixes whose addresses embed an IPv4 address that is checked in turn.
var (
	nat64  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4 = netip.MustParsePrefix("2002::/16")
)

// Check reports nil for a public unicast address, else a *RefusedError. An IPv4-mapped address is
// checked as its IPv4 address, and the IPv4 address that a NAT64 (64:ff9b::/96) or 6to4
// (2002::/16) address embeds is checked as well.
func Check(a netip.Addr) error {
	a = a.Unmap().WithZone("")
	refuse := func(reason string) error { return &RefusedError{Addr: a, Reason: reason} }
	switch {
	case !a.IsValid():
		return refuse("not an address")
	case a.IsUnspecified():
		return refuse("unspecified")
	case a.IsLoopback():
		return refuse("a loopback address")
	case a.IsPrivate():
		return refuse("a private address")
	case a.IsLinkLocalUnicast():
		return refuse("a link-local address")
	case a.IsMulticast():
		return refuse("a multicast address")
	}
	for _, b := range blocked {
		if b.prefix.Contains(a) {
			return refuse(b.reason)
		}
	}
	b := a.As16()
	switch {
	case nat64.Contains(a):
		if err := Check(netip.AddrFrom4([4]byte(b[12:16]))); err != nil {
			return refuse("a NAT64 address of an address that is not public")
		}
	case sixTo4.Contains(a):
		if err := Check(netip.AddrFrom4([4]byte(b[2:6]))); err != nil {
			return refuse("a 6to4 address of an address that is not public")
		}
	}
	return nil
}

// Control is a net.Dialer Control hook: it refuses a connection to an address that is not public.
// It runs after name resolution, for the address actually dialled.
func Control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return &RefusedError{Reason: "not an address"}
	}
	return Check(ap.Addr())
}

// Dialer is a dialer with the given timeout that refuses addresses that are not public.
func Dialer(timeout time.Duration, resolver *net.Resolver) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Resolver: resolver, Control: Control}
}
