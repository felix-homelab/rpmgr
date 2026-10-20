// SPDX-License-Identifier: Apache-2.0

package domains

import (
	"net/netip"
	"strings"
	"syscall"

	"github.com/felix-homelab/rpmgr/internal/egress"
)

// AllowNameservers lets v's queries reach the test nameservers at addrs, which listen on loopback
// addresses that the egress guard refuses; every other address is still checked by the guard.
func AllowNameservers(v *TXTVerifier, addrs ...string) { allow(v, "", addrs) }

// AllowNameserversOverUDP is AllowNameservers for UDP only: a TCP connection to addrs is still
// checked by the guard, as after a truncated answer.
func AllowNameserversOverUDP(v *TXTVerifier, addrs ...string) { allow(v, "udp", addrs) }

// allow lets v reach addrs over the networks that begin with network ("" is every network).
func allow(v *TXTVerifier, network string, addrs []string) {
	allowed := map[netip.Addr]bool{}
	for _, a := range addrs {
		allowed[netip.MustParseAddr(a)] = true
	}
	v.control = func(net, address string, c syscall.RawConn) error {
		if ap, err := netip.ParseAddrPort(address); err == nil && allowed[ap.Addr().Unmap()] && strings.HasPrefix(net, network) {
			return nil
		}
		return egress.Control(net, address, c)
	}
}
