// SPDX-License-Identifier: Apache-2.0

package domains

import (
	"net/netip"
	"syscall"

	"github.com/felix-homelab/rpmgr/internal/egress"
)

// AllowNameservers lets v's queries reach the test nameservers at addrs, which listen on loopback
// addresses that the egress guard refuses; every other address is still checked by the guard.
func AllowNameservers(v *TXTVerifier, addrs ...string) {
	allowed := map[netip.Addr]bool{}
	for _, a := range addrs {
		allowed[netip.MustParseAddr(a)] = true
	}
	v.control = func(network, address string, c syscall.RawConn) error {
		if ap, err := netip.ParseAddrPort(address); err == nil && allowed[ap.Addr().Unmap()] {
			return nil
		}
		return egress.Control(network, address, c)
	}
}
