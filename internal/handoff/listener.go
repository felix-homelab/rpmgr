// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
)

// AddrPorts returns the addresses at which the old process reports a listener on addr
// ("host:port"), in the order to look them up: an address with no host is the wildcard, which it
// reports as [::] (dual stack) or 0.0.0.0. An address that does not parse, or port 0, gives none;
// net.Listen then reports it.
func AddrPorts(addr string) []netip.AddrPort {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil
	}
	if host == "" {
		return []netip.AddrPort{netip.AddrPortFrom(netip.IPv6Unspecified(), uint16(p)),
			netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(p))}
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	return []netip.AddrPort{netip.AddrPortFrom(a, uint16(p))}
}

// Retirable is a listener that both processes of a hand-off hold, such as the admin listener,
// whose server ends as if it were shut down, not as if it failed, once Retire closed it: an HTTP
// server returns http.ErrServerClosed, which its owner takes for a normal stop.
type Retirable struct {
	net.Listener
	retired atomic.Bool
}

// NewRetirable wraps ln.
func NewRetirable(ln net.Listener) *Retirable { return &Retirable{Listener: ln} }

// Accept is the listener's, except that after Retire it returns http.ErrServerClosed.
func (r *Retirable) Accept() (net.Conn, error) {
	c, err := r.Listener.Accept()
	if err != nil && r.retired.Load() {
		return nil, http.ErrServerClosed
	}
	return c, err
}

// Retire stops taking connections: the old process's copy closes, and the new process's copy
// answers alone.
func (r *Retirable) Retire() {
	r.retired.Store(true)
	_ = r.Close()
}
