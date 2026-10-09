// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
)

// Access is who may use a route (docs/03-connections.md, "Access policies"): its IP rules in
// order. The first rule that matches a client's address decides; if none does, the client is
// allowed only when no rule allows. The zero Access allows everyone.
type Access struct {
	rules []ipRule
	key   string // the rules as text, to tell a change
}

type ipRule struct {
	allow    bool
	prefixes []netip.Prefix
}

// AccessOf parses a snapshot's access rules; an IPv4-mapped IPv6 CIDR becomes its IPv4 one.
func AccessOf(a *agentv1.RouteAccess) (Access, error) {
	var out Access
	var key strings.Builder
	for i, r := range a.GetIpRules() {
		if len(r.GetCidrs()) == 0 {
			return Access{}, fmt.Errorf("IP rule %d has no CIDR", i+1)
		}
		rule := ipRule{allow: r.GetAllow()}
		fmt.Fprintf(&key, "%t", r.GetAllow())
		for _, c := range r.GetCidrs() {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return Access{}, fmt.Errorf("IP rule %d: %w", i+1, err)
			}
			if p.Addr().Is4In6() && p.Bits() >= 96 {
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			p = p.Masked()
			rule.prefixes = append(rule.prefixes, p)
			fmt.Fprintf(&key, " %s", p)
		}
		key.WriteByte(';')
		out.rules = append(out.rules, rule)
	}
	out.key = key.String()
	return out, nil
}

// Allows reports whether a client address may use the route.
func (a Access) Allows(ip netip.Addr) bool {
	ip = ip.Unmap()
	anyAllow := false
	for _, r := range a.rules {
		anyAllow = anyAllow || r.allow
		for _, p := range r.prefixes {
			if p.Contains(ip) {
				return r.allow
			}
		}
	}
	return !anyAllow
}

// AllowsAddr is Allows for a connection's remote address; an address that is not IP is denied
// unless the route allows everyone.
func (a Access) AllowsAddr(addr net.Addr) bool {
	if len(a.rules) == 0 {
		return true
	}
	ap, err := netip.ParseAddrPort(addr.String())
	return err == nil && a.Allows(ap.Addr())
}

// Same reports whether two Accesses have the same rules.
func (a Access) Same(b Access) bool { return a.key == b.key }
