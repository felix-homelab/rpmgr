// SPDX-License-Identifier: Apache-2.0

package egress_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/egress"
)

// TestPolicy (#648): the always-denied addresses stay denied in every form, under a listed range
// and for the Instance Admin's destinations; a private address passes only inside a listed range,
// and a refusal names the range to list; Internal admits loopback and private ranges.
func TestPolicy(t *testing.T) {
	own := netip.MustParseAddr("203.0.113.10")
	org := egress.Policy{Own: []netip.Addr{own}, Private: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("fd00::/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32")}}
	inst := egress.Policy{Internal: true, Own: []netip.Addr{own}}
	always := []string{
		"0.0.0.0", "0.1.2.3", "::", "169.254.169.254", "169.254.1.1", "fe80::1", "fd00:ec2::254", "100.100.100.200",
		"224.0.0.1", "ff02::1", "255.255.255.255", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1",
		"::a9fe:a9fe", "::ffff:0:a9fe:a9fe",
	}
	for _, s := range always {
		for name, p := range map[string]egress.Policy{"org": org, "instance": inst} {
			var re *egress.RefusedError
			if err := p.Check(netip.MustParseAddr(s)); !errors.As(err, &re) || re.Range.IsValid() {
				t.Errorf("%s %s: %v, want refused without a range to list", name, s, err)
			}
		}
	}
	// Loopback and the controller's own addresses: never for org endpoints, even listed.
	for _, s := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "203.0.113.10"} {
		if err := org.Check(netip.MustParseAddr(s)); !errors.Is(err, egress.ErrRefused) {
			t.Errorf("org %s: %v, want refused", s, err)
		}
		if err := inst.Check(netip.MustParseAddr(s)); err != nil {
			t.Errorf("instance %s: %v, want admitted", s, err)
		}
	}
	for s, want := range map[string]string{"192.168.1.5": "192.168.0.0/16", "172.20.0.1": "172.16.0.0/12", "fc00::1": "fc00::/7",
		"198.18.0.1": "198.18.0.0/15", "::ffff:192.168.1.5": "192.168.0.0/16"} {
		var re *egress.RefusedError
		if err := org.Check(netip.MustParseAddr(s)); !errors.As(err, &re) || re.Range.String() != want {
			t.Errorf("org %s: %v, want refused naming %s", s, err, want)
		}
		if err := inst.Check(netip.MustParseAddr(s)); err != nil {
			t.Errorf("instance %s: %v", s, err)
		}
	}
	for _, s := range []string{"10.1.2.3", "::ffff:10.1.2.3", "fd12::1", "100.64.0.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if err := org.Check(netip.MustParseAddr(s)); err != nil {
			t.Errorf("org %s: %v, want admitted (listed or public)", s, err)
		}
	}
	if err := (egress.Policy{}).Check(netip.MustParseAddr("10.1.2.3")); !errors.Is(err, egress.ErrRefused) {
		t.Errorf("unlisted private range: %v", err)
	}
	if err := org.Control("tcp", "[::1]:443", nil); !errors.Is(err, egress.ErrRefused) {
		t.Errorf("Control loopback: %v", err)
	}
	if err := org.Control("tcp", "example.com:443", nil); !errors.Is(err, egress.ErrRefused) {
		t.Errorf("Control of a name: %v", err)
	}
	if err := org.Control("tcp", "10.0.0.1:443", nil); err != nil {
		t.Errorf("Control listed: %v", err)
	}
}
