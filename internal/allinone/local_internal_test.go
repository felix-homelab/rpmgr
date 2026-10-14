// SPDX-License-Identifier: Apache-2.0

package allinone

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
)

// TestOwnPorts: the process's listener ports and its bound route ports are its own on loopback,
// on the unspecified addresses, on the host's interface addresses and on the addresses its public
// names resolve to (hairpin NAT). It looks them up again after addrsTTL, after a failed interface
// lookup at the next check and after a failed name lookup a second later, keeping what it had;
// other ports and other hosts are not its own.
func TestOwnPorts(t *testing.T) {
	var cfg config.AllInOne
	if err := config.Parse([]byte("version: 1\npublic_url: https://panel.example.com\nlisten: {tunnel_udp: \":8443\", http: \"\"}\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	o, err := newOwnPorts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	ifaceLookups, nameLookups := 0, 0
	ifaces := []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)}}
	resolved := map[string][]netip.Addr{"panel.example.com": {netip.MustParseAddr("203.0.113.5")}}
	var ifaceFail, nameFail error
	o.now = func() time.Time { return now }
	o.interfaces = func() ([]net.Addr, error) {
		ifaceLookups++
		if ifaceFail != nil {
			return nil, ifaceFail
		}
		return ifaces, nil
	}
	o.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		nameLookups++
		if nameFail != nil {
			return nil, nameFail
		}
		return resolved[host], nil
	}
	is := func(s string) bool { return o.own(netip.MustParseAddrPort(s)) }
	for target, want := range map[string]bool{
		"127.0.0.1:443": true, "127.0.0.53:7381": true, "[::1]:8443": true, "0.0.0.0:443": true, "[::]:7381": true,
		"[::ffff:127.0.0.1]:443": true, "192.0.2.10:443": true, "203.0.113.5:443": true, "192.0.2.11:443": false,
		"127.0.0.1:80": false, "127.0.0.1:8080": false, "198.51.100.1:7381": false,
	} {
		if got := is(target); got != want {
			t.Errorf("%s: own %v, want %v", target, got, want)
		}
	}
	routes := func(port uint16) bool { return port == 5000 }
	o.routes.Store(&routes)
	if !is("127.0.0.1:5000") || !is("192.0.2.10:5000") || is("192.0.2.99:5000") || is("127.0.0.1:5001") {
		t.Error("a route's port")
	}
	if ifaceLookups != 1 || nameLookups != 1 {
		t.Fatalf("%d interface and %d name lookups within the TTL", ifaceLookups, nameLookups)
	}

	// The group's public hostnames join the public URL's host; the next check looks them up.
	resolved["edge.example.com"] = []netip.Addr{netip.MustParseAddr("2001:db8::5")}
	o.setNames([]string{"edge.example.com", "panel.example.com", "edge.example.com", "198.51.100.7"})
	if !is("[2001:db8::5]:443") || !is("198.51.100.7:443") || !is("203.0.113.5:443") || nameLookups != 3 {
		t.Fatalf("the group's names: %d name lookups", nameLookups)
	}

	ifaces = []net.Addr{&net.IPNet{IP: net.ParseIP("2001:db8::7"), Mask: net.CIDRMask(64, 128)}}
	now = now.Add(addrsTTL)
	if !is("[2001:db8::7]:443") || is("192.0.2.10:443") || ifaceLookups != 3 {
		t.Fatalf("after the TTL: %d interface lookups", ifaceLookups)
	}

	ifaceFail = errors.New("netlink refused")
	now = now.Add(addrsTTL)
	if !is("[2001:db8::7]:443") || !is("[2001:db8::7]:7381") || ifaceLookups != 5 {
		t.Fatalf("a failed interface lookup: kept the addresses, %d lookups; want a new one at each check", ifaceLookups)
	}
	ifaceFail = nil

	nameFail = errors.New("no DNS")
	now = now.Add(addrsTTL)
	before := nameLookups
	if !is("203.0.113.5:443") || !is("203.0.113.5:7381") || nameLookups != before+2 {
		t.Fatalf("a failed name lookup: %d lookups, want 2 and the addresses kept", nameLookups-before)
	}
	now = now.Add(nameRetry)
	if !is("203.0.113.5:443") || nameLookups != before+4 {
		t.Fatalf("no new name lookup a second after it failed: %d", nameLookups-before)
	}

	bad := cfg
	bad.Listen.Admin = "localhost"
	if _, err := newOwnPorts(bad); err == nil {
		t.Error("a listen address without a port")
	}
}
