// SPDX-License-Identifier: Apache-2.0

package allinone

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/config"
)

// TestOwnPorts: the process's listener ports and its routes' ports are its own on loopback, on
// the unspecified addresses and on the host's interface addresses, which it looks up again after
// interfacesTTL and keeps when a lookup fails; other ports and other hosts are not.
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
	lookups := 0
	ifaces := []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)}}
	var fail error
	o.now = func() time.Time { return now }
	o.interfaces = func() ([]net.Addr, error) {
		lookups++
		if fail != nil {
			return nil, fail
		}
		return ifaces, nil
	}
	is := func(s string) bool { return o.own(netip.MustParseAddrPort(s)) }
	for target, want := range map[string]bool{
		"127.0.0.1:443": true, "127.0.0.53:7381": true, "[::1]:8443": true, "0.0.0.0:443": true, "[::]:7381": true,
		"[::ffff:127.0.0.1]:443": true, "192.0.2.10:443": true, "192.0.2.11:443": false, "127.0.0.1:80": false,
		"127.0.0.1:8080": false, "198.51.100.1:7381": false,
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
	if lookups != 1 {
		t.Fatalf("%d interface lookups within the TTL", lookups)
	}
	ifaces = []net.Addr{&net.IPNet{IP: net.ParseIP("2001:db8::7"), Mask: net.CIDRMask(64, 128)}}
	now = now.Add(interfacesTTL)
	if !is("[2001:db8::7]:443") || is("192.0.2.10:443") || lookups != 2 {
		t.Fatalf("after the TTL: %d lookups", lookups)
	}
	fail = errors.New("netlink refused")
	now = now.Add(interfacesTTL)
	if !is("[2001:db8::7]:443") || lookups != 3 {
		t.Fatal("a failed lookup dropped the addresses it had")
	}
	bad := cfg
	bad.Listen.Admin = "localhost"
	if _, err := newOwnPorts(bad); err == nil {
		t.Error("a listen address without a port")
	}
}
