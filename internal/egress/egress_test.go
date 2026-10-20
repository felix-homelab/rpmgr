// SPDX-License-Identifier: Apache-2.0

package egress_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/egress"
)

// TestCheck: every range that is not public is refused, in its IPv4-mapped, NAT64 and 6to4 forms
// too; public addresses pass.
func TestCheck(t *testing.T) {
	refused := []string{
		"0.0.0.0", "0.1.2.3", "127.0.0.1", "127.255.255.254", "10.1.2.3", "172.16.0.1", "172.31.255.255",
		"192.168.1.1", "169.254.169.254", "100.64.0.1", "100.100.100.200", "100.127.255.255", "192.0.0.8",
		"192.0.2.1", "198.18.0.1", "198.19.255.255", "198.51.100.7", "203.0.113.9", "224.0.0.1",
		"239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::", "::1", "fe80::1", "fe80::1%eth0", "fc00::1", "fd12:3456::1", "ff02::1", "fec0::1", "100::1",
		"2001::1", "2001:db8::1", "::7f00:1", "64:ff9b:1::a00:1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::c0a8:101",
		"2002:7f00:1::1", "2002:a00:1::", "2002:c0a8:101::1",
		"::ffff:0:7f00:1", "::ffff:0:a00:1", "::ffff:0:a9fe:a9fe", "192.88.99.1", "2001:2::1", "2001:2:0:ffff::1",
		"2001:10::1", "2001:1f:ffff::1", "2001:20::1", "2001:2f:ffff::1", "3fff::1", "3fff:fff:ffff::1", "5f00::1",
	}
	for _, s := range refused {
		err := egress.Check(netip.MustParseAddr(s))
		var re *egress.RefusedError
		if !errors.Is(err, egress.ErrRefused) || !errors.As(err, &re) || re.Reason == "" {
			t.Errorf("%s: %v, want refused with a reason", s, err)
		}
	}
	for _, s := range []string{
		"1.1.1.1", "8.8.8.8", "93.184.215.14", "100.63.255.255", "100.128.0.1", "172.32.0.1", "198.20.0.1",
		"223.255.255.255", "2606:4700:4700::1111", "2a00:1450:4001::200e", "::ffff:8.8.8.8",
		"64:ff9b::808:808", "2002:808:808::1", "::ffff:0:808:808", "192.88.100.1", "2001:3::1", "2001:30::1",
		"3fff:1000::1", "5f01::1",
	} {
		if err := egress.Check(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s: %v, want allowed", s, err)
		}
	}
	if err := egress.Check(netip.Addr{}); !errors.Is(err, egress.ErrRefused) {
		t.Errorf("the zero address: %v", err)
	}
}

// TestControl: the hook refuses the dialled address, and anything it cannot parse.
func TestControl(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:80": false, "[::1]:80": false, "[::ffff:10.0.0.1]:80": false, "8.8.8.8:80": true,
		"[2606:4700:4700::1111]:443": true, "example.com:80": false, "garbage": false,
	} {
		if err := egress.Control("tcp", addr, nil); (err == nil) != ok {
			t.Errorf("%s: %v, want allowed %v", addr, err, ok)
		}
	}
}

// TestDialer_RefusesAtConnect: a listener on loopback is never reached, whatever name led to it.
func TestDialer_RefusesAtConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	for _, host := range []string{"127.0.0.1", "localhost"} {
		c, err := egress.Dialer(time.Second, nil).DialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
		if err == nil {
			_ = c.Close()
		}
		if !errors.Is(err, egress.ErrRefused) {
			t.Errorf("%s: %v, want refused", host, err)
		}
	}
	select {
	case <-accepted:
		t.Fatal("the loopback listener was reached")
	case <-time.After(100 * time.Millisecond):
	}
}
