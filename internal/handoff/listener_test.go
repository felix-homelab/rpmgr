// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"
)

func TestAddrPorts(t *testing.T) {
	ap := netip.MustParseAddrPort
	for _, c := range []struct {
		addr string
		want []netip.AddrPort
	}{
		{"127.0.0.1:7383", []netip.AddrPort{ap("127.0.0.1:7383")}},
		{"[::1]:7383", []netip.AddrPort{ap("[::1]:7383")}},
		{":443", []netip.AddrPort{ap("[::]:443"), ap("0.0.0.0:443")}},
		{"localhost:7383", nil}, // a name, not an address: nothing to look up
		{"127.0.0.1:0", nil},
		{"127.0.0.1:65536", nil},
		{"127.0.0.1:x", nil},
		{"127.0.0.1", nil},
		{"", nil},
	} {
		if got := AddrPorts(c.addr); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.addr, got, c.want)
		}
	}
}

// TestRetirable: a retired listener ends its server as a shutdown; a listener closed otherwise
// fails it as before.
func TestRetirable(t *testing.T) {
	listen := func() *Retirable {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return NewRetirable(ln)
	}
	r := listen()
	go func() {
		c, err := net.Dial("tcp", r.Addr().String())
		if err == nil {
			_ = c.Close()
		}
	}()
	c, err := r.Accept()
	if err != nil {
		t.Fatalf("before retiring: %v", err)
	}
	_ = c.Close()
	r.Retire()
	if _, err := r.Accept(); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("after retiring: %v, want http.ErrServerClosed", err)
	}

	closed := listen()
	_ = closed.Close()
	if _, err := closed.Accept(); err == nil || errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("closed, not retired: %v, want the listener's error", err)
	}
}
