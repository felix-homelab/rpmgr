// SPDX-License-Identifier: Apache-2.0

package acmetest

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/miekg/dns"
)

// TestStartDNS_TakenTCPPort: StartDNS takes another port when the TCP port of the free UDP port is
// taken, and gives up after dnsPortAttempts ports.
func TestStartDNS_TakenTCPPort(t *testing.T) {
	taken := func(n int) *int {
		calls := 0
		listenTCP = func(network, addr string) (net.Listener, error) {
			calls++
			if calls <= n {
				return nil, &net.OpError{Op: "listen", Net: network, Err: syscall.EADDRINUSE}
			}
			return net.Listen(network, addr)
		}
		t.Cleanup(func() { listenTCP = net.Listen })
		return &calls
	}

	calls := taken(dnsPortAttempts - 1)
	s, err := StartDNS([]string{"example.com"}, nil)
	if err != nil || *calls != dnsPortAttempts {
		t.Fatalf("the last attempt: %v after %d", err, *calls)
	}
	defer s.Close()
	for _, network := range []string{"udp", "tcp"} {
		m := new(dns.Msg)
		m.SetQuestion("app.example.com.", dns.TypeA)
		r, _, err := (&dns.Client{Net: network}).Exchange(m, s.Addr)
		if err != nil || len(r.Answer) != 1 {
			t.Fatalf("%s: %v %v", network, r, err)
		}
	}

	calls = taken(dnsPortAttempts)
	if _, err := StartDNS(nil, nil); !errors.Is(err, syscall.EADDRINUSE) || *calls != dnsPortAttempts {
		t.Fatalf("every attempt taken: %v after %d", err, *calls)
	}
}
