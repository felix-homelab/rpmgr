// SPDX-License-Identifier: Apache-2.0

package dnstarget_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/dnstarget"
)

func cname(n string) *rpmgrv1.DnsTarget {
	return &rpmgrv1.DnsTarget{Kind: &rpmgrv1.DnsTarget_Cname{Cname: n}}
}

func addrs(a ...string) *rpmgrv1.DnsTarget {
	return &rpmgrv1.DnsTarget{Kind: &rpmgrv1.DnsTarget_Addresses{Addresses: &rpmgrv1.DnsAddresses{Addresses: a}}}
}

func TestCheck(t *testing.T) {
	reserved := []string{"rpmgr.example.com", "Gw.Example.net."}
	for name, tc := range map[string]struct {
		in   *rpmgrv1.DnsTarget
		want dnstarget.Target
	}{
		"nil publishes nothing":          {nil, dnstarget.Target{}},
		"neither member":                 {&rpmgrv1.DnsTarget{}, dnstarget.Target{}},
		"a CNAME":                        {cname("lb.example.com"), dnstarget.Target{CNAME: "lb.example.com"}},
		"a CNAME is normalised":          {cname(" LB.Example.COM. "), dnstarget.Target{CNAME: "lb.example.com"}},
		"an IDN CNAME":                   {cname("bücher.example"), dnstarget.Target{CNAME: "xn--bcher-kva.example"}},
		"a name that only ends like one": {cname("xrpmgr.example.com"), dnstarget.Target{CNAME: "xrpmgr.example.com"}},
		"IPv4 and IPv6":                  {addrs("192.0.2.1", "2001:DB8::2"), dnstarget.Target{Addresses: []string{"192.0.2.1", "2001:db8::2"}}},
		"a private address":              {addrs("10.1.2.3"), dnstarget.Target{Addresses: []string{"10.1.2.3"}}},
	} {
		got, err := dnstarget.Check(tc.in, reserved)
		if err != nil || got.CNAME != tc.want.CNAME || !slices.Equal(got.Addresses, tc.want.Addresses) {
			t.Errorf("%s: %+v, %v; want %+v", name, got, err, tc.want)
		}
	}
}

func TestCheckRefuses(t *testing.T) {
	reserved := []string{"rpmgr.example.com", "Gw.Example.net."}
	long := make([]string, dnstarget.MaxAddresses+1)
	for i := range long {
		long[i] = fmt.Sprintf("198.51.100.%d", i+1)
	}
	for name, in := range map[string]*rpmgrv1.DnsTarget{
		"an empty CNAME":                 cname(""),
		"a blank CNAME":                  cname("  ."),
		"a single label":                 cname("lb"),
		"an underscore":                  cname("lb_1.example.com"),
		"a wildcard":                     cname("*.example.com"),
		"an address as CNAME":            cname("192.0.2.1"),
		"a leading hyphen":               cname("-lb.example.com"),
		"a URL":                          cname("https://lb.example.com"),
		"a name over 253 characters":     cname(strings.Repeat("a.", 130) + "com"),
		"_acme-challenge":                cname("_acme-challenge.example.com"),
		"_acme-challenge, upper case":    cname("_ACME-Challenge.Example.com"),
		"_acme-challenge below a name":   cname("x._acme-challenge.example.com"),
		"the controller's name":          cname("RPMGR.example.com"),
		"a gateway's name, trailing dot": cname("gw.example.net"),
		"no addresses":                   addrs(),
		"a name as an address":           addrs("example.com"),
		"an empty address":               addrs(""),
		"a prefix":                       addrs("192.0.2.0/24"),
		"IPv4-mapped IPv6":               addrs("::ffff:192.0.2.1"),
		"IPv4-mapped IPv6 in hex":        addrs("::ffff:c000:201"),
		"a duplicate":                    addrs("192.0.2.1", "192.0.2.1"),
		"a duplicate IPv6 in two forms":  addrs("2001:db8::1", "2001:DB8:0:0:0:0:0:1"),
		"a zone":                         addrs("fe80::1%eth0"),
		"the unspecified IPv4 address":   addrs("0.0.0.0"),
		"the unspecified IPv6 address":   addrs("::"),
		"loopback":                       addrs("127.0.0.1"),
		"IPv6 loopback":                  addrs("::1"),
		"multicast":                      addrs("224.0.0.1"),
		"link-local":                     addrs("169.254.1.1"),
		"one more than the limit":        addrs(long...),
		"a good address then a bad one":  addrs("192.0.2.1", "nope"),
	} {
		if _, err := dnstarget.Check(in, reserved); !errors.Is(err, dnstarget.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := dnstarget.Check(addrs(long[:dnstarget.MaxAddresses]...), nil); err != nil {
		t.Errorf("exactly the limit: %v", err)
	}
}

func TestMessage(t *testing.T) {
	if (dnstarget.Target{}).Message() != nil {
		t.Error("no target is no message")
	}
	if m := (dnstarget.Target{CNAME: "lb.example.com"}).Message(); m.GetCname() != "lb.example.com" {
		t.Errorf("a CNAME: %v", m)
	}
	in := []string{"192.0.2.1"}
	m := (dnstarget.Target{Addresses: in}).Message()
	in[0] = "changed"
	if got := m.GetAddresses().GetAddresses(); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("addresses: %v", got)
	}
}
