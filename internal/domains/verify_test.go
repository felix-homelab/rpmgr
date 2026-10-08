// SPDX-License-Identifier: Apache-2.0

package domains_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/felix-homelab/rpmgr/internal/domains"
)

// nameserver is a test DNS server on one loopback address: it answers TXT questions for the
// challenge name with txt, as an authority or not, over UDP truncated if asked, and over TCP.
type nameserver struct {
	txt           []string
	authoritative bool
	truncate      bool
	nxdomain      bool
	queries       atomic.Int32
	tcpQueries    atomic.Int32
}

// serve starts ns on ip:port (port "0" picks one) and returns the port.
func (ns *nameserver) serve(t *testing.T, ip, port string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, port))
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ = net.SplitHostPort(pc.LocalAddr().String())
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, port))
	if err != nil {
		t.Fatal(err)
	}
	handler := func(tcp bool) dns.HandlerFunc {
		return func(w dns.ResponseWriter, q *dns.Msg) {
			ns.queries.Add(1)
			if tcp {
				ns.tcpQueries.Add(1)
			}
			r := new(dns.Msg)
			r.SetReply(q)
			r.Authoritative = ns.authoritative
			if ns.nxdomain {
				r.Rcode = dns.RcodeNameError
			} else if len(ns.txt) > 0 && (!ns.truncate || tcp) {
				r.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: ns.txt}}
			}
			r.Truncated = ns.truncate && !tcp
			_ = w.WriteMsg(r)
		}
	}
	udp, tcpSrv := &dns.Server{PacketConn: pc, Handler: handler(false)}, &dns.Server{Listener: ln, Handler: handler(true)}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = udp.Shutdown(); _ = tcpSrv.Shutdown() })
	return port
}

const value = "c2wkd5yxvcnk3sy7vqkzflqjk5lg6c4v"

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// verifier asks the zone's nameservers by name, each at its address, on port.
func verifier(port string, zone map[string][]string, addrs map[string]string) (*domains.TXTVerifier, *[]string) {
	var asked []string
	return &domains.TXTVerifier{Port: port,
		LookupNS: func(_ context.Context, name string) ([]*net.NS, error) {
			asked = append(asked, name)
			hosts, ok := zone[name]
			if !ok {
				return nil, notFound(name)
			}
			var out []*net.NS
			for _, h := range hosts {
				out = append(out, &net.NS{Host: h + "."})
			}
			return out, nil
		},
		LookupHost: func(_ context.Context, host string) ([]string, error) {
			if a, ok := addrs[host]; ok {
				return []string{a}, nil
			}
			return nil, notFound(host)
		}}, &asked
}

// TestTXTVerifier: the proof is read only from an authoritative nameserver of the zone, found at
// the closest enclosing name with NS records; a value split into strings counts; a wrong value or
// NXDOMAIN is no proof; an answer without authority, a refused nameserver and a failed NS lookup
// are not answers; a truncated answer is asked again over TCP; a resolver that has the record is
// never asked; one nameserver failing leaves the others.
func TestTXTVerifier(t *testing.T) {
	ctx := context.Background()
	good := &nameserver{txt: []string{value}, authoritative: true}
	port := good.serve(t, "127.0.0.1", "0")
	split := &nameserver{txt: []string{value[:10], value[10:]}, authoritative: true}
	split.serve(t, "127.0.0.2", port)
	wrong := &nameserver{txt: []string{"something else"}, authoritative: true}
	wrong.serve(t, "127.0.0.3", port)
	cache := &nameserver{txt: []string{value}} // answers, but without authority, as a resolver does
	cache.serve(t, "127.0.0.4", port)
	big := &nameserver{txt: []string{value}, authoritative: true, truncate: true}
	big.serve(t, "127.0.0.5", port)
	gone := &nameserver{authoritative: true, nxdomain: true}
	gone.serve(t, "127.0.0.6", port)
	addrs := map[string]string{"ns-good.example.net": "127.0.0.1", "ns-split.example.net": "127.0.0.2", "ns-wrong.example.net": "127.0.0.3",
		"ns-cache.example.net": "127.0.0.4", "ns-big.example.net": "127.0.0.5", "ns-gone.example.net": "127.0.0.6",
		"ns-dead.example.net": "127.0.0.7"}

	for name, c := range map[string]struct {
		ns   []string
		want error
	}{
		"an authoritative answer":      {[]string{"ns-good.example.net"}, nil},
		"a value in two strings":       {[]string{"ns-split.example.net"}, nil},
		"a wrong value":                {[]string{"ns-wrong.example.net"}, domains.ErrNoProof},
		"NXDOMAIN":                     {[]string{"ns-gone.example.net"}, domains.ErrNoProof},
		"an answer without authority":  {[]string{"ns-cache.example.net"}, domains.ErrNoNameserver},
		"a truncated answer":           {[]string{"ns-big.example.net"}, nil},
		"nobody listening":             {[]string{"ns-dead.example.net"}, domains.ErrNoNameserver},
		"a nameserver without address": {[]string{"ns-nowhere.example.net"}, domains.ErrNoNameserver},
		"one dead, one good":           {[]string{"ns-dead.example.net", "ns-good.example.net"}, nil},
		"one without authority, wrong": {[]string{"ns-cache.example.net", "ns-wrong.example.net"}, domains.ErrNoProof},
	} {
		v, _ := verifier(port, map[string][]string{"example.com": c.ns}, addrs)
		if err := v.Verify(ctx, "example.com", value); !errors.Is(err, c.want) || c.want == nil && err != nil {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if big.tcpQueries.Load() == 0 {
		t.Error("the truncated answer was not asked again over TCP")
	}

	// The zone is found at the closest enclosing name with NS records.
	v, asked := verifier(port, map[string][]string{"example.com": {"ns-good.example.net"}}, addrs)
	if err := v.Verify(ctx, "app.eu.example.com", value); err != nil {
		t.Fatalf("a name below the zone apex: %v", err)
	}
	if got := strings.Join(*asked, " "); got != "app.eu.example.com eu.example.com example.com" {
		t.Fatalf("NS lookups %q", got)
	}

	// The resolver has the record, the zone's authority does not: no proof, and the resolver is
	// never asked.
	resolver := &nameserver{txt: []string{value}, authoritative: true}
	resolver.serve(t, "127.0.0.8", port)
	v, _ = verifier(port, map[string][]string{"example.com": {"ns-gone.example.net"}}, addrs)
	if err := v.Verify(ctx, "example.com", value); !errors.Is(err, domains.ErrNoProof) || resolver.queries.Load() != 0 {
		t.Fatalf("a record only the resolver has: %v, resolver asked %d times", err, resolver.queries.Load())
	}

	// An NS lookup that fails, rather than finding none, is no answer; so is a name without a zone.
	failing := &domains.TXTVerifier{Port: port, LookupNS: func(context.Context, string) ([]*net.NS, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: "example.com", IsTemporary: true}
	}}
	if err := failing.Verify(ctx, "example.com", value); !errors.Is(err, domains.ErrNoNameserver) {
		t.Fatalf("a failed NS lookup: %v", err)
	}
	v, _ = verifier(port, map[string][]string{}, addrs)
	if err := v.Verify(ctx, "example.com", value); !errors.Is(err, domains.ErrNoNameserver) {
		t.Fatalf("no zone: %v", err)
	}
}
