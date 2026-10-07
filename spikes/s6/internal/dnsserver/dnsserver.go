// SPDX-License-Identifier: Apache-2.0

// Package dnsserver is a small authoritative DNS server for the spike's test zones. Pebble uses
// it as its resolver for HTTP-01/TLS-ALPN-01 address lookups and DNS-01 TXT lookups, and
// certmagic uses it to find the zone (SOA) of a challenge name. TXT answers come from the fake
// Cloudflare API, so a challenge record is visible exactly while it exists at the "provider".
package dnsserver

import (
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Server answers for a set of zones on 127.0.0.1 (UDP and TCP on the same port).
type Server struct {
	zones []string
	// TXT returns the TXT values at an FQDN without trailing dot.
	TXT func(fqdn string) []string

	mu      sync.RWMutex
	addrs   map[string][]net.IP // per-name A records; others get DefaultA
	Default net.IP

	udp, tcp *dns.Server
	Addr     string
}

// Start serves the given zones on a free port of 127.0.0.1.
func Start(zones []string, txt func(string) []string) (*Server, error) {
	s := &Server{TXT: txt, addrs: map[string][]net.IP{}, Default: net.IPv4(127, 0, 0, 1)}
	for _, z := range zones {
		s.zones = append(s.zones, strings.ToLower(strings.TrimSuffix(z, ".")))
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return nil, err
	}
	s.Addr = pc.LocalAddr().String()
	h := dns.HandlerFunc(s.serve)
	s.udp = &dns.Server{PacketConn: pc, Handler: h}
	s.tcp = &dns.Server{Listener: ln, Handler: h}
	go func() { _ = s.udp.ActivateAndServe() }()
	go func() { _ = s.tcp.ActivateAndServe() }()
	return s, nil
}

// Close stops the server.
func (s *Server) Close() {
	_ = s.udp.Shutdown()
	_ = s.tcp.Shutdown()
}

// SetA sets the A records of one name (e.g. to send the CA to a particular gateway).
func (s *Server) SetA(fqdn string, ips ...net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addrs[strings.ToLower(strings.TrimSuffix(fqdn, "."))] = ips
}

func (s *Server) zoneOf(name string) string {
	best := ""
	for _, z := range s.zones {
		if (name == z || strings.HasSuffix(name, "."+z)) && len(z) > len(best) {
			best = z
		}
	}
	return best
}

func (s *Server) soa(zone string) dns.RR {
	return &dns.SOA{Hdr: dns.RR_Header{Name: zone + ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns: "ns1." + zone + ".", Mbox: "hostmaster." + zone + ".", Serial: 1, Refresh: 60,
		Retry: 60, Expire: 600, Minttl: 0}
}

func (s *Server) serve(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	defer func() { _ = w.WriteMsg(m) }()
	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		return
	}
	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	zone := s.zoneOf(name)
	if zone == "" {
		m.Rcode = dns.RcodeNameError
		return
	}
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 0}
	switch q.Qtype {
	case dns.TypeSOA:
		if name == zone {
			m.Answer = append(m.Answer, s.soa(zone))
		}
	case dns.TypeNS:
		if name == zone {
			h := hdr
			h.Rrtype = dns.TypeNS
			m.Answer = append(m.Answer, &dns.NS{Hdr: h, Ns: "ns1." + zone + "."})
		}
	case dns.TypeA:
		s.mu.RLock()
		ips, ok := s.addrs[name]
		s.mu.RUnlock()
		if !ok {
			ips = []net.IP{s.Default}
		}
		for _, ip := range ips {
			h := hdr
			h.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: h, A: ip})
		}
	case dns.TypeTXT:
		for _, v := range s.TXT(name) {
			h := hdr
			h.Rrtype = dns.TypeTXT
			var parts []string
			for len(v) > 255 {
				parts, v = append(parts, v[:255]), v[255:]
			}
			m.Answer = append(m.Answer, &dns.TXT{Hdr: h, Txt: append(parts, v)})
		}
	}
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, s.soa(zone)) // NODATA: no AAAA, no CAA, …
	}
}
