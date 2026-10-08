// SPDX-License-Identifier: Apache-2.0

package domains

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
)

// The TXT proof check (docs/15-dns.md, "Timers and limits").
const (
	QueryTimeout   = 5 * time.Second // per nameserver address
	MaxNameservers = 8               // of a zone, asked in turn
)

// Why a TXT proof was not found.
var (
	ErrNoNameserver = errors.New("domains: no authoritative nameserver of the zone answered")
	ErrNoProof      = errors.New("domains: the TXT record does not hold the challenge value")
)

// ChallengeName is the name of a claim's TXT record.
func ChallengeName(fqdn string) string { return "_rpmgr-challenge." + fqdn }

// TXTVerifier reads a claim's TXT record at the zone's authoritative nameservers, never through a
// resolver, so that split-horizon DNS and negative caching cannot fake or delay a result
// (docs/04-security.md, "Route and hostname ownership"). Only the nameservers of the zone are
// found through the resolver.
type TXTVerifier struct {
	// LookupNS and LookupHost resolve the zone's nameservers; nil uses the system resolver.
	LookupNS   func(ctx context.Context, name string) ([]*net.NS, error)
	LookupHost func(ctx context.Context, host string) ([]string, error)
	// Port is the nameservers' port; empty is 53.
	Port string
}

// Verify reports nil if an authoritative nameserver of the zone holding the claimed name answers
// its TXT record with the challenge value, ErrNoProof if they answer without it, and
// ErrNoNameserver, wrapped with the cause, if none answers.
func (v *TXTVerifier) Verify(ctx context.Context, c Challenge) error {
	fqdn, value := c.FQDN, c.Value
	servers, err := v.nameservers(ctx, fqdn)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoNameserver, err)
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(ChallengeName(fqdn)), dns.TypeTXT)
	q.RecursionDesired = false
	answered := false
	var last error
	for _, host := range servers {
		addrs, err := v.lookupHost(ctx, host)
		if err != nil {
			last = err
			continue
		}
		for _, a := range addrs {
			r, err := exchange(ctx, q, net.JoinHostPort(a, v.port()))
			if err != nil {
				last = err
				continue
			}
			if !r.Authoritative || (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) {
				last = fmt.Errorf("%s answered without authority (rcode %s)", host, dns.RcodeToString[r.Rcode])
				continue
			}
			answered = true
			for _, rr := range r.Answer {
				if txt, ok := rr.(*dns.TXT); ok && strings.Join(txt.Txt, "") == value {
					return nil
				}
			}
			break // one authoritative answer per nameserver
		}
	}
	if !answered {
		return fmt.Errorf("%w: %w", ErrNoNameserver, last)
	}
	return ErrNoProof
}

// nameservers returns the nameservers of the zone that holds fqdn: those of the closest enclosing
// name that has NS records, at most MaxNameservers, sorted.
func (v *TXTVerifier) nameservers(ctx context.Context, fqdn string) ([]string, error) {
	lookup := v.LookupNS
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNS
	}
	var last error
	for name := fqdn; strings.Contains(name, "."); name = name[strings.Index(name, ".")+1:] {
		ns, err := lookup(ctx, name)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || dnsErr.Err == "no such host") {
				last = err
				continue // not a zone apex: try its parent
			}
			return nil, err
		}
		var hosts []string
		for _, n := range ns {
			hosts = append(hosts, strings.TrimSuffix(strings.ToLower(n.Host), "."))
		}
		if len(hosts) == 0 {
			continue
		}
		slices.Sort(hosts)
		hosts = slices.Compact(hosts)
		return hosts[:min(len(hosts), MaxNameservers)], nil
	}
	if last == nil {
		last = errors.New("no NS records up to the top-level domain")
	}
	return nil, last
}

func (v *TXTVerifier) lookupHost(ctx context.Context, host string) ([]string, error) {
	if v.LookupHost != nil {
		return v.LookupHost(ctx, host)
	}
	return net.DefaultResolver.LookupHost(ctx, host)
}

func (v *TXTVerifier) port() string {
	if v.Port == "" {
		return "53"
	}
	return v.Port
}

// exchange asks addr over UDP, and over TCP when the answer was truncated.
func exchange(ctx context.Context, q *dns.Msg, addr string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	r, _, err := (&dns.Client{Net: "udp", Timeout: QueryTimeout}).ExchangeContext(ctx, q, addr)
	if err == nil && r.Truncated {
		r, _, err = (&dns.Client{Net: "tcp", Timeout: QueryTimeout}).ExchangeContext(ctx, q, addr)
	}
	return r, err
}

// Challenge is what a verifier checks: a claim's ID, name and challenge value.
type Challenge struct {
	ID, FQDN, Value string
}

// ChallengeOf is the challenge of a claim.
func ChallengeOf(d *ent.Domain) Challenge {
	return Challenge{ID: d.ID, FQDN: d.Fqdn, Value: d.ChallengeValue}
}

// Verifier checks the proof of a challenge; nil is a proof.
type Verifier interface {
	Verify(ctx context.Context, c Challenge) error
}

// maxError is how much of a check's error a claim keeps.
const maxError = 512

// Record writes the result of a check of d at now: verified, or still pending or failed with why.
func Record(ctx context.Context, tx *ent.Tx, d *ent.Domain, result error, now time.Time) (*ent.Domain, error) {
	u := tx.Domain.UpdateOne(d).SetLastCheckedAt(now)
	if result == nil {
		u.SetStatus(domain.StatusVerified).SetVerifiedAt(now).SetLastError("")
	} else {
		msg := result.Error()
		u.SetLastError(strings.ToValidUTF8(msg[:min(len(msg), maxError)], ""))
	}
	return u.Save(ctx)
}
