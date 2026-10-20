// SPDX-License-Identifier: Apache-2.0

package domains

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
)

// The TXT proof check (docs/15-dns.md, "Timers and limits").
const (
	QueryTimeout   = 5 * time.Second // per nameserver address
	MaxNameservers = 8               // of a zone, asked in turn
)

// Why a TXT proof was not found. Their messages name the kind of failure only, never an address, a
// resolver's or a nameserver's, as members of the org read them (issue #823).
var (
	ErrNoNameserver = errors.New("domains: no authoritative nameserver of the zone answered")
	ErrNoProof      = errors.New("domains: the TXT record does not hold the challenge value")
)

// errNoZone is a name with no NS records up to its top-level domain.
var errNoZone = errors.New("no NS records up to the top-level domain")

// ChallengeName is the name of a claim's TXT record.
func ChallengeName(fqdn string) string { return "_rpmgr-challenge." + fqdn }

// TXTVerifier reads a claim's TXT record at the zone's authoritative nameservers, never through a
// resolver, so that split-horizon DNS and negative caching cannot fake or delay a result
// (docs/04-security.md, "Route and hostname ownership"). Only the nameservers of the zone are
// found through the resolver, the host's own, which is trusted wherever it is. The nameservers'
// addresses come from the claimed zone, so the queries connect only to public addresses
// (internal/egress), checked for the address dialled, over UDP and TCP alike.
type TXTVerifier struct {
	// LookupNS and LookupHost resolve the zone's nameservers; nil uses the system resolver.
	LookupNS   func(ctx context.Context, name string) ([]*net.NS, error)
	LookupHost func(ctx context.Context, host string) ([]string, error)
	// Port is the nameservers' port; empty is 53.
	Port string
	// control replaces egress.Control for the nameservers' addresses; only tests set it.
	control func(network, address string, c syscall.RawConn) error
}

// Verify reports nil if an authoritative nameserver of the zone holding the claimed name answers
// its TXT record with the challenge value, ErrNoProof if they answer without it, and
// ErrNoNameserver, wrapped with the cause, if none answers.
func (v *TXTVerifier) Verify(ctx context.Context, c Challenge) error {
	fqdn, value := c.FQDN, c.Value
	servers, err := v.nameservers(ctx, fqdn)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNoNameserver, zoneFailure(err))
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(ChallengeName(fqdn)), dns.TypeTXT)
	q.RecursionDesired = false
	answered := false
	last := "no nameserver has an address"
	for _, host := range servers {
		addrs, err := v.lookupHost(ctx, host)
		if err != nil {
			last = "a nameserver's name " + resolveFailure(err)
			continue
		}
		for _, a := range addrs {
			r, err := v.exchange(ctx, q, net.JoinHostPort(a, v.port()))
			if err != nil {
				last = queryFailure(err)
				continue
			}
			if !r.Authoritative || (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) {
				last = fmt.Sprintf("a nameserver answered without authority (rcode %s)", dns.RcodeToString[r.Rcode])
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
		return fmt.Errorf("%w: %s", ErrNoNameserver, last)
	}
	return ErrNoProof
}

// zoneFailure is why the zone's nameservers were not found, without the resolver's address.
func zoneFailure(err error) string {
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, errNoZone) || errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return "the name is in no zone with NS records"
	case errors.As(err, &dnsErr) && dnsErr.IsTimeout || errors.Is(err, context.DeadlineExceeded):
		return "looking up the zone's nameservers timed out"
	default:
		return "the zone's nameservers could not be looked up"
	}
}

// resolveFailure is why a nameserver's name did not resolve, without the resolver's address.
func resolveFailure(err error) string {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return "does not resolve"
	case errors.As(err, &dnsErr) && dnsErr.IsTimeout || errors.Is(err, context.DeadlineExceeded):
		return "timed out resolving"
	default:
		return "could not be resolved"
	}
}

// queryFailure is why a query to a nameserver failed, without its address or the controller's.
func queryFailure(err error) string {
	switch {
	case errors.Is(err, egress.ErrRefused):
		return "a nameserver's address is not public"
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		return "a nameserver did not answer in time"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "a nameserver refused the query"
	case errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH):
		return "a nameserver is not reachable"
	default:
		return "a query to a nameserver failed"
	}
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
		last = errNoZone
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

// exchange asks addr over UDP, and over TCP when the answer was truncated, through a dialer that
// refuses addresses that are not public.
func (v *TXTVerifier) exchange(ctx context.Context, q *dns.Msg, addr string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	d := egress.Dialer(QueryTimeout, nil)
	if v.control != nil {
		d.Control = v.control
	}
	r, _, err := (&dns.Client{Net: "udp", Timeout: QueryTimeout, Dialer: d}).ExchangeContext(ctx, q, addr)
	if err == nil && r.Truncated {
		r, _, err = (&dns.Client{Net: "tcp", Timeout: QueryTimeout, Dialer: d}).ExchangeContext(ctx, q, addr)
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
