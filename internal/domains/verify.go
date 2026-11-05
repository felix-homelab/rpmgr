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
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnsrecord"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
)

// The TXT proof check (docs/15-dns.md, "Timers and limits").
const (
	QueryTimeout   = 5 * time.Second // per nameserver address
	MaxNameservers = 8               // of a zone, asked in turn
)

// What a failed TXT check shows of a record (docs/15-dns.md, "Domain verification"): the values found at
// the name, and how much of each.
const (
	maxFoundValues = 3
	maxFoundLen    = 64
)

// Why a TXT proof was not found. Their messages name the kind of failure only, never an address, a
// resolver's or a nameserver's, as members of the org read them (issue #823).
var (
	ErrNoNameserver = errors.New("domains: no authoritative nameserver of the zone answered")
	ErrNoProof      = errors.New("domains: the TXT record does not hold the challenge value")
)

// proofError is a failed proof that says what was found. It is ErrNoProof for errors.Is.
type proofError struct{ msg string }

func (e *proofError) Error() string        { return e.msg }
func (e *proofError) Is(target error) bool { return target == ErrNoProof }

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
// its TXT record with the challenge value, an error that is ErrNoProof if they answer without it,
// and ErrNoNameserver, wrapped with the cause, if none answers. A record that holds the value in
// quotes, as a provider may store it, counts, the way the DNS planner counts it. The error of a
// missing proof says which it is: no TXT record at the name, other values at it (cut), the
// challenge not published yet in a managed zone, or the zone's domain delegated to nameservers
// other than the provider's, which never serve what is published there. The proof itself is the
// authoritative answer only; what a managed zone says (Challenge.Zone) changes the words of a
// failure, never its outcome.
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
	var found []string
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
				if txt, ok := rr.(*dns.TXT); ok {
					got := strings.Join(txt.Txt, "")
					if got == value || unquote(got) == value {
						return nil
					}
					if !slices.Contains(found, got) {
						found = append(found, got)
					}
				}
			}
			break // one authoritative answer per nameserver
		}
	}
	if z := c.Zone; z != nil && len(z.NameServers) > 0 && !Delegated(servers, z.NameServers) {
		return &proofError{fmt.Sprintf("domains: %s is delegated to %s, not to %s; records published at %s are not served: "+
			"set the nameservers at your registrar to %s", z.Name, strings.Join(servers, ", "), z.Provider,
			z.Provider, strings.Join(z.NameServers, ", "))}
	}
	if !answered {
		return fmt.Errorf("%w: %s", ErrNoNameserver, last)
	}
	name := ChallengeName(fqdn)
	switch {
	case len(found) > 0:
		return &proofError{fmt.Sprintf("domains: the TXT record at %s holds %s, expected %q", name, foundValues(found), value)}
	case c.Zone != nil && !c.Zone.Published:
		return &proofError{fmt.Sprintf("domains: the TXT record at %s is not published yet in the managed zone %s: the DNS job "+
			"publishes it once the zone's plan is approved and a pass has run", name, c.Zone.Name)}
	}
	return &proofError{fmt.Sprintf("domains: no TXT record at %s yet (the nameservers answered NXDOMAIN or an empty answer)", name)}
}

// unquote drops the quotes a provider may put around the text of a TXT record. The DNS library
// returns a quote that is part of the data in its escaped form, \".
func unquote(s string) string {
	switch {
	case len(s) >= 4 && strings.HasPrefix(s, `\"`) && strings.HasSuffix(s, `\"`):
		return s[2 : len(s)-2]
	case len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"':
		return s[1 : len(s)-1]
	}
	return s
}

// foundValues quotes the values found at a name, a few of them, each cut; they are public records
// of the name, shown so that the operator sees what the nameservers answer.
func foundValues(found []string) string {
	var out []string
	for _, f := range found[:min(len(found), maxFoundValues)] {
		f = strings.ToValidUTF8(f, "")
		if r := []rune(f); len(r) > maxFoundLen {
			f = string(r[:maxFoundLen]) + "…"
		}
		out = append(out, fmt.Sprintf("%q", f))
	}
	if n := len(found) - len(out); n > 0 {
		out = append(out, fmt.Sprintf("and %d more", n))
	}
	return strings.Join(out, ", ")
}

// Delegation returns the nameservers the public DNS names for the zone apex (those of the closest
// enclosing name that has NS records), at most MaxNameservers, sorted. It is what a registrar
// delegates the domain to; compare it to the provider's assigned ones with Delegated.
func (v *TXTVerifier) Delegation(ctx context.Context, apex string) ([]string, error) {
	return v.nameservers(ctx, apex)
}

// Delegated reports whether every public nameserver of a domain is one of the assigned ones, so
// that what the provider publishes is what is served. No public nameserver is not delegated.
func Delegated(public, assigned []string) bool {
	norm := func(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }
	for _, p := range public {
		if !slices.ContainsFunc(assigned, func(a string) bool { return norm(a) == norm(p) }) {
			return false
		}
	}
	return len(public) > 0
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
	// Zone is the managed DNS zone the claim's name is in, if any: what the verifier says of a
	// failure, never whether it succeeds.
	Zone *ManagedZone
}

// ManagedZone is a zone imported from a DNS provider, as far as a claim's check needs it.
type ManagedZone struct {
	Name     string // the zone's apex
	Provider string // the provider's name, as an operator knows it
	// NameServers are those the provider assigned to the zone; empty if it names none, which
	// skips the delegation check.
	NameServers []string
	// Published is whether the DNS job has published the claim's challenge TXT.
	Published bool
}

// ChallengeOf is the challenge of a claim.
func ChallengeOf(d *ent.Domain) Challenge {
	return Challenge{ID: d.ID, FQDN: d.Fqdn, Value: d.ChallengeValue}
}

// ChallengeFor is the challenge of a claim with the managed zone its name is in, if the claim's org
// has imported one: the closest enclosing zone of the same org. What the zone says changes the words
// of a failed check only (Challenge.Zone). A lookup that fails is the caller's to handle; the check
// then runs without the zone's hints.
func ChallengeFor(ctx context.Context, c *ent.Client, d *ent.Domain) (Challenge, error) {
	ch := ChallengeOf(d)
	var apexes []string
	for name := d.Fqdn; strings.Contains(name, "."); name = name[strings.Index(name, ".")+1:] {
		apexes = append(apexes, name)
	}
	// The apexes are ordered from the longest: the first zone found is the closest.
	zones, err := c.DNSZone.Query().Where(dnszone.OrgID(d.OrgID), dnszone.NameIn(apexes...)).All(ctx)
	if err != nil || len(zones) == 0 {
		return ch, err
	}
	z := slices.MaxFunc(zones, func(a, b *ent.DNSZone) int { return len(a.Name) - len(b.Name) })
	prov, err := z.QueryDNSProvider().Only(ctx)
	if err != nil {
		return ch, err
	}
	published, err := c.DNSRecord.Query().Where(dnsrecord.DNSZoneID(z.ID), dnsrecord.Name(ChallengeName(d.Fqdn)),
		dnsrecord.TypeEQ(dnsrecord.TypeTXT), dnsrecord.StateEQ(dnsrecord.StateSynced)).Exist(ctx)
	if err != nil {
		return ch, err
	}
	ch.Zone = &ManagedZone{Name: z.Name, Provider: ProviderName(string(prov.Kind)), NameServers: z.AssignedNameservers, Published: published}
	return ch, nil
}

// ChallengeWithZone is ChallengeFor for a claim checked by TXT, and a lookup that fails leaves the
// check without the zone's hints; the challenge of a claim of another method is ChallengeOf.
func ChallengeWithZone(ctx context.Context, c *ent.Client, d *ent.Domain) Challenge {
	if d.Method == domain.MethodDNSTxt {
		if ch, err := ChallengeFor(ctx, c, d); err == nil {
			return ch
		}
	}
	return ChallengeOf(d)
}

// ProviderName is a DNS provider's name as an operator knows it.
func ProviderName(kind string) string {
	if kind == "cloudflare" {
		return "Cloudflare"
	}
	return kind
}

// DelegationLookup finds the nameservers the public DNS names for a zone's apex; a TXTVerifier does.
type DelegationLookup interface {
	Delegation(ctx context.Context, apex string) ([]string, error)
}

// CheckDelegation says whether the public DNS delegates a zone's domain to the nameservers its
// provider assigned: ok, or mismatch with the public nameservers; unknown, with none, where there
// are no assigned ones to compare or the lookup failed, which is no verdict.
func CheckDelegation(ctx context.Context, v DelegationLookup, apex string, assigned []string) (dnszone.DelegationState, []string) {
	if len(assigned) == 0 {
		return dnszone.DelegationStateUnknown, nil
	}
	public, err := v.Delegation(ctx, apex)
	switch {
	case err != nil:
		return dnszone.DelegationStateUnknown, nil
	case Delegated(public, assigned):
		return dnszone.DelegationStateOk, public
	}
	return dnszone.DelegationStateMismatch, public
}

// Verifier checks the proof of a challenge; nil is a proof.
type Verifier interface {
	Verify(ctx context.Context, c Challenge) error
}

// maxError is how much of a check's error a claim keeps.
const maxError = 512

// Record writes the result of a check of d at now: verified, or still pending or failed with why.
// A proof of a claim that is nested under, or contains, a verified domain of another org does not
// verify it: the claim is held as pending_approval for an Instance Admin (docs/04-security.md,
// "Route and hostname ownership"). ctx must be a scope that sees every org's claims, the system
// scope; Record reads the other orgs' domains in it.
func Record(ctx context.Context, tx *ent.Tx, d *ent.Domain, result error, now time.Time) (*ent.Domain, error) {
	u := tx.Domain.UpdateOne(d).SetLastCheckedAt(now)
	if result == nil {
		held, err := Conflicts(ctx, tx, d.OrgID, d.Fqdn)
		if err != nil {
			return nil, err
		}
		if held {
			u.SetStatus(domain.StatusPendingApproval).SetLastError("")
		} else {
			u.SetStatus(domain.StatusVerified).SetVerifiedAt(now).SetLastError("")
		}
	} else {
		msg := result.Error()
		u.SetLastError(strings.ToValidUTF8(msg[:min(len(msg), maxError)], ""))
	}
	return u.Save(ctx)
}
