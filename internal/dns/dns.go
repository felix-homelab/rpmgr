// SPDX-License-Identifier: Apache-2.0

// Package dns holds the provider-neutral types of DNS automation and the Provider interface that
// the DNS job, the certmagic adapter and the zone import use (docs/15-dns.md, "Provider
// interface"). A provider is a package of its own, such as internal/dns/cloudflare.
package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Zone is a DNS zone a provider manages.
type Zone struct {
	ID     string
	Name   string // without a trailing dot, lower case
	Status string // the provider's status, such as "active"
	Type   string // the provider's zone type, such as "full"
}

// Record is a DNS record. ID is empty for a record that does not exist yet.
type Record struct {
	ID      string
	Type    string
	Name    string
	Content string
	TTL     int // seconds; 1 means automatic at Cloudflare
	Proxied bool
	Comment string
}

// Batch is a set of changes to one zone. A provider that is all-or-nothing (Capabilities.Batch)
// applies them in the order deletes, patches, puts, posts.
type Batch struct {
	Deletes []string // record IDs
	Patches []Record // ID and the changed fields; here every field is sent
	Puts    []Record // ID and the whole new record
	Posts   []Record // records to create
}

// Len returns the number of operations in the batch.
func (b Batch) Len() int { return len(b.Deletes) + len(b.Patches) + len(b.Puts) + len(b.Posts) }

// TokenInfo is what a provider says about the credential it was given.
type TokenInfo struct {
	ID        string
	Status    string    // the provider's status; "active" is usable
	ExpiresAt time.Time // zero: the token does not expire
}

// Active reports whether the provider calls the token usable.
func (t TokenInfo) Active() bool { return strings.EqualFold(t.Status, "active") }

// Capabilities are what a provider can do beyond plain records.
type Capabilities struct {
	Comments  bool // records carry a comment, where the ownership marker lives
	Proxy     bool // A, AAAA and CNAME records can be proxied
	Batch     bool // Apply is all-or-nothing
	ApexCNAME bool // a CNAME at the zone apex works
}

// Provider is a DNS provider account. Implementations are safe for concurrent use, and take each
// request they send from the Gate in the context of the call, if there is one.
type Provider interface {
	// Verify checks the credential and returns what the provider says about it.
	Verify(ctx context.Context) (TokenInfo, error)
	// ListZones returns every zone the credential can see, following all pages.
	ListZones(ctx context.Context) ([]Zone, error)
	// ListRecords returns every record of a zone, following all pages.
	ListRecords(ctx context.Context, zoneID string) ([]Record, error)
	// Apply sends a batch; it is all-or-nothing if Caps().Batch.
	Apply(ctx context.Context, zoneID string, b Batch) error
	// Caps returns the provider's capabilities.
	Caps() Capabilities
}

// Gate is the budget a provider client takes each request from. The client calls Take before every
// request it sends, a page of a listing as much as a batch, and sends nothing if it fails. A Gate
// reaches the client in the context of the call (WithGate), so the same client serves callers
// with different budgets (docs/15-dns.md, "Batches, failures and the rate budget").
type Gate interface {
	// Take takes one request from the budget. It fails with RateLimited when the budget is spent or
	// blocked.
	Take(ctx context.Context) error
}

type gateKey struct{}

// WithGate returns ctx with the gate a provider client takes its requests from.
func WithGate(ctx context.Context, g Gate) context.Context {
	return context.WithValue(ctx, gateKey{}, g)
}

// GateFrom returns the gate in ctx, nil if there is none.
func GateFrom(ctx context.Context) Gate {
	g, _ := ctx.Value(gateKey{}).(Gate)
	return g
}

// The kinds of failure a provider reports. Test for them with errors.Is.
var (
	// ErrUnauthorized: the provider does not accept the credential (HTTP 401).
	ErrUnauthorized = errors.New("dns: the provider does not accept the credential")
	// ErrForbidden: the credential lacks the permission or the zone (HTTP 403).
	ErrForbidden = errors.New("dns: the credential lacks the permission")
	// ErrNotFound: the zone or record does not exist, or is not visible to the credential.
	ErrNotFound = errors.New("dns: not found")
	// ErrInvalid: the request was refused before it was sent, because it breaks a limit of the
	// provider.
	ErrInvalid = errors.New("dns: the request breaks a provider limit")
)

// RateLimited is the error of a provider that blocks requests until Until. Test for it with
// errors.As. Until is the provider's Retry-After, or a default when it names none.
type RateLimited struct{ Until time.Time }

func (r RateLimited) Error() string {
	return "dns: the provider rate-limits requests until " + r.Until.UTC().Format(time.RFC3339)
}

// ProviderError is a failed provider call: Err is one of the kinds above, RateLimited, or nil for
// any other failure, and Messages are the provider's own words. It never holds a credential.
type ProviderError struct {
	Status   int
	Err      error
	Messages []string
}

func (e *ProviderError) Error() string {
	s := fmt.Sprintf("dns: provider answered HTTP %d", e.Status)
	if e.Err != nil {
		s = e.Err.Error() + " (HTTP " + fmt.Sprint(e.Status) + ")"
	}
	if len(e.Messages) > 0 {
		s += ": " + strings.Join(e.Messages, "; ")
	}
	return s
}

// Unwrap returns the kind of the failure.
func (e *ProviderError) Unwrap() error { return e.Err }
