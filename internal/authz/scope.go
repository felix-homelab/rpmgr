// SPDX-License-Identifier: Apache-2.0

// Package authz is the only package that can put an OrgScope into a context. The store reads the
// scope and refuses to run without one (docs/04-security.md, "One enforcement point, with defence
// in depth"; docs/06-data-model.md, "Tenancy enforcement").
//
// OrgScope has only unexported fields and the context key is unexported, so code outside this
// package can read a scope but cannot construct or inject one. The zero OrgScope is invalid.
package authz

import (
	"context"
	"errors"
	"fmt"
)

// OrgScope is the org a request may act in, or the explicit system scope of a job.
type OrgScope struct {
	orgID  string
	system bool
	actor  string
	reason string
}

// OrgID is the org the scope is bound to; empty for the system scope.
func (s OrgScope) OrgID() string { return s.orgID }

// System reports whether this is the explicit, audited system scope.
func (s OrgScope) System() bool { return s.system }

// Actor is the principal (user ID or job name) the scope was granted to.
func (s OrgScope) Actor() string { return s.actor }

// Reason is the audited reason of a system scope.
func (s OrgScope) Reason() string { return s.reason }

type scopeKey struct{}

// Principal is an authenticated caller with the roles of its memberships, keyed by org ID. The
// authentication layer builds it from the session or API token.
type Principal struct {
	UserID      string
	Memberships map[string]string
}

// AuditFunc records the grant of a system scope. An error refuses the scope.
type AuditFunc func(ctx context.Context, job, reason string) error

var (
	// ErrNotMember is returned when the principal has no membership in the org.
	ErrNotMember = errors.New("authz: principal is not a member of the org")
	// ErrNoAudit is returned when a system scope is requested without an audit function.
	ErrNoAudit = errors.New("authz: a system scope needs an audit record")
)

// ForOrg returns ctx with an OrgScope for orgID if p is a member of that org.
func ForOrg(ctx context.Context, p Principal, orgID string) (context.Context, error) {
	if p.UserID == "" || orgID == "" {
		return nil, fmt.Errorf("authz: empty principal or org: %w", ErrNotMember)
	}
	if _, ok := p.Memberships[orgID]; !ok {
		return nil, ErrNotMember
	}
	return context.WithValue(ctx, scopeKey{}, OrgScope{orgID: orgID, actor: p.UserID}), nil
}

// System returns ctx with the system scope for a job, granted only together with an audit record.
func System(ctx context.Context, job, reason string, audit AuditFunc) (context.Context, error) {
	if audit == nil {
		return nil, ErrNoAudit
	}
	if job == "" || reason == "" {
		return nil, errors.New("authz: a system scope needs a job name and a reason")
	}
	if err := audit(ctx, job, reason); err != nil {
		return nil, fmt.Errorf("authz: audit record of a system scope failed: %w", err)
	}
	return context.WithValue(ctx, scopeKey{}, OrgScope{system: true, actor: job, reason: reason}), nil
}

// FromContext returns the scope in ctx, if any.
func FromContext(ctx context.Context) (OrgScope, bool) {
	s, ok := ctx.Value(scopeKey{}).(OrgScope)
	if !ok || (!s.system && s.orgID == "") {
		return OrgScope{}, false
	}
	return s, true
}
