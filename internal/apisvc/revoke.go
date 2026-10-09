// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"log/slog"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// Revocations revoke the identity of a decommissioned agent (docs/04-security.md, "Revocation").
type Revocations struct {
	// Sys is the controller's system scope: identities and the audit chain are not org rows.
	Sys    context.Context
	RevLog *revlog.Log
	Logger *slog.Logger
	// Denied, if set, applies a changed deny-list to this controller's sessions at once; other
	// replicas apply it at their next revision check.
	Denied func()
}

// agent revokes the identity of an agent of kind in tx, in the revocation log and the audit log,
// for actor, and reports whether it was not revoked before. Call applied after the commit.
func (r *Revocations) agent(tx *ent.Tx, kind pki.Kind, org, id, reason, actor string, now time.Time) (bool, error) {
	inst, err := tx.Instance.Get(r.Sys, 1)
	if err != nil {
		return false, err
	}
	ident := pki.Identity{TrustDomain: inst.TrustDomain, Org: org, Kind: kind, ID: id}
	row, changed, err := pki.RevokeIdentity(r.Sys, tx, ident, reason, now)
	if err != nil || !changed {
		return false, err
	}
	if r.RevLog != nil {
		if _, err := r.RevLog.Append(revlog.Entry{Kind: revlog.IdentityRevoked, Org: org, Subject: ident.String(), Detail: reason,
			NotAfter: &row.NotAfter, Actor: actor}); err != nil && r.Logger != nil {
			r.Logger.Error("cannot append to the revocation log", "kind", revlog.IdentityRevoked, "subject", ident.String(), "error", err)
		}
	}
	_, err = audit.Append(r.Sys, tx, audit.Entry{OrgID: org, ActorType: audit.ActorUser, ActorID: actor, Action: "identity.revoke",
		TargetType: string(kind), TargetID: id, Result: audit.Success, Reason: reason})
	return err == nil, err
}

// applied applies the deny-list after a revocation committed.
func (r *Revocations) applied() {
	if r.Denied != nil {
		r.Denied()
	}
}
