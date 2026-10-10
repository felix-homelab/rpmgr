// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/revlog"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentsession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/agentstate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/compiledsnapshot"
	"github.com/felix-homelab/rpmgr/internal/store/ent/connector"
	"github.com/felix-homelab/rpmgr/internal/store/ent/datasession"
	"github.com/felix-homelab/rpmgr/internal/store/ent/enrollmenttoken"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gateway"
	"github.com/felix-homelab/rpmgr/internal/store/ent/issuedcertificate"
	"github.com/felix-homelab/rpmgr/internal/store/ent/resourcestatus"
	"github.com/felix-homelab/rpmgr/internal/store/ent/routetarget"
	"github.com/felix-homelab/rpmgr/internal/store/ent/schema"
)

// The purge of agents (docs/04-security.md, "Lifecycle").
const (
	EphemeralPurgeAfter = 30 * time.Minute    // after an ephemeral connector's last disconnect
	TombstonePeriod     = 90 * 24 * time.Hour // after a connector or gateway was decommissioned
	PurgeEvery          = time.Minute
)

// PurgeOptions configure the purge job.
type PurgeOptions struct {
	DB     *store.DB
	RevLog *revlog.Log
	Logger *slog.Logger
	// Denied, if set, applies a changed deny-list to this controller's sessions at once.
	Denied func()
	Now    func() time.Time
}

// PurgeJob purges, under a lease, each ephemeral connector EphemeralPurgeAfter after its last
// disconnect, revoking its identity, and the tombstone of each connector and gateway after the
// TombstonePeriod.
func PurgeJob(o PurgeOptions) lease.Job {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return lease.Job{Name: "purge-agents", Reason: "purge ephemeral connectors and old tombstones", Every: PurgeEvery,
		Run: func(ctx context.Context, _ lease.Lease) error { return purge(ctx, o) }}
}

// agentRow is an agent the purge looks at.
type agentRow struct {
	kind      pki.Kind
	org, id   string
	ephemeral bool
}

func purge(ctx context.Context, o PurgeOptions) error {
	now := o.Now().UTC()
	c := o.DB.Client()
	var due []agentRow
	ephemeral, err := c.Connector.Query().Where(connector.Ephemeral(true)).All(ctx)
	if err != nil {
		return err
	}
	for _, con := range ephemeral {
		s, err := c.AgentSession.Get(ctx, con.ID)
		if err != nil && !ent.IsNotFound(err) {
			return err
		}
		if gone(con, s, now) {
			due = append(due, agentRow{pki.KindConnector, con.OrgID, con.ID, true})
		}
	}
	before := now.Add(-TombstonePeriod)
	cons, err := c.Connector.Query().Where(connector.Ephemeral(false), connector.DecommissionedAtLTE(before)).All(ctx)
	if err != nil {
		return err
	}
	for _, con := range cons {
		due = append(due, agentRow{pki.KindConnector, con.OrgID, con.ID, false})
	}
	gws, err := c.Gateway.Query().Where(gateway.DecommissionedAtLTE(before)).All(ctx)
	if err != nil {
		return err
	}
	for _, gw := range gws {
		due = append(due, agentRow{pki.KindGateway, gw.OrgID, gw.ID, false})
	}
	var errs []error
	revoked := false
	for _, a := range due {
		r, err := purgeAgent(ctx, o, a, now)
		revoked = revoked || r
		if err != nil {
			errs = append(errs, err)
		}
	}
	if revoked && o.Denied != nil {
		o.Denied()
	}
	return errors.Join(errs...)
}

// gone reports whether an ephemeral connector's last disconnect is EphemeralPurgeAfter ago: by its
// recorded end, by a session no controller has seen since, or by its enrollment if it never
// connected.
func gone(con *ent.Connector, s *ent.AgentSession, now time.Time) bool {
	cutoff := now.Add(-EphemeralPurgeAfter)
	switch {
	case s == nil:
		return !con.CreatedAt.After(cutoff)
	case s.DisconnectedAt != nil:
		return !s.DisconnectedAt.After(cutoff)
	default:
		return !schema.AgentSessionLive(nil, s.LastSeenAt, now) && !s.LastSeenAt.After(cutoff)
	}
}

// errKept is a tombstone the purge keeps for now.
var errKept = errors.New("kept")

// purgeAgent deletes an agent in one configuration transaction: its identity revoked if it was
// not yet, its route targets if it is ephemeral, its bound enrollment tokens, what the controller
// observed of it and its row. A tombstone whose connector still has route targets, or with a
// certificate that has not expired, is kept, as are its certificate records otherwise deleted.
// It reports whether it revoked the identity.
func purgeAgent(ctx context.Context, o PurgeOptions, a agentRow, now time.Time) (bool, error) {
	revoked := false
	_, err := store.ConfigTx(store.RevisionOrg(ctx, a.org), o.DB, func(tx *ent.Tx) ([]string, error) {
		if !a.ephemeral {
			if a.kind == pki.KindConnector {
				if n, err := tx.RouteTarget.Query().Where(routetarget.ConnectorID(a.id)).Count(ctx); err != nil || n > 0 {
					return nil, errors.Join(err, errIf(n > 0, errKept))
				}
			}
			live, err := tx.IssuedCertificate.Query().Where(issuedcertificate.SubjectID(a.id), issuedcertificate.NotAfterGTE(now)).Count(ctx)
			if err != nil || live > 0 {
				return nil, errors.Join(err, errIf(live > 0, errKept))
			}
			if _, err := tx.IssuedCertificate.Delete().Where(issuedcertificate.SubjectID(a.id)).Exec(ctx); err != nil {
				return nil, err
			}
		}
		inst, err := tx.Instance.Get(ctx, 1)
		if err != nil {
			return nil, err
		}
		id := pki.Identity{TrustDomain: inst.TrustDomain, Org: a.org, Kind: a.kind, ID: a.id}
		row, changed, err := pki.RevokeIdentity(ctx, tx, id, "purged", now)
		if err != nil {
			return nil, err
		}
		if changed {
			revoked = true
			appendLog(o.RevLog, o.Logger, revlog.Entry{Kind: revlog.IdentityRevoked, Org: a.org, Subject: id.String(), Detail: "purged",
				NotAfter: &row.NotAfter, Actor: "purge-agents"})
			if _, err := audit.Append(ctx, tx, audit.Entry{OrgID: a.org, ActorType: audit.ActorSystem, ActorID: "purge-agents",
				Action: "identity.revoke", TargetType: string(a.kind), TargetID: a.id, Result: audit.Success, Reason: "purged"}); err != nil {
				return nil, err
			}
		}
		if err := deleteAgent(ctx, tx, a); err != nil {
			return nil, err
		}
		_, err = audit.Append(ctx, tx, audit.Entry{OrgID: a.org, ActorType: audit.ActorSystem, ActorID: "purge-agents",
			Action: string(a.kind) + ".purge", TargetType: string(a.kind), TargetID: a.id, Result: audit.Success})
		return []string{a.id}, err
	})
	if errors.Is(err, errKept) {
		return false, nil
	}
	return revoked, err
}

// deleteAgent deletes an agent's row and everything that names it.
func deleteAgent(ctx context.Context, tx *ent.Tx, a agentRow) error {
	steps := []func() error{
		func() error { _, err := tx.AgentSession.Delete().Where(agentsession.ID(a.id)).Exec(ctx); return err },
		func() error { _, err := tx.AgentState.Delete().Where(agentstate.ID(a.id)).Exec(ctx); return err },
		func() error {
			_, err := tx.ResourceStatus.Delete().Where(resourcestatus.AgentID(a.id)).Exec(ctx)
			return err
		},
		func() error {
			_, err := tx.CompiledSnapshot.Delete().Where(compiledsnapshot.AgentID(a.id)).Exec(ctx)
			return err
		},
	}
	if a.kind == pki.KindConnector {
		steps = append(steps,
			func() error {
				_, err := tx.RouteTarget.Delete().Where(routetarget.ConnectorID(a.id)).Exec(ctx)
				return err
			},
			func() error {
				_, err := tx.DataSession.Delete().Where(datasession.ConnectorID(a.id)).Exec(ctx)
				return err
			},
			func() error {
				_, err := tx.EnrollmentToken.Delete().Where(enrollmenttoken.ConnectorID(a.id)).Exec(ctx)
				return err
			},
			func() error { return tx.Connector.DeleteOneID(a.id).Exec(ctx) })
	} else {
		steps = append(steps,
			func() error {
				_, err := tx.DataSession.Delete().Where(datasession.GatewayID(a.id)).Exec(ctx)
				return err
			},
			func() error {
				_, err := tx.EnrollmentToken.Delete().Where(enrollmenttoken.GatewayID(a.id)).Exec(ctx)
				return err
			},
			func() error { return tx.Gateway.DeleteOneID(a.id).Exec(ctx) })
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func errIf(cond bool, err error) error {
	if cond {
		return err
	}
	return nil
}
