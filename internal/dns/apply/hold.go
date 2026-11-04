// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"context"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/dns/plan"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/dnszone"
)

// The held_reason of a zone (docs/15-dns.md, "Held zones and plan approval").
const (
	// HeldImported: the zone was imported and no plan is approved yet.
	HeldImported = "imported"
	// HeldRestored: a restore of a backup held every zone.
	HeldRestored = "restored"
	// HeldEnabled: a disabled zone was enabled and needs an approved plan.
	HeldEnabled = "enabled"
	// HeldDeletionGuard: a pass would have removed more names than the zone's delete_threshold.
	HeldDeletionGuard = "deletion_guard"
	// HeldPlanChanged: the plan that was approved is not the one the pass computed.
	HeldPlanChanged = "plan_changed"
)

// Removals counts the names whose address records the plan removes: names with a deleted A, AAAA
// or CNAME record and none created at the name. A record that is replaced, such as an address that
// changes, or a type that changes, is no removal (docs/15-dns.md, "Held zones and plan approval").
func Removals(p plan.Plan) int {
	created := map[string]bool{}
	for _, r := range p.Creates {
		if isAddress(r.Type) {
			created[r.Name] = true
		}
	}
	removed := map[string]bool{}
	for _, r := range p.Deletes {
		if isAddress(r.Type) && !created[r.Name] {
			removed[r.Name] = true
		}
	}
	return len(removed)
}

func isAddress(t string) bool { return t == "A" || t == "AAAA" || t == "CNAME" }

// Guard is the gate of an active zone's pass (Wanted.Gate): it holds the zone, and the pass writes
// nothing, when the plan removes more names than threshold, or, if the Owner or Admin approved a
// plan, when this is not it. An approved plan passes whatever it removes; approved is then true,
// and the approval is used up. A threshold of 0 holds on every removal.
func Guard(threshold int, approvedHash string) func(plan.Plan) (hold string, approved bool) {
	return func(p plan.Plan) (string, bool) {
		switch {
		case approvedHash != "" && p.Hash == approvedHash:
			return "", true
		case approvedHash != "":
			return HeldPlanChanged, false
		case Removals(p) > threshold:
			return HeldDeletionGuard, false
		}
		return "", false
	}
}

// Plan lists the provider's records and plans, and writes nothing: no ledger row is touched, no
// crash repaired and no drift corrected. It is what a held zone shows, and what an approval
// binds to (docs/15-dns.md, "The plan and its hash").
func (e *Engine) Plan(ctx context.Context, p dns.Provider, z Zone, w Wanted) (plan.Plan, error) {
	live, err := p.ListRecords(ctx, z.ProviderID)
	if err != nil {
		return plan.Plan{}, err
	}
	return e.PlanOf(ctx, live, z, w)
}

// PlanOf plans against the records the caller listed.
func (e *Engine) PlanOf(ctx context.Context, live []dns.Record, z Zone, w Wanted) (plan.Plan, error) {
	owned, err := Owned(ctx, e.DB, z.ID)
	if err != nil {
		return plan.Plan{}, err
	}
	return plan.Diff(plan.Input{Zone: z.Name, Desired: w.Desired, Keep: w.Keep, Reserved: w.Reserved, Live: live, Owned: owned, TrustDomain: e.TrustDomain}), nil
}

// HoldAll sets every zone to held, with the reason restored, or, with disabled, to disabled; the
// stored plans and approvals go. It is what a restore does (docs/15-dns.md, "Held zones and plan
// approval"), in the restore's transaction, and returns the number of zones.
func HoldAll(ctx context.Context, tx *ent.Tx, disabled bool) (int, error) {
	u := tx.DNSZone.Update().ClearPendingPlan().SetPendingPlanHash("")
	if disabled {
		u.SetSyncState(dnszone.SyncStateDisabled).SetHeldReason("")
	} else {
		u.SetSyncState(dnszone.SyncStateHeld).SetHeldReason(HeldRestored)
	}
	return u.Save(ctx)
}
