// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"context"
	"encoding/json"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// snapshot is a record as the audit entry shows it. A record holds no secret.
type snapshot struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	ID      string `json:"provider_record_id,omitempty"`
	row     string // the ledger row, the target of the entry
}

func snap(r *ent.DNSRecord) *snapshot {
	s := &snapshot{Name: r.Name, Type: string(r.Type), Content: r.Content, TTL: r.TTL, Proxied: r.Proxied, row: r.ID}
	if r.ProviderRecordID != nil {
		s.ID = *r.ProviderRecordID
	}
	return s
}

// auditRow records a write of the DNS job at the provider, or a repair of the ledger, in the chain of
// the zone's org, with the record before and after (docs/04-security.md, "Audit log"). The target is
// the ledger row of the record.
func (e *Engine) auditRow(ctx context.Context, tx *ent.Tx, z Zone, action, reason string, before, after *snapshot) error {
	diff, err := json.Marshal(struct {
		Before *snapshot `json:"before,omitempty"`
		After  *snapshot `json:"after,omitempty"`
	}{before, after})
	if err != nil {
		return err
	}
	t := after
	if t == nil {
		t = before
	}
	_, err = audit.Append(ctx, tx, audit.Entry{OrgID: z.OrgID, ActorType: audit.ActorSystem, ActorID: Actor,
		Action: action, TargetType: "dns_record", TargetID: t.row, TargetName: t.Name, Result: audit.Success,
		Diff: string(diff), Reason: reason})
	return err
}
