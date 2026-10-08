// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/domains"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/domain"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// recordingVerifier proves the names in ok and records every name it checks.
type recordingVerifier struct {
	mu      sync.Mutex
	ok      map[string]bool
	checked []string
}

func (v *recordingVerifier) Verify(_ context.Context, fqdn, _ string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.checked = append(v.checked, fqdn)
	if v.ok[fqdn] {
		return nil
	}
	return domains.ErrNoProof
}

// TestDomainChecks (docs/15-dns.md, "Timers and limits"): a pending claim is checked every minute
// in its first quarter hour and every 15 minutes after it; one not proved within 7 days fails
// unchecked; a proof verifies it; claims of a method without a verifier, and claims that are not
// pending, are left alone.
func TestDomainChecks(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "org-a")
		now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
		add := func(fqdn string, age time.Duration, checked *time.Duration, edit func(*ent.DomainCreate)) {
			c := db.Client().Domain.Create().SetOrgID(org).SetFqdn(fqdn).SetChallengeValue("v").SetCreatedAt(now.Add(-age))
			if checked != nil {
				c.SetLastCheckedAt(now.Add(-*checked))
			}
			if edit != nil {
				edit(c)
			}
			c.ExecX(sys)
		}
		ago := func(d time.Duration) *time.Duration { return &d }
		add("new.example", 2*time.Minute, nil, nil)
		add("early-recent.example", 5*time.Minute, ago(30*time.Second), nil)
		add("early-due.example", 5*time.Minute, ago(61*time.Second), nil)
		add("late-recent.example", time.Hour, ago(10*time.Minute), nil)
		add("late-due.example", time.Hour, ago(16*time.Minute), nil)
		add("proved.example", time.Hour, ago(20*time.Minute), nil)
		add("expired.example", 7*24*time.Hour+time.Minute, ago(time.Minute), nil)
		add("web.example", 2*time.Minute, nil, func(c *ent.DomainCreate) { c.SetMethod(domain.MethodHTTP) })
		add("done.example", time.Hour, ago(time.Hour), func(c *ent.DomainCreate) { c.SetStatus(domain.StatusVerified) })

		v := &recordingVerifier{ok: map[string]bool{"proved.example": true}}
		job := controller.DomainCheckJob(controller.DomainCheckOptions{DB: db, TXT: v, Now: func() time.Time { return now }})
		if err := job.Run(context.WithoutCancel(sys), lease.Lease{}); err != nil {
			t.Fatal(err)
		}
		slices.Sort(v.checked)
		if want := []string{"early-due.example", "late-due.example", "new.example", "proved.example"}; !slices.Equal(v.checked, want) {
			t.Fatalf("checked %v, want %v", v.checked, want)
		}
		get := func(fqdn string) *ent.Domain { return db.Client().Domain.Query().Where(domain.Fqdn(fqdn)).OnlyX(sys) }
		for _, fqdn := range []string{"new.example", "early-due.example", "late-due.example"} {
			d := get(fqdn)
			if d.Status != domain.StatusPending || d.LastCheckedAt == nil || !d.LastCheckedAt.Equal(now) || d.LastError == "" {
				t.Errorf("%s: %+v", fqdn, d)
			}
		}
		if d := get("proved.example"); d.Status != domain.StatusVerified || d.VerifiedAt == nil || d.LastError != "" {
			t.Errorf("a proved claim: %+v", d)
		}
		if d := get("expired.example"); d.Status != domain.StatusFailed || d.LastError != "not proved within 7 days" {
			t.Errorf("an expired claim: %+v", d)
		}
		if d := get("web.example"); d.LastCheckedAt != nil {
			t.Errorf("an HTTP claim without a verifier was checked: %+v", d)
		}
		if d := get("early-recent.example"); !d.LastCheckedAt.Equal(now.Add(-30 * time.Second)) {
			t.Errorf("a claim not due was checked: %+v", d)
		}

		// A minute later the early claims are due again, the late ones not.
		v.checked = nil
		later := controller.DomainCheckJob(controller.DomainCheckOptions{DB: db, TXT: v, Now: func() time.Time { return now.Add(time.Minute) }})
		if err := later.Run(context.WithoutCancel(sys), lease.Lease{}); err != nil {
			t.Fatal(err)
		}
		slices.Sort(v.checked)
		if want := []string{"early-due.example", "early-recent.example", "new.example"}; !slices.Equal(v.checked, want) {
			t.Fatalf("a minute later checked %v, want %v", v.checked, want)
		}
	})
}
