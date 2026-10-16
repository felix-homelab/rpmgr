// SPDX-License-Identifier: Apache-2.0

package accounts_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/accounts"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestSetInstanceAdmin_Concurrent (D95): revocations of the Instance Admin role at the same time,
// each the user's own, never leave the instance without an active Instance Admin, on every
// database: on PostgreSQL the second waits for the first's row locks.
func TestSetInstanceAdmin_Concurrent(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		sys := storetest.SystemCtx(t)
		m := &accounts.MFA{Accounts: accounts.New(db, sys, nil)}
		for round := range 10 {
			var ids []string
			for i := range 3 {
				ids = append(ids, db.Client().User.Create().SetEmail(fmt.Sprintf("r%d-%d@example.com", round, i)).
					SetDisplayName("x").SetInstanceAdmin(true).SaveX(sys).ID)
			}
			var wg sync.WaitGroup
			errs := make(chan error, len(ids))
			for _, id := range ids {
				wg.Go(func() {
					if _, err := m.SetInstanceAdmin(context.Background(), id, false, id); err != nil {
						errs <- err
					}
				})
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if !errors.Is(err, accounts.ErrLastInstanceAdmin) {
					t.Fatalf("round %d: %v", round, err)
				}
			}
			if n := db.Client().User.Query().Where(user.InstanceAdmin(true), user.StatusEQ(user.StatusActive)).CountX(sys); n != 1 {
				t.Fatalf("round %d: %d active Instance Admins, want 1", round, n)
			}
			db.Client().User.Update().SetInstanceAdmin(false).ExecX(sys)
		}
	})
}

// TestRecovery_LockOrder (D95): removals of second factors and reset links for the members of an
// org, made at once, write the instance's audit log and the org's in the same order, so that they
// never deadlock on PostgreSQL.
func TestRecovery_LockOrder(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		sys := storetest.SystemCtx(t)
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		kek, err := secret.NewKEK(key)
		if err != nil {
			t.Fatal(err)
		}
		sealer, err := secret.NewSealer(kek)
		if err != nil {
			t.Fatal(err)
		}
		m := &accounts.MFA{Accounts: accounts.New(db, sys, nil), Sealer: sealer}
		org := storetest.Org(t, db, "org-a")
		admin := db.Client().User.Create().SetEmail("admin@example.com").SetDisplayName("a").SaveX(sys).ID
		var wg sync.WaitGroup
		errs := make(chan error, 200)
		for i := range 6 {
			u := db.Client().User.Create().SetEmail(fmt.Sprintf("u%d@example.com", i)).SetDisplayName("u").SaveX(sys).ID
			wg.Go(func() {
				for range 8 {
					if _, _, err := m.EnrollTOTP(u, "rpmgr test"); err != nil {
						errs <- err
						continue
					}
					if err := m.RemoveTOTP(u, admin, nil, org); err != nil {
						errs <- err
					}
				}
			})
			wg.Go(func() {
				for range 8 {
					if _, err := m.ResetLink(u, admin, org); err != nil {
						errs <- err
					}
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})
}
