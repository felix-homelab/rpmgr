// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaygroup"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestTxHook: ConfigTx and WriteTx run the context's hook last, in their transaction, so its
// writes commit with theirs and its error rolls both back; a transaction that fails never runs
// it; read transactions and contexts without the hook never run it.
func TestTxHook(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		sys := storetest.SystemCtx(t)
		org := storetest.Org(t, db, "org-a")
		var ran int
		var fail error
		ctx := store.WithTxHook(sys, func(ctx context.Context, tx *ent.Tx) error {
			ran++
			if err := tx.GatewayGroup.Create().SetOrgID(org).SetName(fmt.Sprintf("hook%d", ran)).Exec(ctx); err != nil {
				return err
			}
			return fail
		})
		count := func(name string) int {
			return db.Client().GatewayGroup.Query().Where(gatewaygroup.Name(name)).CountX(sys)
		}
		create := func(name string) func(tx *ent.Tx) ([]string, error) {
			return func(tx *ent.Tx) ([]string, error) {
				return []string{org}, tx.GatewayGroup.Create().SetOrgID(org).SetName(name).Exec(ctx)
			}
		}

		if _, err := store.ConfigTx(ctx, db, create("config")); err != nil || ran != 1 || count("config") != 1 || count("hook1") != 1 {
			t.Fatalf("ConfigTx: %v, %d runs", err, ran)
		}
		if err := store.WriteTx(ctx, db, func(tx *ent.Tx) error { _, err := create("write")(tx); return err }); err != nil ||
			ran != 2 || count("write") != 1 || count("hook2") != 1 {
			t.Fatalf("WriteTx: %v, %d runs", err, ran)
		}
		fail = errors.New("the hook fails")
		if _, err := store.ConfigTx(ctx, db, create("rolled")); !errors.Is(err, fail) || count("rolled") != 0 || count("hook3") != 0 {
			t.Fatalf("a failing hook: %v", err)
		}
		fail = nil
		if _, err := store.ConfigTx(ctx, db, func(*ent.Tx) ([]string, error) { return nil, errors.New("no") }); err == nil || ran != 3 {
			t.Fatalf("a failing transaction ran the hook: %v, %d runs", err, ran)
		}
		if err := store.ReadTx(ctx, db, func(*ent.Tx, store.Revision) error { return nil }); err != nil || ran != 3 {
			t.Fatalf("ReadTx: %v, %d runs", err, ran)
		}
		if _, err := store.ConfigTx(store.WithoutTxHook(ctx), db, create("without")); err != nil || ran != 3 {
			t.Fatalf("WithoutTxHook: %v, %d runs", err, ran)
		}
		if _, err := store.ConfigTx(sys, db, create("plain")); err != nil || ran != 3 {
			t.Fatalf("no hook: %v, %d runs", err, ran)
		}
	})
}
