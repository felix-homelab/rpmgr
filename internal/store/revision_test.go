// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

const testTrustDomain = "rpmgr-7f3k2q6m" // base32: a–z and 2–7

func initialised(t *testing.T, db *store.DB) store.Revision {
	t.Helper()
	rev, err := store.InitInstance(systemCtx(t), db, testTrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

func TestInitInstance(t *testing.T) {
	forEachDialect(t, func(t *testing.T, _ *ent.Client, db *store.DB) {
		ctx := systemCtx(t)
		if _, err := store.InitInstance(ctx, db, "not-a-trust-domain"); err == nil {
			t.Error("invalid trust domain accepted")
		}
		if _, err := store.InitInstance(context.Background(), db, testTrustDomain); err == nil {
			t.Error("InitInstance without a scope succeeded")
		}
		rev := initialised(t, db)
		u, err := uuid.Parse(rev.DBEpoch)
		if err != nil || u.Version() != 7 || rev.Seq != 0 {
			t.Fatalf("revision after init: %+v (%v); want a UUIDv7 epoch and seq 0", rev, err)
		}
		if _, err := store.InitInstance(ctx, db, testTrustDomain); !errors.Is(err, store.ErrInitialised) {
			t.Errorf("second InitInstance: %v, want ErrInitialised", err)
		}
		e1, err := store.NewEpoch(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		e2, err := store.NewEpoch(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if e1 == rev.DBEpoch || e1 == e2 {
			t.Errorf("epochs repeat: %s, %s, %s", rev.DBEpoch, e1, e2)
		}
	})
}

func TestNewEpochNeedsInstance(t *testing.T) {
	forEachDialect(t, func(t *testing.T, _ *ent.Client, db *store.DB) {
		if _, err := store.NewEpoch(systemCtx(t), db); err == nil {
			t.Error("NewEpoch on an uninitialised database succeeded")
		}
	})
}

func TestConfigTx_RecordsRevision(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, db *store.DB) {
		init := initialised(t, db)
		a, _ := seed(t, c)
		ctxA := orgCtx(t, a.org)
		rev, err := store.ConfigTx(ctxA, db, func(tx *ent.Tx) ([]string, error) {
			g, err := tx.GatewayGroup.Create().SetOrgID(a.org).SetName("us").Save(ctxA)
			if err != nil {
				return nil, err
			}
			return []string{g.ID}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if rev.Seq != 1 || rev.DBEpoch != init.DBEpoch {
			t.Fatalf("revision %+v, want seq 1 in epoch %s", rev, init.DBEpoch)
		}
		r := c.ConfigRevision.GetX(systemCtx(t), 1)
		if r.Actor != "usr_of_"+a.org || r.DbEpoch != init.DBEpoch || len(r.ChangedResources) != 1 {
			t.Errorf("recorded revision: %+v", r)
		}
	})
}

func TestConfigTx_FailureLeavesNothing(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, db *store.DB) {
		initialised(t, db)
		a, _ := seed(t, c)
		ctxA := orgCtx(t, a.org)
		boom := errors.New("boom")
		_, err := store.ConfigTx(ctxA, db, func(tx *ent.Tx) ([]string, error) {
			if _, err := tx.GatewayGroup.Create().SetOrgID(a.org).SetName("lost").Save(ctxA); err != nil {
				return nil, err
			}
			return nil, boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("ConfigTx: %v, want the error of fn", err)
		}
		sys := systemCtx(t)
		if n := c.ConfigRevision.Query().CountX(sys); n != 0 {
			t.Errorf("%d revisions after a failed transaction", n)
		}
		if n := c.GatewayGroup.Query().CountX(sys); n != 2 {
			t.Errorf("the failed transaction's group was committed: %d groups", n)
		}
		rev, err := store.ConfigTx(ctxA, db, func(*ent.Tx) ([]string, error) { return nil, nil })
		if err != nil || rev.Seq != 1 {
			t.Errorf("next revision after the failure: %+v, %v; want seq 1", rev, err)
		}
	})
}

func TestConfigTx_NeedsScopeAndInstance(t *testing.T) {
	forEachDialect(t, func(t *testing.T, _ *ent.Client, db *store.DB) {
		noop := func(*ent.Tx) ([]string, error) { return nil, nil }
		if _, err := store.ConfigTx(systemCtx(t), db, noop); err == nil {
			t.Error("ConfigTx on an uninitialised database succeeded")
		}
		initialised(t, db)
		if _, err := store.ConfigTx(context.Background(), db, noop); err == nil {
			t.Error("ConfigTx without a scope succeeded")
		}
	})
}

// TestConfigTx_CommitOrderIsRevisionOrder: concurrent configuration transactions, some failing,
// get unique, gap-free revisions, and no reader ever sees a higher revision before a lower one:
// in every snapshot the number of revisions equals the highest seq.
func TestConfigTx_CommitOrderIsRevisionOrder(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, db *store.DB) {
		initialised(t, db)
		a, _ := seed(t, c)
		ctxA := orgCtx(t, a.org)
		const writers, perWriter = 8, 15
		var done atomic.Bool
		var readerErr atomic.Value
		var snapshots atomic.Int64
		var readers sync.WaitGroup
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !done.Load() {
				err := store.ReadTx(ctxA, db, func(tx *ent.Tx, rev store.Revision) error {
					n, err := tx.ConfigRevision.Query().Count(ctxA)
					if err != nil {
						return err
					}
					if int64(n) != rev.Seq {
						return fmt.Errorf("snapshot at seq %d holds %d revisions", rev.Seq, n)
					}
					return nil
				})
				if err != nil {
					readerErr.Store(err)
					return
				}
				snapshots.Add(1)
			}
		}()
		var failed atomic.Int64
		var writersWG sync.WaitGroup
		for w := 0; w < writers; w++ {
			writersWG.Add(1)
			go func(w int) {
				defer writersWG.Done()
				for i := 0; i < perWriter; i++ {
					_, err := store.ConfigTx(ctxA, db, func(tx *ent.Tx) ([]string, error) {
						time.Sleep(time.Duration((w*7+i)%3) * time.Millisecond)
						if i%5 == 4 {
							return nil, errors.New("rejected change")
						}
						g, err := tx.GatewayGroup.Create().SetOrgID(a.org).SetName(fmt.Sprintf("g-%d-%d", w, i)).Save(ctxA)
						if err != nil {
							return nil, err
						}
						return []string{g.ID}, nil
					})
					if err != nil {
						failed.Add(1)
					}
				}
			}(w)
		}
		writersWG.Wait()
		done.Store(true)
		readers.Wait()
		if err, _ := readerErr.Load().(error); err != nil {
			t.Fatal(err)
		}
		committed := int64(writers*perWriter) - failed.Load()
		if failed.Load() != int64(writers*perWriter/5) {
			t.Fatalf("%d transactions failed, want exactly the %d rejected ones", failed.Load(), writers*perWriter/5)
		}
		sys := systemCtx(t)
		ids := c.ConfigRevision.Query().IDsX(sys)
		if int64(len(ids)) != committed {
			t.Fatalf("%d revisions, want %d", len(ids), committed)
		}
		seen := map[int64]bool{}
		for _, id := range ids {
			seen[id] = true
		}
		for s := int64(1); s <= committed; s++ {
			if !seen[s] {
				t.Fatalf("revision %d missing: revisions are not gap-free", s)
			}
		}
		if snapshots.Load() == 0 {
			t.Fatal("the reader took no snapshot")
		}
	})
}

// TestReadTx_Snapshot: a read transaction keeps its snapshot and its revision label while a
// configuration transaction commits.
func TestReadTx_Snapshot(t *testing.T) {
	forEachDialect(t, func(t *testing.T, c *ent.Client, db *store.DB) {
		initialised(t, db)
		a, _ := seed(t, c)
		ctxA := orgCtx(t, a.org)
		err := store.ReadTx(ctxA, db, func(tx *ent.Tx, rev store.Revision) error {
			before, err := tx.GatewayGroup.Query().Count(ctxA)
			if err != nil {
				return err
			}
			if _, err := store.ConfigTx(ctxA, db, func(w *ent.Tx) ([]string, error) {
				return nil, w.GatewayGroup.Create().SetOrgID(a.org).SetName("during").Exec(ctxA)
			}); err != nil {
				return err
			}
			after, err := tx.GatewayGroup.Query().Count(ctxA)
			if err != nil {
				return err
			}
			if before != after || rev.Seq != 0 {
				return fmt.Errorf("snapshot changed: %d then %d groups at seq %d", before, after, rev.Seq)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if n := c.GatewayGroup.Query().CountX(ctxA); n != 2 {
			t.Errorf("after the read transaction: %d groups in org A, want 2", n)
		}
	})
}
