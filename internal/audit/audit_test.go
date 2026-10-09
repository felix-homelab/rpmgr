// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/auditentry"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// env is an initialised database with two orgs.
type env struct {
	db   *store.DB
	a, b string
}

func setup(t *testing.T, f func(t *testing.T, e env)) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		storetest.Init(t, db)
		f(t, env{db: db, a: storetest.Org(t, db, "org-a"), b: storetest.Org(t, db, "org-b")})
	})
}

func login(org, user string) audit.Entry {
	return audit.Entry{OrgID: org, ActorType: audit.ActorUser, ActorID: user, AuthMethod: "password",
		IP: "192.0.2.10", Action: "session.login", Result: audit.Success}
}

func record(t *testing.T, db *store.DB, e audit.Entry) audit.Entry {
	t.Helper()
	out, err := audit.Record(context.Background(), db, e)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func verify(t *testing.T, db *store.DB, org string) (audit.Head, error) {
	t.Helper()
	return audit.Verify(storetest.SystemCtx(t), db, org)
}

func wantHead(t *testing.T, db *store.DB, org string, seq int64) audit.Head {
	t.Helper()
	h, err := verify(t, db, org)
	if err != nil {
		t.Fatalf("chain %q: %v", org, err)
	}
	if h.Seq != seq {
		t.Fatalf("chain %q has %d entries, want %d", org, h.Seq, seq)
	}
	return h
}

func TestAppend_ChainsPerOrgAndInstance(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		if h := wantHead(t, e.db, e.a, 0); !bytes.Equal(h.Hash, audit.Genesis(e.a)) {
			t.Fatal("an empty chain's head is not its genesis hash")
		}
		a1 := record(t, e.db, login(e.a, "usr_1"))
		b1 := record(t, e.db, login(e.b, "usr_2"))
		a2 := record(t, e.db, login(e.a, "usr_1"))
		i1 := record(t, e.db, audit.Entry{ActorType: audit.ActorSystem, ActorID: "local-cli",
			Action: "kek.rotate", Result: audit.Success})
		if a1.Seq != 1 || a2.Seq != 2 || b1.Seq != 1 || i1.Seq != 1 {
			t.Fatalf("seqs a=%d,%d b=%d instance=%d; want one sequence per chain", a1.Seq, a2.Seq, b1.Seq, i1.Seq)
		}
		if !bytes.Equal(a1.PrevHash, audit.Genesis(e.a)) || !bytes.Equal(a2.PrevHash, a1.Hash) {
			t.Fatal("org A's entries are not linked")
		}
		if bytes.Equal(audit.Genesis(e.a), audit.Genesis(e.b)) || !ids.Valid("aud", a1.ID) {
			t.Fatal("genesis hashes repeat, or the ID is not an aud_ ID")
		}
		if h := wantHead(t, e.db, e.a, 2); !bytes.Equal(h.Hash, a2.Hash) {
			t.Fatal("org A's head is not its last entry")
		}
		wantHead(t, e.db, e.b, 1)
		wantHead(t, e.db, "", 1)
		if a1.Time.Location() != time.UTC || a1.Time.Nanosecond()%1000 != 0 {
			t.Errorf("time %v: want UTC in whole microseconds", a1.Time)
		}
	})
}

// TestVerify_DetectsTampering edits the database the way an attacker without the checkpoint
// signatures would, and expects verification to name the first entry that does not fit.
func TestVerify_DetectsTampering(t *testing.T) {
	cases := []struct {
		name    string
		tamper  func(t *testing.T, e env, x exec)
		chain   func(e env) string
		wantSeq int64
	}{
		{"modified field", func(t *testing.T, e env, x exec) {
			x(t, "UPDATE audit_log SET ip = '198.51.100.1' WHERE org_id = $1 AND seq = 3", e.a)
		}, orgA, 3},
		{"modified prev_hash", func(t *testing.T, e env, x exec) {
			x(t, "UPDATE audit_log SET prev_hash = hash WHERE org_id = $1 AND seq = 2", e.a)
		}, orgA, 2},
		{"modified entry with its hash recomputed", func(t *testing.T, e env, x exec) {
			ent3 := entryAt(t, e, e.a, 3)
			ent3.Action = "session.logout"
			x(t, "UPDATE audit_log SET action = $1, hash = $2 WHERE org_id = $3 AND seq = 3",
				ent3.Action, audit.ChainHash(ent3.PrevHash, ent3), e.a)
		}, orgA, 4},
		{"modified entry relinked to the next", func(t *testing.T, e env, x exec) {
			ent3 := entryAt(t, e, e.a, 3)
			ent3.Action = "session.logout"
			h := audit.ChainHash(ent3.PrevHash, ent3)
			x(t, "UPDATE audit_log SET action = $1, hash = $2 WHERE org_id = $3 AND seq = 3", ent3.Action, h, e.a)
			x(t, "UPDATE audit_log SET prev_hash = $1 WHERE org_id = $2 AND seq = 4", h, e.a)
		}, orgA, 4},
		{"deleted entry", func(t *testing.T, e env, x exec) {
			x(t, "DELETE FROM audit_log WHERE org_id = $1 AND seq = 3", e.a)
		}, orgA, 3},
		{"deleted tail", func(t *testing.T, e env, x exec) {
			x(t, "DELETE FROM audit_log WHERE org_id = $1 AND seq = 5", e.a)
		}, orgA, 5},
		{"deleted entries and head", func(t *testing.T, e env, x exec) {
			x(t, "DELETE FROM audit_log WHERE org_id = $1 AND seq >= 4", e.a)
			x(t, "DELETE FROM audit_heads WHERE chain = $1", e.a)
		}, orgA, 3},
		{"every entry deleted, head kept", func(t *testing.T, e env, x exec) {
			x(t, "DELETE FROM audit_log WHERE org_id = $1", e.a)
		}, orgA, 5},
		{"reordered entries", func(t *testing.T, e env, x exec) {
			x(t, "UPDATE audit_log SET seq = 100 WHERE org_id = $1 AND seq = 2", e.a)
			x(t, "UPDATE audit_log SET seq = 2 WHERE org_id = $1 AND seq = 4", e.a)
			x(t, "UPDATE audit_log SET seq = 4 WHERE org_id = $1 AND seq = 100", e.a)
		}, orgA, 2},
		{"entry moved to another org", func(t *testing.T, e env, x exec) {
			x(t, "UPDATE audit_log SET org_id = $1, seq = 6 WHERE org_id = $2 AND seq = 5", e.b, e.a)
		}, orgB, 6},
		{"instance entry moved into an org", func(t *testing.T, e env, x exec) {
			x(t, "UPDATE audit_log SET org_id = $1, seq = 6 WHERE org_id IS NULL AND seq = 2", e.a)
		}, instance, 2},
		{"head rewound", func(t *testing.T, e env, x exec) {
			x(t, "UPDATE audit_heads SET seq = 4 WHERE chain = $1", e.a)
		}, orgA, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setup(t, func(t *testing.T, e env) {
				for i := 0; i < 5; i++ {
					record(t, e.db, login(e.a, "usr_1"))
					record(t, e.db, login(e.b, "usr_2"))
					record(t, e.db, audit.Entry{ActorType: audit.ActorSystem, ActorID: "job",
						Action: "job.run", Result: audit.Success})
				}
				x := func(t *testing.T, q string, args ...any) {
					t.Helper()
					if _, err := e.db.Writer.ExecContext(context.Background(), q, args...); err != nil {
						t.Fatal(err)
					}
				}
				tc.tamper(t, e, x)
				org := tc.chain(e)
				_, err := verify(t, e.db, org)
				var ce *audit.ChainError
				if !errors.As(err, &ce) || !errors.Is(err, audit.ErrBroken) {
					t.Fatalf("Verify after tampering: %v, want a ChainError", err)
				}
				if ce.Seq != tc.wantSeq {
					t.Errorf("broken at %d (%s), want %d", ce.Seq, ce.Problem, tc.wantSeq)
				}
			})
		})
	}
}

type exec func(t *testing.T, q string, args ...any)

func orgA(e env) string                { return e.a }
func orgB(e env) string                { return e.b }
func instance(env) string              { return "" }
func sys(t *testing.T) context.Context { return storetest.SystemCtx(t) }

// entryAt reads an entry through Ent and converts it to the form the hash covers.
func entryAt(t *testing.T, e env, org string, seq int64) audit.Entry {
	t.Helper()
	r := e.db.Client().AuditEntry.Query().
		Where(auditentry.OrgID(org), auditentry.Seq(seq)).OnlyX(sys(t))
	return audit.Entry{ID: r.ID, OrgID: org, Seq: r.Seq, PrevHash: r.PrevHash, Hash: r.Hash,
		Time: r.Ts, ActorType: audit.ActorType(r.ActorType), ActorID: r.ActorID,
		CredentialID: r.CredentialID, AuthMethod: r.AuthMethod, IP: r.IP, UserAgent: r.UserAgent,
		RequestID: r.RequestID, Action: r.Action, TargetType: r.TargetType, TargetID: r.TargetID,
		Result: audit.Result(r.Result), Diff: r.Diff, Reason: r.Reason}
}

// TestAppend_ConcurrentStaysLinear: concurrent appends to two chains, some inside configuration
// transactions that fail, leave both chains gap-free and verifiable.
func TestAppend_ConcurrentStaysLinear(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		const writers, perWriter = 8, 20
		var wg sync.WaitGroup
		errs := make(chan error, writers*perWriter)
		rejected := errors.New("rejected change")
		ctxs := map[string]context.Context{e.a: storetest.OrgCtx(t, e.a), e.b: storetest.OrgCtx(t, e.b)}
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				org := []string{e.a, e.b}[w%2]
				ctx := ctxs[org]
				for i := 0; i < perWriter; i++ {
					if i%4 != 3 {
						_, err := audit.Record(ctx, e.db, login(org, fmt.Sprintf("usr_%d", w)))
						errs <- err
						continue
					}
					_, err := store.ConfigTx(ctx, e.db, func(tx *ent.Tx) ([]string, error) {
						if _, err := audit.Append(ctx, tx, login(org, "usr_cfg")); err != nil {
							return nil, err
						}
						return nil, rejected
					})
					if !errors.Is(err, rejected) {
						errs <- fmt.Errorf("failing configuration transaction: %w", err)
					}
				}
			}(w)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		perChain := int64(writers / 2 * perWriter * 3 / 4)
		wantHead(t, e.db, e.a, perChain)
		wantHead(t, e.db, e.b, perChain)
	})
}

// TestAppend_CommitsWithTheChange: an entry appended in a configuration transaction commits with
// it, and a failed transaction leaves neither its entry nor a gap.
func TestAppend_CommitsWithTheChange(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		ctx := storetest.OrgCtx(t, e.a)
		change := func(fail bool) error {
			_, err := store.ConfigTx(ctx, e.db, func(tx *ent.Tx) ([]string, error) {
				g, err := tx.GatewayGroup.Create().SetOrgID(e.a).SetName(fmt.Sprintf("g-%v", fail)).Save(ctx)
				if err != nil {
					return nil, err
				}
				entry := login(e.a, "usr_1")
				entry.Action, entry.TargetType, entry.TargetID = "gateway_group.create", "gateway_group", g.ID
				if _, err := audit.Append(ctx, tx, entry); err != nil {
					return nil, err
				}
				if fail {
					return nil, errors.New("rejected")
				}
				return []string{g.ID}, nil
			})
			return err
		}
		if err := change(true); err == nil {
			t.Fatal("the failing change committed")
		}
		wantHead(t, e.db, e.a, 0)
		if err := change(false); err != nil {
			t.Fatal(err)
		}
		wantHead(t, e.db, e.a, 1)
		if got := entryAt(t, e, e.a, 1); got.Action != "gateway_group.create" {
			t.Errorf("entry 1 is %q", got.Action)
		}
	})
}

func TestAppend_RefusesInvalidEntries(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		bad := map[string]audit.Entry{
			"unknown actor type": {ActorType: "robot", ActorID: "r", Action: "x", Result: audit.Success},
			"user without ID":    {ActorType: audit.ActorUser, Action: "x", Result: audit.Success},
			"unknown result":     {ActorType: audit.ActorSystem, ActorID: "j", Action: "x", Result: "maybe"},
			"no action":          {ActorType: audit.ActorSystem, ActorID: "j", Result: audit.Success},
			"not an org ID":      {OrgID: "gwg_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R", ActorType: audit.ActorSystem, ActorID: "j", Action: "x", Result: audit.Success},
			"unknown org":        {OrgID: ids.New("org"), ActorType: audit.ActorSystem, ActorID: "j", Action: "x", Result: audit.Success},
		}
		for name, entry := range bad {
			if _, err := audit.Record(context.Background(), e.db, entry); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
		anon := audit.Entry{ActorType: audit.ActorAnonymous, IP: "203.0.113.9", Action: "session.login", Result: audit.Failure}
		record(t, e.db, anon)
		wantHead(t, e.db, "", 1)
		wantHead(t, e.db, e.a, 0)
	})
}

// TestAppend_Scope: an org scope appends to its own chain and the instance chain, never to another
// org's; reads through Ent are filtered like every org-owned table, and Ent cannot change entries.
func TestAppend_Scope(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		ctxA := storetest.OrgCtx(t, e.a)
		if _, err := audit.Record(ctxA, e.db, login(e.b, "usr_1")); !errors.Is(err, audit.ErrOutsideScope) {
			t.Fatalf("org A appending to org B: %v, want ErrOutsideScope", err)
		}
		record(t, e.db, login(e.b, "usr_2"))
		for _, org := range []string{e.a, ""} {
			if _, err := audit.Record(ctxA, e.db, login(org, "usr_1")); err != nil {
				t.Fatalf("org A appending to chain %q: %v", org, err)
			}
		}
		c := e.db.Client()
		if n := c.AuditEntry.Query().CountX(ctxA); n != 1 {
			t.Errorf("org A sees %d entries, want only its own", n)
		}
		if n := c.AuditHead.Query().CountX(ctxA); n != 1 {
			t.Errorf("org A sees %d heads, want only its own", n)
		}
		if n := c.AuditEntry.Query().CountX(sys(t)); n != 3 {
			t.Errorf("the system scope sees %d entries, want 3", n)
		}
		if _, err := c.AuditEntry.Query().Count(context.Background()); err == nil {
			t.Error("an Ent query without a scope succeeded")
		}
		if _, err := c.AuditEntry.Delete().Exec(sys(t)); err == nil {
			t.Error("Ent deleted audit entries")
		}
		if _, err := c.AuditEntry.Update().Where(auditentry.Seq(1)).Save(sys(t)); err == nil {
			t.Error("Ent updated audit entries")
		}
		if _, err := c.AuditHead.Update().SetSeq(0).Save(sys(t)); err == nil {
			t.Error("Ent updated audit heads")
		}
		err := c.AuditEntry.Create().SetSeq(9).SetPrevHash(nil).SetHash(nil).SetTs(time.Now()).
			SetActorType(auditentry.ActorTypeSystem).SetAction("x").SetResult(auditentry.ResultSuccess).Exec(sys(t))
		if err == nil {
			t.Error("Ent created an audit entry")
		}
		wantHead(t, e.db, e.a, 1)
		wantHead(t, e.db, e.b, 1)
		wantHead(t, e.db, "", 1)
	})
}

func TestVerify_Scope(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		ctxA := storetest.OrgCtx(t, e.a)
		if _, err := audit.Verify(ctxA, e.db, e.a); err != nil {
			t.Errorf("org A verifying its chain: %v", err)
		}
		for _, org := range []string{e.b, ""} {
			if _, err := audit.Verify(ctxA, e.db, org); !errors.Is(err, audit.ErrOutsideScope) {
				t.Errorf("org A verifying chain %q: %v, want ErrOutsideScope", org, err)
			}
		}
		if _, err := audit.Verify(context.Background(), e.db, e.a); err == nil {
			t.Error("Verify without a scope succeeded")
		}
	})
}

// TestAppend_CleansClientFields: text a client controls is stored as valid UTF-8 without NUL
// (PostgreSQL refuses both) and capped, and the chain still verifies on both dialects.
func TestAppend_CleansClientFields(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		entry := login(e.a, "usr_1")
		entry.UserAgent = "agent\x00\xff" + strings.Repeat("é", audit.MaxUserAgent)
		entry.RequestID = strings.Repeat("r", audit.MaxRequestID+1)
		entry.Diff = "{\"before\":{\"name\":\"a\x00\"}}"
		got := record(t, e.db, entry)
		if !utf8.ValidString(got.UserAgent) || strings.ContainsRune(got.UserAgent, 0) ||
			len(got.UserAgent) > audit.MaxUserAgent || !strings.HasPrefix(got.UserAgent, "agent\uFFFD\uFFFD") {
			t.Errorf("user agent stored as %q", got.UserAgent)
		}
		if len(got.RequestID) != audit.MaxRequestID {
			t.Errorf("request ID of %d bytes", len(got.RequestID))
		}
		if stored := entryAt(t, e, e.a, 1); stored.UserAgent != got.UserAgent {
			t.Error("the stored user agent differs from the hashed one")
		}
		wantHead(t, e.db, e.a, 1)
	})
}

// TestSystemScopes: a system scope is granted only together with its entry in the instance
// chain; when the entry cannot be written, the scope is refused.
func TestSystemScopes(t *testing.T) {
	setup(t, func(t *testing.T, e env) {
		ctx, err := authz.System(context.Background(), "ephemeral-purge", "purge disconnected connectors", audit.SystemScopes(e.db))
		if err != nil {
			t.Fatal(err)
		}
		if s, ok := authz.FromContext(ctx); !ok || !s.System() {
			t.Fatal("no system scope")
		}
		wantHead(t, e.db, "", 1)
		r := e.db.Client().AuditEntry.Query().Where(auditentry.OrgIDIsNil()).OnlyX(sys(t))
		if r.ActorType != auditentry.ActorTypeSystem || r.ActorID != "ephemeral-purge" ||
			r.Action != "system_scope.grant" || r.Reason != "purge disconnected connectors" {
			t.Errorf("recorded grant: %+v", r)
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := authz.System(cancelled, "job", "reason", audit.SystemScopes(e.db)); err == nil {
			t.Fatal("a system scope was granted although its audit entry failed")
		}
	})
}

// TestCanonical_FieldBoundaries: moving bytes between adjacent fields changes the encoding, and so
// does every field the hash covers.
func TestCanonical_FieldBoundaries(t *testing.T) {
	base := audit.Entry{ID: "aud_x", OrgID: "org_x", Seq: 7, Time: time.UnixMicro(1_700_000_000_000_000),
		ActorType: audit.ActorUser, ActorID: "ab", CredentialID: "c", Action: "route.update", Result: audit.Success}
	shifted := base
	shifted.ActorID, shifted.CredentialID = "a", "bc"
	if bytes.Equal(audit.Canonical(base), audit.Canonical(shifted)) {
		t.Fatal("shifting a byte between fields keeps the encoding")
	}
	mutations := map[string]func(*audit.Entry){
		"id":          func(e *audit.Entry) { e.ID = "aud_y" },
		"org":         func(e *audit.Entry) { e.OrgID = "" },
		"seq":         func(e *audit.Entry) { e.Seq++ },
		"time":        func(e *audit.Entry) { e.Time = e.Time.Add(time.Microsecond) },
		"actor type":  func(e *audit.Entry) { e.ActorType = audit.ActorAgent },
		"actor":       func(e *audit.Entry) { e.ActorID = "x" },
		"credential":  func(e *audit.Entry) { e.CredentialID = "x" },
		"auth method": func(e *audit.Entry) { e.AuthMethod = "x" },
		"ip":          func(e *audit.Entry) { e.IP = "x" },
		"user agent":  func(e *audit.Entry) { e.UserAgent = "x" },
		"request":     func(e *audit.Entry) { e.RequestID = "x" },
		"action":      func(e *audit.Entry) { e.Action = "x" },
		"target type": func(e *audit.Entry) { e.TargetType = "x" },
		"target":      func(e *audit.Entry) { e.TargetID = "x" },
		"result":      func(e *audit.Entry) { e.Result = audit.Denied },
		"diff":        func(e *audit.Entry) { e.Diff = "x" },
		"reason":      func(e *audit.Entry) { e.Reason = "x" },
	}
	seen := map[string]string{string(audit.Canonical(base)): "base"}
	for name, mutate := range mutations {
		e := base
		mutate(&e)
		enc := string(audit.Canonical(e))
		if other, dup := seen[enc]; dup {
			t.Errorf("changing %s gives the encoding of %s", name, other)
		}
		seen[enc] = name
	}
}

// TestRecord_WithoutTxHook: Record never runs a request's transaction hook, which belongs to the
// change the request makes.
func TestRecord_WithoutTxHook(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	storetest.Init(t, db)
	ran := false
	ctx := store.WithTxHook(context.Background(), func(context.Context, *ent.Tx) error { ran = true; return nil })
	if _, err := audit.Record(ctx, db, audit.Entry{ActorType: audit.ActorAnonymous, Action: "login.fail", Result: audit.Failure}); err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Fatal("Record ran the hook")
	}
}
