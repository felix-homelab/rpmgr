// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/auditsink"
	"github.com/felix-homelab/rpmgr/internal/auditsink/syslogtest"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// syslogSink makes a syslog sink for address, trusting the CA bundle ca.
func (e *sinkEnv) syslogSink(name, address, ca string, entries bool) *ent.AuditSink {
	e.t.Helper()
	return e.db.Client().AuditSink.Create().SetKind("syslog").SetName(name).SetSettings(map[string]string{"address": address, "ca": ca}).
		SetEntries(entries).SaveX(e.sys)
}

// itemIDs are the IDs of the JSON in the messages, in order.
func itemIDs(t *testing.T, msgs []string) []string {
	t.Helper()
	var out []string
	for _, m := range msgs {
		var b struct{ ID string }
		if err := json.Unmarshal([]byte(m[strings.Index(m, "{"):]), &b); err != nil {
			t.Fatalf("a message without JSON: %q", m)
		}
		out = append(out, b.ID)
	}
	return out
}

// TestAuditSink_SyslogShipsAndResumes (#936): a syslog sink ships every chain's checkpoints and
// entries as RFC 5424 messages; a server of another CA is refused and gets nothing; a connection
// the server drops in the middle of a batch fails the batch, which goes again from the cursor, so
// the receiver has every item at least once and the backlog ends at 0.
func TestAuditSink_SyslogShipsAndResumes(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newSinkEnv(t, db)
		org := storetest.Org(t, db, "org-a")
		srv := syslogtest.New(t, 0)
		wrong := e.syslogSink("wrong-ca", srv.Addr, syslogtest.OtherCA(t), true)
		s := e.syslogSink("syslog", srv.Addr, srv.CA, true)
		want := map[string]bool{}
		for range 3 {
			en := e.appendTo(org)
			want[en.ID] = true
			want[e.checkpoint(org, en)] = true
		}
		en := e.appendTo("")
		want[en.ID], want[e.checkpoint("", en)] = true, true

		// The server drops the first connection after its first message, in the middle of the batch.
		srv.SetDrop(1)
		e.mustRun()
		if got := e.status(s); got.LastError == "" || !strings.Contains(got.LastError, "syslog server") || got.LastSuccessAt != nil {
			t.Fatalf("after a dropped connection: error %q, last success %v", got.LastError, got.LastSuccessAt)
		}
		if b := e.backlog("syslog"); b.Items == 0 {
			t.Fatalf("a dropped batch left no backlog: %+v", b)
		}
		if got := e.status(wrong); !strings.Contains(got.LastError, "not signed by a CA of the sink's bundle") {
			t.Fatalf("a server of another CA: %q", got.LastError)
		}

		// The server is well again: the sink resends from its cursor, so no item is missing.
		srv.SetDrop(0)
		e.clock = e.clock.Add(auditsink.BackoffMax)
		e.mustRun()
		got := map[string]bool{}
		ids := itemIDs(t, srv.Messages())
		for _, id := range ids {
			got[id] = true
		}
		for id := range want {
			if !got[id] {
				t.Errorf("item %s never reached the syslog server (%d messages)", id, len(ids))
			}
		}
		if b := e.backlog("syslog"); b.Items != 0 || !b.Oldest.IsZero() {
			t.Fatalf("backlog %+v after catching up", b)
		}
		if st := e.status(s); st.LastError != "" || st.LastSuccessAt == nil {
			t.Fatalf("status after catching up: error %q, last success %v", st.LastError, st.LastSuccessAt)
		}
		if b := e.backlog("wrong-ca"); b.Items == 0 {
			t.Fatal("the sink of another CA is not behind")
		}

		// Nothing new: no connection, no message.
		conns, n := srv.Connections(), len(srv.Messages())
		e.clock = e.clock.Add(auditsink.Every)
		e.mustRun()
		if srv.Connections() != conns+0 && len(srv.Messages()) != n {
			t.Errorf("a caught-up sink shipped again")
		}
	})
}

// TestAuditSink_SyslogOversizeEntry (#936): an entry too long for one syslog message is shipped
// with its diff left out and marked truncated, so it never holds the cursor.
func TestAuditSink_SyslogOversizeEntry(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newSinkEnv(t, db)
		srv := syslogtest.New(t, 0)
		s := e.syslogSink("syslog", srv.Addr, srv.CA, true)
		big, err := audit.Record(context.Background(), e.db, audit.Entry{ActorType: audit.ActorUser, ActorID: "usr_ada", Action: "route.update",
			TargetType: "route", TargetID: "rte_1", Result: audit.Success, Diff: strings.Repeat("x", 20000)})
		if err != nil {
			t.Fatal(err)
		}
		e.checkpoint("", big)
		e.mustRun()
		var found bool
		for _, m := range srv.Messages() {
			if len(m) > auditsink.MaxSyslogMessage {
				t.Errorf("a message of %d octets", len(m))
			}
			if strings.Contains(m, big.ID) {
				found = strings.Contains(m, `"truncated":true`) && !strings.Contains(m, "xxxx")
			}
		}
		if !found {
			t.Fatalf("the oversize entry did not arrive truncated: %d messages", len(srv.Messages()))
		}
		if b := e.backlog("syslog"); b.Items != 0 || e.status(s).LastError != "" {
			t.Fatalf("backlog %+v, error %q", b, e.status(s).LastError)
		}
	})
}

// TestAuditSink_SyslogBacklogNeverBlocksAppend (#936): the syslog clause of
// TestAuditSink_BacklogNeverBlocksAppend. A server that accepts the connection and never answers
// the handshake holds the pass; appends commit at their usual pace meanwhile; once the server is
// back the sink ships from its cursor.
func TestAuditSink_SyslogBacklogNeverBlocksAppend(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newSinkEnv(t, db)
		org := storetest.Org(t, db, "org-a")
		srv := syslogtest.New(t, 0)
		hole, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = hole.Close() })
		held := make(chan net.Conn, 1)
		go func() {
			if c, err := hole.Accept(); err == nil {
				held <- c
			}
		}()
		s := e.syslogSink("syslog", hole.Addr().String(), srv.CA, true)
		e.checkpoint(org, e.appendTo(org))

		var wg sync.WaitGroup
		wg.Go(func() {
			if err := e.run(); err != nil {
				t.Errorf("pass: %v", err)
			}
		})
		c := <-held // the sink waits for the handshake
		var worst time.Duration
		for range 25 {
			start := time.Now()
			e.appendTo(org)
			e.appendTo("")
			worst = max(worst, time.Since(start))
		}
		if worst > time.Second {
			t.Errorf("an append took %v while a syslog server hung", worst)
		}
		_ = c.Close()
		wg.Wait()
		if b := e.backlog("syslog"); b.Items == 0 || b.Oldest.IsZero() {
			t.Fatalf("backlog %+v, want items waiting", b)
		}
		if got := e.status(s); got.LastError == "" || got.LastSuccessAt != nil {
			t.Fatalf("status: error %q, last success %v", got.LastError, got.LastSuccessAt)
		}

		db.Client().AuditSink.UpdateOne(s).SetSettings(map[string]string{"address": srv.Addr, "ca": srv.CA}).ExecX(e.sys)
		e.clock = e.clock.Add(auditsink.BackoffMax)
		e.mustRun()
		if b := e.backlog("syslog"); b.Items != 0 || !b.Oldest.IsZero() {
			t.Fatalf("backlog %+v after the server came back, want none", b)
		}
	})
}

// TestAuditSink_BacklogCountsInSQL (#1026 review): a sink without a cursor, and a sink behind
// another, are counted per chain from the tables, with the right oldest time, for many chains.
func TestAuditSink_BacklogCountsInSQL(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := newSinkEnv(t, db)
		orgs := []string{storetest.Org(t, db, "org-a"), storetest.Org(t, db, "org-b"), storetest.Org(t, db, "org-c")}
		e.sink("fresh", "/fresh", false)
		e.sink("partial", "/partial", false)
		var first time.Time
		for i, org := range orgs {
			for range 4 {
				en := e.appendTo(org)
				e.checkpoint(org, en)
				if i == 0 && first.IsZero() {
					first = time.Now()
				}
			}
		}
		// "partial" has a cursor on the first org that holds its first two checkpoints.
		cps := db.Client().AuditSink.Query().AllX(e.sys)
		for _, s := range cps {
			if s.Name != "partial" {
				continue
			}
			rows, err := db.Client().QueryContext(e.sys, "SELECT seq FROM audit_checkpoints WHERE org_id = $1 ORDER BY seq LIMIT 1 OFFSET 1", orgs[0])
			if err != nil {
				t.Fatal(err)
			}
			var seq int64
			if !rows.Next() || rows.Scan(&seq) != nil {
				t.Fatal("no second checkpoint")
			}
			_ = rows.Close()
			db.Client().AuditSinkCursor.Create().SetSinkID(s.ID).SetChain(orgs[0]).SetCheckpointSeq(seq).SaveX(e.sys)
		}
		fresh, partial := e.backlog("fresh"), e.backlog("partial")
		if fresh.Items != 12 || fresh.Oldest.IsZero() || len(fresh.Chains) != len(orgs) {
			t.Errorf("a sink without a cursor: %+v", fresh)
		}
		if partial.Items != 10 {
			t.Errorf("a sink behind by two checkpoints on one chain: %+v", partial)
		}
		for _, c := range partial.Chains {
			if want := map[bool]int64{true: 2, false: 4}[c.Chain == orgs[0]]; c.Items != want {
				t.Errorf("chain %s: %d items, want %d", c.Chain, c.Items, want)
			}
		}
	})
}
