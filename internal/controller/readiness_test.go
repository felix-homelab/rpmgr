// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/resourcestatus"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func notReady(id string, reason agentv1.NotReadyReason, detail string) *agentv1.ResourceStatus {
	return &agentv1.ResourceStatus{ResourceId: id, Reason: reason, Detail: detail}
}

func statusMsg(complete bool, rs ...*agentv1.ResourceStatus) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{Readiness: rs, ReadinessComplete: complete}}}
}

// TestResourceStatus: the controller keeps what an agent reports not ready: the whole set from an
// Applied of a snapshot it sent, changes from a Status, the whole set again from a complete one; a
// reason that did not change keeps its since; an Applied of a snapshot it did not send is ignored;
// an agent cannot make it keep more than 1024 rows or longer text.
func TestResourceStatus(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := pushEnv(t, db)
		sys := storetest.SystemCtx(t)
		cert, id := e.agentCert(t)
		st := e.open(t, testCtx(t), cert, hello("0.1.0"))
		if recv(t, st).GetWelcome() == nil {
			t.Fatal("no Welcome")
		}
		signed, snap := e.recvSnapshot(t, st, id)
		rows := func() map[string]*ent.ResourceStatus {
			out := map[string]*ent.ResourceStatus{}
			for _, r := range db.Client().ResourceStatus.Query().Where(resourcestatus.AgentID(id.ID)).AllX(sys) {
				out[r.ResourceID] = r
			}
			return out
		}
		// waitRows sends m, then a marker Status, and waits for the marker: messages are handled in
		// order, so m has been recorded then.
		marker := 0
		waitRows := func(m *agentv1.AgentMessage) map[string]*ent.ResourceStatus {
			t.Helper()
			send(t, st, m)
			marker++
			name := fmt.Sprintf("marker-%d", marker)
			send(t, st, statusMsg(false, notReady(name, agentv1.NotReadyReason_NOT_READY_REASON_ENVIRONMENT, "")))
			deadline := time.Now().Add(10 * time.Second)
			for rows()[name] == nil {
				if time.Now().After(deadline) {
					t.Fatal("the marker was never recorded")
				}
				time.Sleep(10 * time.Millisecond)
			}
			send(t, st, statusMsg(false, notReady(name, agentv1.NotReadyReason_NOT_READY_REASON_UNSPECIFIED, "")))
			for rows()[name] != nil {
				time.Sleep(10 * time.Millisecond)
			}
			return rows()
		}
		blocked, port := agentv1.NotReadyReason_NOT_READY_REASON_BLOCKED_BY_LOCAL_POLICY, agentv1.NotReadyReason_NOT_READY_REASON_PORT_IN_USE

		a := applied(signed, snap.GetRevision())
		a.GetApplied().NotReady = []*agentv1.ResourceStatus{notReady("r1", blocked, "10.0.0.5:5432"), notReady("r2", port, "port 5432")}
		got := waitRows(a)
		if len(got) != 2 || got["r1"].Reason != "NOT_READY_REASON_BLOCKED_BY_LOCAL_POLICY" || got["r1"].Detail != "10.0.0.5:5432" ||
			got["r1"].OrgID != id.Org {
			t.Fatalf("after Applied: %v", got)
		}
		since2 := got["r2"].Since

		stranger := applied(&agentv1.Signed{Payload: []byte("not sent")}, snap.GetRevision())
		stranger.GetApplied().NotReady = []*agentv1.ResourceStatus{notReady("r9", port, "")}
		if got := waitRows(stranger); len(got) != 2 || got["r9"] != nil {
			t.Fatalf("an Applied of a snapshot not sent was recorded: %v", got)
		}

		got = waitRows(statusMsg(false, notReady("r1", agentv1.NotReadyReason_NOT_READY_REASON_UNSPECIFIED, ""), notReady("r2", port, "port 5432"),
			notReady("r3", agentv1.NotReadyReason_NOT_READY_REASON_TRANSPORT_UNAVAILABLE, "quic")))
		if len(got) != 2 || got["r1"] != nil || !got["r2"].Since.Equal(since2) || got["r3"] == nil {
			t.Fatalf("after a change: %v", got)
		}
		got = waitRows(statusMsg(false, notReady("r2", port, "port 5433")))
		if got["r2"].Detail != "port 5433" || !got["r2"].Since.After(since2) {
			t.Fatalf("a changed detail: %v", got["r2"])
		}
		if got = waitRows(statusMsg(true, notReady("r3", agentv1.NotReadyReason_NOT_READY_REASON_TRANSPORT_UNAVAILABLE, "quic"))); len(got) != 1 || got["r3"] == nil {
			t.Fatalf("after a complete Status: %v", got)
		}
		if got = waitRows(statusMsg(true)); len(got) != 0 {
			t.Fatalf("after an empty complete Status: %v", got)
		}

		// The long one sorts first, so it is kept.
		flood := []*agentv1.ResourceStatus{notReady("a"+strings.Repeat("é", 400), port, strings.Repeat("x", 2000))}
		for i := range 1100 {
			flood = append(flood, notReady(fmt.Sprintf("f%04d", i), port, ""))
		}
		send(t, st, statusMsg(false, flood...))
		deadline := time.Now().Add(20 * time.Second)
		for len(rows()) < 1024 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		send(t, st, statusMsg(false, notReady("one-more", port, "")))
		time.Sleep(200 * time.Millisecond)
		got = rows()
		if len(got) != 1024 || got["one-more"] != nil {
			t.Fatalf("%d rows kept, one more %v", len(got), got["one-more"] != nil)
		}
		for rid, r := range got {
			if len(rid) > 512 || len(r.Detail) > 512 || !utf8.ValidString(rid) {
				t.Fatalf("an unclipped row: %d bytes, detail %d", len(rid), len(r.Detail))
			}
		}
		if got[clipped("a"+strings.Repeat("é", 400))] == nil {
			t.Fatal("the long resource ID was not kept, clipped")
		}
	})
}

// clipped is s cut to 512 bytes of valid UTF-8, as the controller stores agent text.
func clipped(s string) string { return strings.ToValidUTF8(s[:min(len(s), 512)], "") }

// TestDataSessions: each Status of a gateway replaces what the controller knows of its data
// sessions: one row per connector and transport, keeping when it was first heard of; a session
// no longer reported goes; a connector's report and an unknown transport are ignored; a gateway
// cannot make it keep more than 4096 rows.
func TestDataSessions(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := pushEnv(t, db)
		sys := storetest.SystemCtx(t)
		gwCert, gw := e.certOf(t, pki.KindGateway)
		conCert, _ := e.agentCert(t)
		gst := e.open(t, testCtx(t), gwCert, hello("0.1.0"))
		cst := e.open(t, testCtx(t), conCert, hello("0.1.0"))
		for _, st := range []controlStream{gst, cst} {
			if recv(t, st).GetWelcome() == nil {
				t.Fatal("no Welcome")
			}
		}
		report := func(st controlStream, ds ...*agentv1.DataSession) {
			t.Helper()
			send(t, st, &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{DataSessions: ds}}})
		}
		ds := func(connector string, tr agentv1.Transport, rtt time.Duration) *agentv1.DataSession {
			d := &agentv1.DataSession{ConnectorId: connector, Transport: tr}
			if rtt > 0 {
				d.Rtt = durationpb.New(rtt)
			}
			return d
		}
		rows := func() map[string]*ent.DataSession {
			out := map[string]*ent.DataSession{}
			for _, r := range db.Client().DataSession.Query().AllX(sys) {
				out[r.GatewayID+"/"+r.ConnectorID+"/"+string(r.Transport)] = r
			}
			return out
		}
		waitFor := func(what string, ok func(map[string]*ent.DataSession) bool) map[string]*ent.DataSession {
			t.Helper()
			deadline := time.Now().Add(10 * time.Second)
			for {
				if got := rows(); ok(got) {
					return got
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s: %v", what, rows())
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		quic, h2 := agentv1.Transport_TRANSPORT_QUIC, agentv1.Transport_TRANSPORT_H2
		report(gst, ds("con_a", quic, 12*time.Millisecond), ds("con_a", h2, 0), ds("con_b", h2, 0), ds("con_c", agentv1.Transport_TRANSPORT_UNSPECIFIED, 0))
		got := waitFor("the first report", func(m map[string]*ent.DataSession) bool { return len(m) == 3 })
		first := got[gw.ID+"/con_a/quic"]
		if first == nil || first.RttMs != 12 || first.OrgID != gw.Org || got[gw.ID+"/con_a/h2"].RttMs != 0 {
			t.Fatalf("after the first report: %v", got)
		}

		report(cst, ds("con_x", quic, time.Millisecond))
		// The connector's messages are handled in order: once the marker is recorded, so is its report.
		send(t, cst, statusMsg(false, notReady("marker", agentv1.NotReadyReason_NOT_READY_REASON_ENVIRONMENT, "")))
		for db.Client().ResourceStatus.Query().CountX(sys) == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		report(gst, ds("con_a", quic, 30*time.Millisecond), ds("con_a", h2, 0))
		got = waitFor("the second report", func(m map[string]*ent.DataSession) bool {
			return len(m) == 2 && m[gw.ID+"/con_a/quic"] != nil && m[gw.ID+"/con_a/quic"].RttMs == 30
		})
		if a := got[gw.ID+"/con_a/quic"]; !a.EstablishedAt.Equal(first.EstablishedAt) || a.ReportedAt.Before(first.ReportedAt) {
			t.Fatalf("a session still reported: %+v, first %+v", a, first)
		}
		for k := range got {
			if strings.Contains(k, "con_x") || strings.Contains(k, "con_b") {
				t.Fatalf("%s is kept", k)
			}
		}

		var flood []*agentv1.DataSession
		for i := range 5000 {
			flood = append(flood, ds(fmt.Sprintf("con_%05d", i), h2, 0))
		}
		report(gst, flood...)
		waitFor("a flood", func(m map[string]*ent.DataSession) bool { return len(m) == 4096 })
		report(gst)
		waitFor("an empty report", func(m map[string]*ent.DataSession) bool { return len(m) == 0 })
	})
}
