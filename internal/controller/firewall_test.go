// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

func firewallStatus(phase agentv1.FirewallPhase, reason string, refused ...string) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Status{Status: &agentv1.Status{Firewall: &agentv1.FirewallState{
		Phase: phase, Reason: reason, Rules: []string{"80/tcp"}, Refused: refused, Reported: timestamppb.New(time.Unix(1000, 0))}}}}
}

// TestFirewallState (D152): the state a gateway reports of its host's firewall shows until the next
// report replaces it or its session ends; an agent that reported nothing shows none.
func TestFirewallState(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		e := startSessions(t, db, "0.1.0", 0)
		certA, a := e.agentCert(t)
		certB, b := e.agentCert(t)
		stA, stB := e.open(t, testCtx(t), certA, hello("0.1.0")), e.open(t, testCtx(t), certB, hello("0.1.0"))
		recv(t, stA)
		recv(t, stB)
		eventually := func(what string, ok func() bool) {
			t.Helper()
			for range 200 {
				if ok() {
					return
				}
				time.Sleep(25 * time.Millisecond)
			}
			t.Fatal(what)
		}
		if f := e.sessions.Firewall(a.ID); f != nil {
			t.Fatalf("an agent that reported nothing shows %v", f)
		}
		send(t, stA, firewallStatus(agentv1.FirewallPhase_FIREWALL_PHASE_APPLIED, ""))
		eventually("the report did not show", func() bool {
			return e.sessions.Firewall(a.ID).GetState() == rpmgrv1.FirewallState_FIREWALL_STATE_APPLIED
		})
		if f := e.sessions.Firewall(a.ID); f.GetRules()[0] != "80/tcp" || f.GetReportTime().AsTime().Unix() != 1000 {
			t.Errorf("the report shows %v", f)
		}
		send(t, stA, firewallStatus(agentv1.FirewallPhase_FIREWALL_PHASE_FAILED, "ufw is inactive", "22/tcp"))
		eventually("the failure did not replace the report", func() bool {
			return e.sessions.Firewall(a.ID).GetState() == rpmgrv1.FirewallState_FIREWALL_STATE_FAILED
		})
		if f := e.sessions.Firewall(a.ID); f.GetReason() != "ufw is inactive" || len(f.GetRefused()) != 1 {
			t.Errorf("the failure shows %v", f)
		}
		send(t, stA, firewallStatus(agentv1.FirewallPhase_FIREWALL_PHASE_OFF, "switched off"))
		eventually("off did not show", func() bool {
			return e.sessions.Firewall(a.ID).GetState() == rpmgrv1.FirewallState_FIREWALL_STATE_OFF
		})
		if e.sessions.Firewall(b.ID) != nil {
			t.Fatal("another agent shows A's firewall")
		}
		// A phase this release does not know is shown as unset, not as a state it never had.
		send(t, stB, firewallStatus(agentv1.FirewallPhase(99), ""))
		eventually("an unknown phase was dropped", func() bool { return e.sessions.Firewall(b.ID) != nil })
		if s := e.sessions.Firewall(b.ID).GetState(); s != rpmgrv1.FirewallState_FIREWALL_STATE_UNSPECIFIED {
			t.Errorf("an unknown phase shows as %v", s)
		}
		// A new session starts without the old session's report: the gateway reports it again.
		stB2 := e.open(t, testCtx(t), certB, hello("0.1.0"))
		recv(t, stB2)
		eventually("the report outlived its session", func() bool { return e.sessions.Firewall(b.ID) == nil })
	})
}
