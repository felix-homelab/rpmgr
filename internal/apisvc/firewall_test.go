// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"sync"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// fakeFirewalls is the firewall states the controller holds, by agent ID.
type fakeFirewalls struct {
	mu   sync.Mutex
	held map[string]*rpmgrv1.FirewallStatus
}

func (f *fakeFirewalls) Firewall(id string) *rpmgrv1.FirewallStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held[id]
}

func (f *fakeFirewalls) set(id string, s *rpmgrv1.FirewallStatus) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.held == nil {
		f.held = map[string]*rpmgrv1.FirewallStatus{}
	}
	f.held[id] = s
}

// TestGatewayFirewallStatus (D152): a gateway's status carries the state of its host's firewall as
// the gateway reported it, in Get and in List, and none for a gateway that reported nothing.
func TestGatewayFirewallStatus(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	gw, err := createGateway(ada, org, group, "gw1", "gw1.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	quiet, err := createGateway(ada, org, group, "gw2", "gw2.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	e.firewalls.set(gw.GetId(), &rpmgrv1.FirewallStatus{State: rpmgrv1.FirewallState_FIREWALL_STATE_FAILED,
		Reason: "ufw is inactive", Rules: []string{"80/tcp"}, Refused: []string{"22/tcp"}})
	r, err := ada.gw.GetGateway(ctx, connect.NewRequest(&rpmgrv1.GetGatewayRequest{GatewayId: gw.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	if f := r.Msg.GetGateway().GetStatus().GetFirewall(); f.GetState() != rpmgrv1.FirewallState_FIREWALL_STATE_FAILED ||
		f.GetReason() != "ufw is inactive" || len(f.GetRefused()) != 1 {
		t.Errorf("Get shows %v", f)
	}
	l, err := ada.gw.ListGateways(ctx, connect.NewRequest(&rpmgrv1.ListGatewaysRequest{OrgId: org}))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, g := range l.Msg.GetGateways() {
		switch g.GetId() {
		case gw.GetId():
			seen++
			if g.GetStatus().GetFirewall().GetState() != rpmgrv1.FirewallState_FIREWALL_STATE_FAILED {
				t.Errorf("List shows %v", g.GetStatus().GetFirewall())
			}
		case quiet.GetId():
			seen++
			if g.GetStatus().GetFirewall() != nil {
				t.Errorf("a gateway that reported nothing shows %v", g.GetStatus().GetFirewall())
			}
		}
	}
	if seen != 2 {
		t.Fatalf("the list holds %d of the two gateways", seen)
	}
}
