// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store/ent/rollouttarget"
)

// TestRollouts_HostPolicy: the update policy an agent reported is stored and shown on the agent
// APIs; PreviewRollout lists the agents whose policy refuses the release (a pre-release on a
// stable host, auto_update off or notify) with the reason and the command, and an agent that
// reported none is not listed; CreateRollout marks those targets skipped at once with the same
// reason, in a staged and in an easy rollout, and leaves the others and the unknown ones pending.
func TestRollouts_HostPolicy(t *testing.T) {
	e, ada, org, group := gatewayEnv(t)
	ctx := context.Background()
	sys := e.sys
	c := e.db.Client()
	if err := ada.stepUp(pw, ""); err != nil {
		t.Fatal(err)
	}
	pre := rpmgrv1.UpdateChannel_UPDATE_CHANNEL_PRERELEASE
	if _, err := settings.UpdateInstance(sys, e.db, &rpmgrv1.InstanceSettings{UpdateChannel: &pre},
		&fieldmaskpb.FieldMask{Paths: []string{"update_channel"}}, 0); err != nil {
		t.Fatal(err)
	}
	rels := map[string]string{}
	for v, ch := range map[string]string{"1.4.2": release.Stable, "1.5.0-rc.1": release.Prerelease} {
		resp, err := ada.rel.UploadRelease(ctx, connect.NewRequest(signedRelease(t, e.clock, v, 10, ch)))
		if err != nil {
			t.Fatal(err)
		}
		rels[v] = resp.Msg.GetRelease().GetId()
	}
	c.Release.Update().SetMirroredAt(e.clock).ExecX(sys)

	// The fleet and what each host reported.
	type host struct{ auto, channel string }
	hosts := map[string]host{"ok": {"auto", "prerelease"}, "stable": {"auto", "stable"}, "off": {"off", "prerelease"},
		"notify": {"notify", "prerelease"}, "older": {}}
	ids := map[string]string{}
	for name, h := range hosts {
		id := c.Connector.Create().SetOrgID(org).SetName(name).SetSpiffeID("spiffe://t/" + name).SetPubkeySha256(name).SaveX(sys).ID
		ids[name] = id
		c.AgentSession.Create().SetID(id).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetAgentVersion("1.4.2").
			SetCapabilities([]string{agentproto.CapOTA}).SetUpdateAuto(h.auto).SetUpdateChannel(h.channel).SaveX(sys)
	}
	gw := c.Gateway.Create().SetOrgID(org).SetGatewayGroupID(group).SetName("gw1").SetSlot(1).SetTunnelEndpoints([]string{"gw1.example:443"}).
		SetSpiffeID("spiffe://t/gw1").SaveX(sys)
	c.AgentSession.Create().SetID(gw.ID).SetOrgID(org).SetSessionEpoch(1).SetControllerNode("ctn_1").SetAgentVersion("1.4.2").
		SetCapabilities([]string{agentproto.CapOTA}).SetUpdateAuto("auto").SetUpdateChannel("stable").SaveX(sys)

	// The agent APIs show it.
	got, err := ada.con.GetConnector(ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: ids["stable"]}))
	if err != nil {
		t.Fatal(err)
	}
	if p := got.Msg.GetConnector().GetSession().GetUpdatePolicy(); p.GetAutoUpdate() != "auto" || p.GetUpdateChannel() != "stable" {
		t.Errorf("the connector's policy: %v", p)
	}
	if got, err = ada.con.GetConnector(ctx, connect.NewRequest(&rpmgrv1.GetConnectorRequest{ConnectorId: ids["older"]})); err != nil ||
		got.Msg.GetConnector().GetSession().GetUpdatePolicy() != nil {
		t.Errorf("an agent without a report: %v, %v", got.Msg.GetConnector().GetSession().GetUpdatePolicy(), err)
	}

	preview := func(release string, agents ...string) *rpmgrv1.PreviewRolloutResponse {
		t.Helper()
		resp, err := ada.rel.PreviewRollout(ctx, connect.NewRequest(&rpmgrv1.PreviewRolloutRequest{ReleaseId: release, AgentIds: agents}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg
	}
	names := func(p *rpmgrv1.PreviewRolloutResponse) string {
		var n []string
		for _, s := range p.GetSkipped() {
			n = append(n, s.GetAgentName())
		}
		return strings.Join(n, ",")
	}
	p := preview(rels["1.5.0-rc.1"])
	if p.GetTotal() != 6 || names(p) != "gw1,notify,off,stable" {
		t.Fatalf("a pre-release: %d agents, skipping %s", p.GetTotal(), names(p))
	}
	for _, s := range p.GetSkipped() {
		want := map[string][2]string{
			"gw1":    {"pre-release", "sudo rpmgr policy set-update-channel prerelease"},
			"stable": {"pre-release", "sudo rpmgr policy set-update-channel prerelease"},
			"off":    {"auto_update: off", "sudo rpmgr policy set-auto-update auto"},
			"notify": {"auto_update: notify", "sudo rpmgr policy set-auto-update auto"}}[s.GetAgentName()]
		if !strings.Contains(s.GetReason(), want[0]) || s.GetCommand() != want[1] {
			t.Errorf("%s: %q, %q", s.GetAgentName(), s.GetReason(), s.GetCommand())
		}
	}
	// A stable release is refused only by auto_update.
	if p := preview(rels["1.4.2"]); names(p) != "notify,off" {
		t.Errorf("a stable release: skipping %s", names(p))
	}
	if p := preview(rels["1.5.0-rc.1"], ids["off"], ids["older"], "con_nosuchagent"); p.GetTotal() != 2 || names(p) != "off" {
		t.Errorf("a queue: %d agents, skipping %s", p.GetTotal(), names(p))
	}
	if _, err := ada.rel.PreviewRollout(ctx, connect.NewRequest(&rpmgrv1.PreviewRolloutRequest{ReleaseId: "rel_nosuch"})); code(err) != connect.CodeNotFound {
		t.Errorf("an unknown release: %v", err)
	}
	if _, err := ada.rel.PreviewRollout(ctx, connect.NewRequest(&rpmgrv1.PreviewRolloutRequest{})); code(err) != connect.CodeInvalidArgument {
		t.Errorf("no release: %v", err)
	}

	// A staged rollout skips them at once, with the reason, and never offers them the release.
	resp, err := ada.rel.CreateRollout(ctx, connect.NewRequest(&rpmgrv1.CreateRolloutRequest{ReleaseId: rels["1.5.0-rc.1"], CanaryAgentIds: []string{ids["ok"]}}))
	if err != nil {
		t.Fatal(err)
	}
	state := func(rollout, agent string) (rollouttarget.State, string) {
		t.Helper()
		row := c.RolloutTarget.Query().Where(rollouttarget.RolloutID(rollout), rollouttarget.AgentID(agent)).OnlyX(sys)
		return row.State, row.Reason
	}
	ro := resp.Msg.GetRollout().GetId()
	for name, want := range map[string]rollouttarget.State{"ok": rollouttarget.StatePending, "older": rollouttarget.StatePending,
		"stable": rollouttarget.StateSkipped, "off": rollouttarget.StateSkipped, "notify": rollouttarget.StateSkipped} {
		st, reason := state(ro, ids[name])
		if st != want || (want == rollouttarget.StateSkipped) != strings.Contains(reason, "run on the host: sudo rpmgr policy set-") {
			t.Errorf("%s: %s, %q", name, st, reason)
		}
	}
	if st, _ := state(ro, gw.ID); st != rollouttarget.StateSkipped {
		t.Errorf("the gateway on the stable channel: %s", st)
	}
	if _, err := ada.rel.CancelRollout(ctx, connect.NewRequest(&rpmgrv1.CancelRolloutRequest{RolloutId: ro})); err != nil {
		t.Fatal(err)
	}

	// An easy rollout queues them skipped.
	resp, err = ada.rel.CreateRollout(ctx, connect.NewRequest(&rpmgrv1.CreateRolloutRequest{ReleaseId: rels["1.5.0-rc.1"],
		Mode: rpmgrv1.RolloutMode_ROLLOUT_MODE_EASY, AgentIds: []string{ids["stable"], ids["older"], ids["ok"]}}))
	if err != nil {
		t.Fatal(err)
	}
	ro = resp.Msg.GetRollout().GetId()
	for name, want := range map[string]rollouttarget.State{"stable": rollouttarget.StateSkipped, "older": rollouttarget.StatePending, "ok": rollouttarget.StatePending} {
		if st, _ := state(ro, ids[name]); st != want {
			t.Errorf("easy, %s: %s", name, st)
		}
	}
}
