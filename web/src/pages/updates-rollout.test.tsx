// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import {
  AgentKind, ReleaseService, ReleaseSource, RolloutStage, RolloutState, RolloutTargetState,
  type AdvanceRolloutRequest, type CancelRolloutRequest, type CreateRolloutRequest, type PauseRolloutRequest,
  type ResumeRolloutRequest,
} from "@/gen/rpmgr/v1/release_pb";
import { InstanceSettingsSchema, RolloutMode, SettingsService, UpdateChannel } from "@/gen/rpmgr/v1/settings_pb";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";
import { create } from "@bufbuild/protobuf";

afterEach(cleanup);

async function confirmStepUp() {
  const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
  fireEvent.change(dialog.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
}

const release = { id: "rel_1.5.0", version: "1.5.0", channel: UpdateChannel.STABLE, manifestSeq: 7n, source: ReleaseSource.CHECK,
  mirrored: true, createTime: { seconds: 1791590400n, nanos: 0 }, controllerVersion: false, newerThanController: false };

function connector(id: string, name: string, over: Partial<{ connected: boolean; version: string; builtIn: boolean }> = {}) {
  return { id, name, enabled: true, ephemeral: false, labels: {}, transport: 0, builtIn: over.builtIn ?? false,
    session: { connected: over.connected ?? true, version: over.version ?? "1.4.2" } };
}

function gateway(id: string, name: string, over: Partial<{ connected: boolean; version: string; enrolled: boolean; decommissioned: boolean }> = {}) {
  return { id, name, gatewayGroupId: "ggr_1", slot: 1, tunnelEndpoints: [`${name}:443`], enabled: true,
    decommissionTime: over.decommissioned ? { seconds: 1791590400n, nanos: 0 } : undefined,
    status: { enrolled: over.enrolled ?? true, connected: over.connected ?? true, version: over.version ?? "1.4.2" } };
}

// The org's agents: two online, one offline, one on the release already, and three a rollout leaves
// out (built in, decommissioned, not enrolled).
const agents = {
  connectors: [connector("con_db", "db-host"), connector("con_nas", "nas", { connected: false }),
    connector("con_new", "new-host", { version: "1.5.0" }), connector("con_aio", "built-in", { builtIn: true })],
  gateways: [gateway("gw_1", "edge"), gateway("gw_old", "old", { decommissioned: true }), gateway("gw_new", "fresh", { enrolled: false })],
};

function rollout(over: Partial<{ state: RolloutState; stage: RolloutStage; percentage: number; pauseReason: string }> = {}) {
  const stage = over.stage ?? RolloutStage.PERCENTAGE;
  return { id: "rol_1", releaseId: "rel_1.5.0", version: "1.5.0", stage, percentage: over.percentage ?? (stage === RolloutStage.CANARY ? 0 : 25),
    state: over.state ?? RolloutState.RUNNING, pauseReason: over.pauseReason ?? "", etag: "r1",
    counts: { pending: 2, offered: 1, staged: 0, updated: 2, rolledBack: 1, refused: 0, skipped: 1, stalled: 0 } };
}

function target(agentName: string, over: Partial<{ canary: boolean; bucket: number; state: RolloutTargetState; reason: string; kind: AgentKind }> = {}) {
  return { id: `rlt_${agentName}`, rolloutId: "rol_1", agentId: `con_${agentName}`, agentKind: over.kind ?? AgentKind.CONNECTOR, agentName,
    orgId: "org_1", canary: over.canary ?? false, bucket: over.bucket ?? 50, state: over.state ?? RolloutTargetState.PENDING,
    reason: over.reason ?? "", versionBefore: "1.4.2" };
}

// targets of a rollout at 25 %: both test agents updated, one agent of the stage rolled back, one
// skipped and three waiting for later stages (buckets 30, 60 and 90).
const done25 = [
  target("db-host", { canary: true, bucket: 70, state: RolloutTargetState.UPDATED }),
  target("edge", { canary: true, bucket: 12, state: RolloutTargetState.UPDATED, kind: AgentKind.GATEWAY }),
  target("nas", { bucket: 3, state: RolloutTargetState.ROLLED_BACK, reason: "the service did not become ready" }),
  target("printer", { bucket: 8, state: RolloutTargetState.SKIPPED, reason: "offline" }),
  target("wiki", { bucket: 30 }), target("mail", { bucket: 60 }), target("backup", { bucket: 90 }),
];

function page({ active, targets = [], lists = agents, createError, wrongEtag = false } = {} as {
  active?: ReturnType<typeof rollout>;
  targets?: ReturnType<typeof target>[];
  lists?: typeof agents;
  createError?: boolean;
  wrongEtag?: boolean;
}) {
  const calls = { create: [] as CreateRolloutRequest[], advance: [] as AdvanceRolloutRequest[], pause: [] as PauseRolloutRequest[],
    resume: [] as ResumeRolloutRequest[], cancel: [] as CancelRolloutRequest[], steppedUp: 0 };
  let steppedUp = false;
  const guarded = <T,>(f: () => T): T => {
    if (!steppedUp) throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
    steppedUp = false;
    return f();
  };
  const current = active ?? rollout();
  show("/settings/updates", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", instanceAdmin: true, memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: () => (calls.steppedUp++, steppedUp = true, {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: 0 } }) });
    router.service(SettingsService, {
      getInstanceSettings: () => ({ settings: create(InstanceSettingsSchema, { releaseCheck: true, updateChannel: UpdateChannel.STABLE,
        rolloutMode: RolloutMode.ADVANCED }), etag: "i1" }),
    });
    router.service(ConnectorService, { listConnectors: () => ({ connectors: lists.connectors }) });
    router.service(GatewayService, { listGateways: () => ({ gateways: lists.gateways }) });
    router.service(ReleaseService, {
      listReleases: () => ({ releases: [release], controllerVersion: "1.4.2" }),
      listRollouts: () => ({ rollouts: active ? [active] : [] }),
      listRolloutTargets: () => ({ rolloutTargets: targets }),
      createRollout: (req) => guarded(() => {
        if (createError) throw apiError(Code.FailedPrecondition, "ROLLOUT_ACTIVE");
        return (calls.create.push(req), { rollout: current });
      }),
      advanceRollout: (req) => guarded(() => {
        if (wrongEtag) throw apiError(Code.FailedPrecondition, "ETAG_MISMATCH");
        return (calls.advance.push(req), { rollout: current });
      }),
      pauseRollout: (req) => (calls.pause.push(req), { rollout: { ...current, state: RolloutState.PAUSED } }),
      resumeRollout: (req) => guarded(() => (calls.resume.push(req), { rollout: current })),
      cancelRollout: (req) => guarded(() => (calls.cancel.push(req), { rollout: { ...current, state: RolloutState.CANCELLED } })),
    });
  });
  return calls;
}

async function openDialog() {
  const card = within(await screen.findByRole("region", { name: "Releases" }));
  fireEvent.click(await card.findByRole("button", { name: "Roll out…" }));
  return within(await screen.findByRole("dialog", { name: "Roll out 1.5.0" }));
}

function box(dialog: ReturnType<typeof within>, name: string) {
  return dialog.getByRole("checkbox", { name: new RegExp(`^${name}(?![a-z-])`) }) as HTMLInputElement;
}

describe("starting a rollout", () => {
  it("explains the test agents, suggests one online connector and gateway, and counts who gets the release", async () => {
    page();
    const dialog = await openDialog();
    expect(dialog.getByText("Step 1 of 2: test agents")).toBeTruthy();
    expect(dialog.getByText("These agents update first. All other agents wait until you continue the rollout.")).toBeTruthy();
    await waitFor(() => expect(box(dialog, "db-host").checked).toBe(true));
    expect(box(dialog, "edge").checked).toBe(true);
    expect(box(dialog, "nas").checked).toBe(false);
    expect(box(dialog, "new-host").disabled).toBe(true);
    expect(dialog.getByRole("group", { name: "Connectors" })).toBeTruthy();
    expect(within(dialog.getByRole("group", { name: "Gateways" })).getAllByRole("checkbox")).toHaveLength(1);
    expect(dialog.queryByRole("checkbox", { name: /built-in|old|fresh/ })).toBeNull();
    expect(dialog.getByText("4 agents get the release · 1 already runs 1.5.0 · 3 not included: built in, decommissioned or not enrolled")).toBeTruthy();
    // The choice in words, which a scrolled list may hide.
    expect(dialog.getByText("2 test agents: db-host, edge")).toBeTruthy();
    fireEvent.click(box(dialog, "edge"));
    expect(dialog.getByText("Test agent: db-host")).toBeTruthy();
  });

  it("reviews the plan and starts the rollout with the test agents, after a step-up", async () => {
    const calls = page();
    const dialog = await openDialog();
    await waitFor(() => expect(box(dialog, "edge").checked).toBe(true));
    fireEvent.click(dialog.getByRole("button", { name: "Next" }));
    expect(dialog.getByText("Step 2 of 2: review the plan")).toBeTruthy();
    const plan = within(dialog.getByRole("list", { name: "The plan" })).getAllByRole("listitem").map((li) => li.textContent);
    expect(plan).toEqual([
      "1Test agentsdb-host, edge update first.",
      "225 %Then about 1 more agent, when you continue.",
      "3All agentsThen the remaining 1 agent, when you continue.",
    ]);
    fireEvent.click(dialog.getByRole("button", { name: "Start the rollout" }));
    await confirmStepUp();
    await waitFor(() => expect(calls.create).toHaveLength(1));
    expect(calls.create[0]).toMatchObject({ releaseId: "rel_1.5.0", canaryAgentIds: ["con_db", "gw_1"] });
  });

  it("keeps the choice when going back, and says why the rollout did not start", async () => {
    page({ createError: true });
    const dialog = await openDialog();
    await waitFor(() => expect(box(dialog, "edge").checked).toBe(true));
    fireEvent.click(box(dialog, "edge"));
    fireEvent.click(dialog.getByRole("button", { name: "Next" }));
    fireEvent.click(dialog.getByRole("button", { name: "Back" }));
    expect(box(dialog, "edge").checked).toBe(false);
    expect(box(dialog, "db-host").checked).toBe(true);
    fireEvent.click(dialog.getByRole("button", { name: "Next" }));
    fireEvent.click(dialog.getByRole("button", { name: "Start the rollout" }));
    await confirmStepUp();
    expect(await dialog.findByText(/ROLLOUT_ACTIVE|api error/)).toBeTruthy();
  });

  it("suggests nothing when no agent is online, and needs one test agent to go on", async () => {
    page({ lists: { connectors: [connector("con_nas", "nas", { connected: false })], gateways: [gateway("gw_1", "edge", { connected: false })] } });
    const dialog = await openDialog();
    expect(await dialog.findByText(/^No agent is online, so none is suggested/)).toBeTruthy();
    expect(box(dialog, "nas").checked).toBe(false);
    const next = dialog.getByRole("button", { name: "Next" }) as HTMLButtonElement;
    expect(next.disabled).toBe(true);
    expect(next.getAttribute("aria-describedby")).toBeTruthy();
    expect(dialog.getByText("Choose at least one test agent.")).toBeTruthy();
    fireEvent.click(box(dialog, "nas"));
    expect(next.disabled).toBe(false);
    expect(dialog.getByText(/^A test agent is offline: it is skipped/)).toBeTruthy();
  });

  it("filters the agents by the search", async () => {
    page();
    const dialog = await openDialog();
    await waitFor(() => expect(box(dialog, "edge").checked).toBe(true));
    fireEvent.change(dialog.getByRole("searchbox", { name: "Search agents" }), { target: { value: "ED" } });
    expect(dialog.getAllByRole("checkbox")).toHaveLength(1);
    expect(dialog.queryByRole("group", { name: "Connectors" })).toBeNull();
    fireEvent.change(dialog.getByRole("searchbox", { name: "Search agents" }), { target: { value: "zzz" } });
    expect(dialog.getByText("No agent matches the search.")).toBeTruthy();
  });
});

describe("following a rollout", () => {
  it("shows the stages and holds Continue until the test agents are done", async () => {
    page({ active: rollout({ stage: RolloutStage.CANARY }), targets: [
      target("db-host", { canary: true, state: RolloutTargetState.UPDATED }),
      target("edge", { canary: true, bucket: 12, state: RolloutTargetState.OFFERED, kind: AgentKind.GATEWAY }),
      target("wiki", { bucket: 20 }), target("mail", { bucket: 60 }),
    ] });
    const region = within(await screen.findByRole("region", { name: "Rollout" }));
    const stages = within(region.getByRole("list", { name: "Stages" })).getAllByRole("listitem");
    expect(await within(stages[0]!).findByText("1 of 2 updated")).toBeTruthy();
    expect(stages.map((s) => s.getAttribute("aria-current"))).toEqual(["step", null, null]);
    expect(stages.map((s) => s.textContent)).toEqual([
      "Test agents, current stage1 of 2 updated", "25 %, to come1 waiting", "All agents, to come2 waiting",
    ]);
    const go = region.getByRole("button", { name: "Continue to 25 % (1 more agent)" }) as HTMLButtonElement;
    expect(go.disabled).toBe(true);
    expect(region.getByText("You can continue once this stage is done: 1 agent is still updating.")).toBeTruthy();
    const updating = within(region.getByText("Updating now").closest("details")!);
    expect(updating.getByRole("row", { name: /edge/ })).toBeTruthy();
    expect(updating.queryByRole("row", { name: /wiki|mail/ })).toBeNull();
    expect(region.getByText("Waiting for a later stage").closest("details")!.open).toBe(false);
  });

  it("continues to all agents once the stage is done, or to another percentage, under the etag it read", async () => {
    const calls = page({ active: rollout(), targets: done25 });
    const region = within(await screen.findByRole("region", { name: "Rollout" }));
    const go = await region.findByRole("button", { name: "Continue to all agents (3 more agents)" }) as HTMLButtonElement;
    expect(go.disabled).toBe(false);
    expect(region.getByRole("progressbar", { name: "Agents updated" }).getAttribute("aria-valuetext")).toBe("2 of 6 agents updated");
    expect(region.getByText("2 of 6 agents updated · 1 skipped")).toBeTruthy();
    fireEvent.click(go);
    await confirmStepUp();
    await waitFor(() => expect(calls.advance).toHaveLength(1));
    expect(calls.advance[0]).toMatchObject({ rolloutId: "rol_1", etag: "r1", next: { case: "all", value: true } });

    const choose = region.getByRole("button", { name: "Choose another stage" });
    fireEvent.click(choose);
    expect(choose.getAttribute("aria-expanded")).toBe("true");
    const choices = within(region.getByRole("group", { name: "Next stage" }));
    expect(choices.getAllByRole("radio").map((r) => r.parentElement?.textContent)).toEqual(["50 %", "75 %", "All agents", "Another percentage"]);
    fireEvent.click(choices.getByRole("radio", { name: "50 %" }));
    fireEvent.click(region.getByRole("button", { name: "Continue to 50 % (1 more agent)" }));
    await confirmStepUp();
    await waitFor(() => expect(calls.advance).toHaveLength(2));
    expect(calls.advance[1]).toMatchObject({ next: { case: "percentage", value: 50 } });
  });

  it("takes another percentage only above the current one", async () => {
    const calls = page({ active: rollout(), targets: done25 });
    const region = within(await screen.findByRole("region", { name: "Rollout" }));
    fireEvent.click(await region.findByRole("button", { name: "Choose another stage" }));
    fireEvent.click(region.getByRole("radio", { name: "Another percentage" }));
    const percent = region.getByRole("textbox", { name: "Percentage" });
    for (const bad of ["25", "100", "3a"]) {
      fireEvent.change(percent, { target: { value: bad } });
      expect(percent.getAttribute("aria-invalid")).toBe("true");
      expect((region.getByRole("button", { name: "Continue" }) as HTMLButtonElement).disabled).toBe(true);
    }
    expect(region.getByText("A whole number from 26 to 99.")).toBeTruthy();
    fireEvent.change(percent, { target: { value: "40" } });
    fireEvent.click(region.getByRole("button", { name: "Continue to 40 % (1 more agent)" }));
    await confirmStepUp();
    await waitFor(() => expect(calls.advance).toHaveLength(1));
    expect(calls.advance[0]).toMatchObject({ next: { case: "percentage", value: 40 } });
  });

  it("lists the agents that need attention first, with why", async () => {
    page({ active: rollout(), targets: done25 });
    const region = within(await screen.findByRole("region", { name: "Rollout" }));
    await region.findByText("Need attention");
    const groups = region.getAllByRole("group").filter((g) => g.tagName === "DETAILS").map((d) => d.querySelector("summary")?.textContent);
    expect(groups).toEqual(["Need attention (1)", "Waiting for a later stage (3)", "Updated (2)", "Skipped (1)"]);
    const row = within(region.getByText("Need attention").closest("details")!).getByRole("row", { name: /nas/ });
    expect(within(row).getAllByRole("cell").map((c) => c.textContent)).toEqual(["nas", "connector", "rolled back", "the service did not become ready"]);
    const waiting = within(region.getByText("Waiting for a later stage").closest("details")!);
    expect(waiting.getAllByText("waiting")).toHaveLength(3);
  });

  it("offers no Continue at all agents or while paused, pauses without a step-up, and resumes and cancels with one", async () => {
    page({ active: rollout({ stage: RolloutStage.ALL, percentage: 100 }), targets: done25 });
    const all = within(await screen.findByRole("region", { name: "Rollout" }));
    expect(await all.findByText(/^Every agent gets the release now/)).toBeTruthy();
    expect(all.queryByRole("button", { name: /^Continue/ })).toBeNull();
    expect(all.getByRole("button", { name: "Pause" })).toBeTruthy();
    cleanup();

    const calls = page({ active: rollout({ state: RolloutState.PAUSED, pauseReason: "nas rolled back: not ready" }), targets: done25 });
    const paused = within(await screen.findByRole("region", { name: "Rollout" }));
    expect(await paused.findByText(/^Paused: nas rolled back/)).toBeTruthy();
    expect(paused.queryByRole("button", { name: /^Continue/ })).toBeNull();
    expect(paused.queryByRole("button", { name: "Pause" })).toBeNull();
    fireEvent.click(paused.getByRole("button", { name: "Resume" }));
    await confirmStepUp();
    await waitFor(() => expect(calls.resume).toHaveLength(1));
    fireEvent.click(paused.getByRole("button", { name: "Cancel" }));
    expect(paused.getByRole("alert").textContent).toMatch(/^Cancelling the rollout ends it for good/);
    fireEvent.click(paused.getByRole("button", { name: "Keep it" }));
    expect(paused.queryByRole("alert")).toBeNull();
    fireEvent.click(paused.getByRole("button", { name: "Cancel" }));
    fireEvent.click(paused.getByRole("button", { name: "Cancel the rollout" }));
    await confirmStepUp();
    await waitFor(() => expect(calls.cancel).toHaveLength(1));
    expect(calls.steppedUp).toBe(2);
    expect(calls.pause).toHaveLength(0);
  });

  it("pauses a running rollout without a step-up", async () => {
    const calls = page({ active: rollout(), targets: done25 });
    const region = within(await screen.findByRole("region", { name: "Rollout" }));
    fireEvent.click(await region.findByRole("button", { name: "Pause" }));
    await waitFor(() => expect(calls.pause).toHaveLength(1));
    expect(calls.pause[0]).toMatchObject({ rolloutId: "rol_1", etag: "r1" });
    expect(calls.steppedUp).toBe(0);
  });

  it("says when the rollout changed meanwhile", async () => {
    page({ active: rollout(), targets: done25, wrongEtag: true });
    const region = within(await screen.findByRole("region", { name: "Rollout" }));
    fireEvent.click(await region.findByRole("button", { name: "Continue to all agents (3 more agents)" }));
    await confirmStepUp();
    expect(await region.findByText(/ETAG_MISMATCH|api error/)).toBeTruthy();
  });
});
