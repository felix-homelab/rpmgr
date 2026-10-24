// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import {
  AgentKind, ReleaseService, ReleaseSource, RolloutStage, RolloutState, RolloutTargetState,
  type CancelRolloutRequest, type CreateRolloutRequest, type PauseRolloutRequest, type ResumeRolloutRequest,
} from "@/gen/rpmgr/v1/release_pb";
import { InstanceSettingsSchema, RolloutMode, SettingsService, UpdateChannel, type UpdateInstanceSettingsRequest } from "@/gen/rpmgr/v1/settings_pb";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

async function confirmStepUp() {
  const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
  fireEvent.change(dialog.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
}

const release = { id: "rel_1.5.0", version: "1.5.0", channel: UpdateChannel.STABLE, manifestSeq: 7n, source: ReleaseSource.CHECK,
  mirrored: true, createTime: { seconds: 1791590400n, nanos: 0 }, controllerVersion: true, newerThanController: false };

function connector(id: string, name: string, over: Partial<{ connected: boolean; version: string; builtIn: boolean; ota: boolean }> = {}) {
  return { id, name, enabled: true, ephemeral: false, labels: {}, transport: 0, builtIn: over.builtIn ?? false,
    session: { connected: over.connected ?? true, version: over.version ?? "1.4.2", overTheAir: over.ota ?? true } };
}

function gateway(id: string, name: string, over: Partial<{ version: string; enrolled: boolean }> = {}) {
  return { id, name, gatewayGroupId: "ggr_1", slot: 1, tunnelEndpoints: [`${name}:443`], enabled: true,
    status: { enrolled: over.enrolled ?? true, connected: true, version: over.version ?? "1.4.2", overTheAir: true } };
}

// The org's agents: three connectors and two gateways that can take 1.5.0, one connector offline,
// and four that cannot (built in, no updater, never connected, already on 1.5.0) and a gateway
// that has not enrolled.
const agents = {
  connectors: [connector("con_web", "web"), connector("con_db", "db-host"), connector("con_nas", "nas", { connected: false }),
    connector("con_aio", "built-in", { builtIn: true }), connector("con_box", "container", { ota: false }),
    connector("con_new", "new-host", { version: "", ota: false }), connector("con_done", "done-host", { version: "1.5.0" })],
  gateways: [gateway("gw_2", "edge-2"), gateway("gw_1", "edge-1"), gateway("gw_new", "fresh", { enrolled: false, version: "" })],
};

function easy(over: Partial<{ state: RolloutState; pauseReason: string; failed: number }> = {}) {
  return { id: "rol_9", releaseId: "rel_1.5.0", version: "1.5.0", mode: RolloutMode.EASY, stage: RolloutStage.CANARY, percentage: 0,
    state: over.state ?? RolloutState.RUNNING, pauseReason: over.pauseReason ?? "", etag: "r9",
    counts: { pending: 2, offered: 0, staged: 1, updated: 2, rolledBack: over.failed ?? 1, refused: 0, skipped: 1, stalled: 0 } };
}

function target(agentName: string, position: number, state: RolloutTargetState, reason = "") {
  return { id: `rlt_${agentName}`, rolloutId: "rol_9", agentId: `con_${agentName}`, agentKind: AgentKind.CONNECTOR, agentName,
    orgId: "org_1", canary: false, bucket: 0, position, state, reason, versionBefore: "1.4.2" };
}

// A queue of seven: two updated, one rolled back that the queue went past, one skipped, one
// installing now and two to come.
const queue = [
  target("mail", 6, RolloutTargetState.PENDING), target("web", 1, RolloutTargetState.UPDATED),
  target("nas", 2, RolloutTargetState.ROLLED_BACK, "not ready within the readiness window"),
  target("db-host", 3, RolloutTargetState.UPDATED), target("printer", 4, RolloutTargetState.SKIPPED, "offline"),
  target("wiki", 5, RolloutTargetState.STAGED), target("backup", 7, RolloutTargetState.PENDING),
];

function page({ active, targets = [], mode = RolloutMode.EASY, createError = false } = {} as {
  active?: ReturnType<typeof easy>; targets?: ReturnType<typeof target>[]; mode?: RolloutMode; createError?: boolean;
}) {
  const calls = { create: [] as CreateRolloutRequest[], pause: [] as PauseRolloutRequest[], resume: [] as ResumeRolloutRequest[],
    cancel: [] as CancelRolloutRequest[], settings: [] as UpdateInstanceSettingsRequest[] };
  let steppedUp = false;
  const guarded = <T,>(f: () => T): T => {
    if (!steppedUp) throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
    steppedUp = false;
    return f();
  };
  const settings = () => create(InstanceSettingsSchema, { releaseCheck: true, updateChannel: UpdateChannel.STABLE, rolloutMode: mode });
  show("/settings/updates", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", instanceAdmin: true, memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: () => (steppedUp = true, {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: 0 } }) });
    router.service(SettingsService, {
      getInstanceSettings: () => ({ settings: settings(), etag: "i1" }),
      updateInstanceSettings: (req) => {
        calls.settings.push(req);
        mode = req.settings?.rolloutMode ?? mode;
        return { settings: settings(), etag: "i2" };
      },
    });
    router.service(ConnectorService, { listConnectors: () => ({ connectors: agents.connectors }) });
    router.service(GatewayService, { listGateways: () => ({ gateways: agents.gateways }) });
    router.service(ReleaseService, {
      listReleases: () => ({ releases: [release], controllerVersion: "1.5.0" }),
      listRollouts: () => ({ rollouts: active ? [active] : [] }),
      listRolloutTargets: () => ({ rolloutTargets: targets }),
      createRollout: (req) => guarded(() => {
        if (createError) throw new ConnectError("agent con_web has not announced over-the-air updates", Code.FailedPrecondition);
        return (calls.create.push(req), { rollout: easy() });
      }),
      pauseRollout: (req) => (calls.pause.push(req), { rollout: { ...easy(), state: RolloutState.PAUSED } }),
      resumeRollout: (req) => guarded(() => (calls.resume.push(req), { rollout: easy() })),
      cancelRollout: (req) => guarded(() => (calls.cancel.push(req), { rollout: { ...easy(), state: RolloutState.CANCELLED } })),
    });
  });
  return calls;
}

async function openDialog() {
  const card = within(await screen.findByRole("region", { name: "Releases" }));
  const button = await card.findByRole("button", { name: "Roll out…" }) as HTMLButtonElement;
  await waitFor(() => expect(button.disabled).toBe(false));
  fireEvent.click(button);
  return within(await screen.findByRole("dialog", { name: "Roll out 1.5.0" }));
}

function box(dialog: ReturnType<typeof within>, name: string) {
  return dialog.getByRole("checkbox", { name: new RegExp(`^${name}(?![a-z-])`) }) as HTMLInputElement;
}

function order(dialog: ReturnType<typeof within>) {
  return within(dialog.getByRole("list", { name: "Order" })).getAllByRole("listitem").map((li) => li.textContent?.replace(/^\d+/, "").split(/connector|gateway/)[0]);
}

describe("starting an easy rollout", () => {
  it("lists the agents that can take the release, connectors first, and says why the others cannot", async () => {
    page();
    const dialog = await openDialog();
    await waitFor(() => expect(box(dialog, "web")).toBeTruthy());
    const groups = [dialog.getByRole("group", { name: "Connectors" }), dialog.getByRole("group", { name: "Gateways" })].map((g) => within(g).getAllByRole("checkbox").map((c) => c.closest("label")?.textContent?.split("1.4.2")[0]));
    expect(groups).toEqual([["db-host", "nas", "web"], ["edge-1", "edge-2"]]);
    expect(dialog.getByText("built-in: built in, updates with the controller")).toBeTruthy();
    expect(dialog.getByText("container: no over-the-air updater on its host")).toBeTruthy();
    expect(dialog.getByText("new-host: never connected")).toBeTruthy();
    expect(dialog.getByText("done-host: runs 1.5.0 already")).toBeTruthy();
    expect(dialog.getByText("fresh: not enrolled")).toBeTruthy();
    expect(dialog.queryByRole("checkbox", { name: /container|built-in|fresh/ })).toBeNull();
    // Nothing ticked: Start says why it waits.
    const start = dialog.getByRole("button", { name: "Start: update 0 agents" }) as HTMLButtonElement;
    expect(start.disabled).toBe(true);
    expect(dialog.getByText("Choose at least one agent.")).toBeTruthy();
  });

  it("queues ticked agents in the default order, lets the user move them, and starts the queue after a step-up", async () => {
    const calls = page();
    const dialog = await openDialog();
    await waitFor(() => expect(box(dialog, "web")).toBeTruthy());
    fireEvent.click(box(dialog, "edge-2"));
    fireEvent.click(box(dialog, "web"));
    fireEvent.click(box(dialog, "db-host"));
    expect(order(dialog)).toEqual(["db-host", "web", "edge-2"]);
    fireEvent.click(dialog.getByRole("button", { name: "Move edge-2 up" }));
    expect(order(dialog)).toEqual(["db-host", "edge-2", "web"]);
    expect((dialog.getByRole("button", { name: "Move db-host up" }) as HTMLButtonElement).disabled).toBe(true);
    expect((dialog.getByRole("button", { name: "Move web down" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(box(dialog, "web"));
    expect(order(dialog)).toEqual(["db-host", "edge-2"]);
    // Select all puts each new agent at its place in the default order among those queued.
    fireEvent.click(dialog.getByRole("button", { name: "Select all" }));
    expect(order(dialog)).toEqual(["db-host", "nas", "web", "edge-1", "edge-2"]);
    expect(dialog.getByText("An agent that is offline when its turn comes is skipped.")).toBeTruthy();
    fireEvent.click(dialog.getByRole("button", { name: "Start: update 5 agents" }));
    await confirmStepUp();
    await waitFor(() => expect(calls.create).toHaveLength(1));
    expect(calls.create[0]).toMatchObject({ releaseId: "rel_1.5.0", mode: RolloutMode.EASY, canaryAgentIds: [],
      agentIds: ["con_db", "con_nas", "con_web", "gw_1", "gw_2"] });
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Roll out 1.5.0" })).toBeNull());
  });

  it("finds agents by name and shows the server's refusal", async () => {
    page({ createError: true });
    const dialog = await openDialog();
    await waitFor(() => expect(box(dialog, "web")).toBeTruthy());
    fireEvent.change(dialog.getByLabelText("Search agents"), { target: { value: "edge" } });
    expect(dialog.queryByRole("checkbox", { name: /^web/ })).toBeNull();
    fireEvent.click(dialog.getByRole("button", { name: "Select all" }));
    expect(order(dialog)).toEqual(["edge-1", "edge-2"]);
    fireEvent.change(dialog.getByLabelText("Search agents"), { target: { value: "nothing" } });
    expect(dialog.getByText("No agent matches the search.")).toBeTruthy();
    fireEvent.click(dialog.getByRole("button", { name: "Start: update 2 agents" }));
    await confirmStepUp();
    expect(await dialog.findByText("agent con_web has not announced over-the-air updates")).toBeTruthy();
  });

  it("opens the staged dialog in the advanced mode, and the mode switch saves the setting", async () => {
    const calls = page({ mode: RolloutMode.ADVANCED });
    const dialog = await openDialog();
    expect(dialog.getByText("Step 1 of 2: test agents")).toBeTruthy();
    fireEvent.click(dialog.getByRole("button", { name: "Cancel" }));
    const select = await screen.findByLabelText("Rollouts") as HTMLSelectElement;
    expect(select.value).toBe(String(RolloutMode.ADVANCED));
    fireEvent.change(select, { target: { value: String(RolloutMode.EASY) } });
    const form = select.closest("form")!;
    fireEvent.click(within(form).getByRole("button", { name: /^Save/ }));
    await waitFor(() => expect(calls.settings).toHaveLength(1));
    expect(calls.settings[0]?.settings?.rolloutMode).toBe(RolloutMode.EASY);
    expect(calls.settings[0]?.updateMask?.paths).toContain("rollout_mode");
    const easyDialog = await openDialog();
    expect(easyDialog.getByText(/one after another, in the order on the right/)).toBeTruthy();
  });
});

describe("following an easy rollout", () => {
  it("shows the agent whose turn it is, the queue to come, and the failed agent with the count, while the queue goes on", async () => {
    page({ active: easy(), targets: queue });
    const card = within(await screen.findByRole("region", { name: "Rollout" }));
    expect(card.getByText("Rollout of 1.5.0, one agent after another")).toBeTruthy();
    expect(card.getByText("1 failed")).toBeTruthy();
    await waitFor(() => expect(card.getByText("wiki")).toBeTruthy());
    const part = (label: string) => card.getByText(label, { selector: "dt" }).nextElementSibling as HTMLElement;
    expect(part("Now").textContent).toMatch(/^wiki.*staged/);
    expect(within(part("Next")).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["6mail", "7backup"]);
    expect(within(part("Updated")).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["web", "db-host"]);
    expect(part("Failed").textContent).toContain("nas");
    expect(part("Failed").textContent).toContain("not ready within the readiness window");
    expect(part("Skipped").textContent).toContain("offline");
    expect(card.getByRole("button", { name: "Pause" })).toBeTruthy();
    expect(card.queryByRole("button", { name: "Resume" })).toBeNull();
    expect(card.queryByRole("button", { name: /Continue/ })).toBeNull();
  });

  it("explains a pause after failures in a row and resumes or cancels after a step-up", async () => {
    const calls = page({ active: easy({ state: RolloutState.PAUSED, failed: 3, pauseReason: "3 agents in a row failed to take the release" }),
      targets: queue });
    const card = within(await screen.findByRole("region", { name: "Rollout" }));
    expect(card.getByRole("status").textContent).toBe("Paused: 3 agents in a row failed to take the release");
    expect(card.getByText("3 failed")).toBeTruthy();
    expect(card.getByText(/Resume goes on with the next agent/)).toBeTruthy();
    fireEvent.click(card.getByRole("button", { name: "Resume" }));
    await confirmStepUp();
    await waitFor(() => expect(calls.resume).toEqual([expect.objectContaining({ rolloutId: "rol_9", etag: "r9" })]));
    fireEvent.click(card.getByRole("button", { name: "Cancel" }));
    fireEvent.click(card.getByRole("button", { name: "Cancel the rollout" }));
    await confirmStepUp();
    await waitFor(() => expect(calls.cancel).toHaveLength(1));
  });

  it("shows no failure count while nothing failed, and an empty queue when the last agent has its turn", async () => {
    page({ active: easy({ failed: 0 }), targets: [target("web", 1, RolloutTargetState.UPDATED), target("db-host", 2, RolloutTargetState.OFFERED)] });
    const card = within(await screen.findByRole("region", { name: "Rollout" }));
    await waitFor(() => expect(card.getByText("db-host")).toBeTruthy());
    expect(card.queryByText(/failed$/)).toBeNull();
    const part = (label: string) => card.getByText(label, { selector: "dt" }).nextElementSibling as HTMLElement;
    expect(part("Next").textContent).toBe("—");
    expect(part("Failed").textContent).toBe("—");
  });
});
