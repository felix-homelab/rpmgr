// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { updateBlock, type UpdatableAgent } from "@/components/update-button";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import {
  AgentKind, ReleaseService, ReleaseSource, RolloutStage, RolloutState, RolloutTargetState, type UpgradeAgentsRequest,
} from "@/gen/rpmgr/v1/release_pb";
import { RolloutMode, UpdateChannel } from "@/gen/rpmgr/v1/settings_pb";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const ready: UpdatableAgent = { id: "con_db", version: "1.4.2", online: true, builtIn: false, enrolled: true, overTheAir: true };
const easyRunning = { mode: RolloutMode.EASY, version: "1.5.0" };
const queued = (state: RolloutTargetState, reason = "") => ({ id: "rlt_1", rolloutId: "rol_9", agentId: "con_db", agentKind: AgentKind.CONNECTOR,
  agentName: "db-host", orgId: "org_1", canary: false, bucket: 0, position: 4, state, reason, versionBefore: "1.4.2", $typeName: "rpmgr.v1.RolloutTarget" as const });

describe("why an agent cannot be updated", () => {
  it("names the first reason that applies, and none for an agent that can take the release", () => {
    const cases: [string, Parameters<typeof updateBlock>][] = [
      ["", [ready, "1.5.0", undefined, undefined]],
      ["", [ready, "1.5.0", easyRunning, undefined]],
      ["builtIn", [{ ...ready, builtIn: true, overTheAir: false }, "1.5.0", undefined, undefined]],
      ["notEnrolled", [{ ...ready, enrolled: false, version: "" }, "1.5.0", undefined, undefined]],
      ["neverConnected", [{ ...ready, version: "", overTheAir: false }, "1.5.0", undefined, undefined]],
      ["noUpdater", [{ ...ready, overTheAir: false }, "1.5.0", undefined, undefined]],
      ["noRelease", [ready, undefined, undefined, undefined]],
      ["upToDate", [{ ...ready, version: "1.5.0" }, "1.5.0", easyRunning, undefined]],
      ["staged", [ready, "1.5.0", { mode: RolloutMode.ADVANCED, version: "1.5.0" }, undefined]],
      ["otherRelease", [ready, "1.5.0", { mode: RolloutMode.EASY, version: "1.4.9" }, undefined]],
      ["queued", [ready, "1.5.0", easyRunning, queued(RolloutTargetState.PENDING)]],
      ["queued", [ready, "1.5.0", easyRunning, queued(RolloutTargetState.STAGED)]],
      ["skipped", [ready, "1.5.0", easyRunning, queued(RolloutTargetState.SKIPPED, "the local policy says auto_update: notify")]],
      ["offline", [{ ...ready, online: false }, "1.5.0", undefined, undefined]],
      // A failed agent keeps its place: only a new rollout tries it again.
      ["failed", [ready, "1.5.0", easyRunning, queued(RolloutTargetState.ROLLED_BACK, "not ready")]],
      ["failed", [ready, "1.5.0", easyRunning, queued(RolloutTargetState.STALLED)]],
      // An agent of an ended rollout is no longer queued.
      ["", [ready, "1.5.0", undefined, undefined]],
    ];
    for (const [want, args] of cases) {
      expect(updateBlock(...args), JSON.stringify(args[0])).toBe(want);
    }
  });
});

const release = { id: "rel_1.5.0", version: "1.5.0", channel: UpdateChannel.STABLE, manifestSeq: 7n, source: ReleaseSource.CHECK,
  mirrored: true, controllerVersion: true, newerThanController: false };

function connector(id: string, name: string, over: Partial<{ version: string; ota: boolean; connected: boolean }> = {}) {
  return { id, name, enabled: true, labels: {}, session: { connected: over.connected ?? true, version: over.version ?? "1.4.2", overTheAir: over.ota ?? true } };
}

function page({ admin = true, active, targets = [] as ReturnType<typeof queued>[], refuse = false } = {} as {
  admin?: boolean; active?: object; targets?: ReturnType<typeof queued>[]; refuse?: boolean;
}) {
  const calls: UpgradeAgentsRequest[] = [];
  let steppedUp = false;
  let rollouts = active ? [active] : [];
  let list = targets;
  show("/connectors", auth({
    getSession: () => ({ userId: "usr_ada", instanceAdmin: admin, memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: () => (steppedUp = true, {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: 0 } }) });
    router.service(GatewayService, { listGateways: () => ({ gateways: [] }) });
    router.service(ConnectorService, { listConnectors: () => ({ connectors: [connector("con_db", "db-host"), connector("con_box", "box", { ota: false }),
      connector("con_new", "new-host", { version: "1.5.0" })] }) });
    router.service(ReleaseService, {
      listReleases: () => ({ releases: [release], controllerVersion: "1.5.0" }),
      listRollouts: () => ({ rollouts }),
      listRolloutTargets: () => ({ rolloutTargets: list }),
      upgradeAgents: (req) => {
        if (!steppedUp) throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
        if (refuse) throw apiError(Code.FailedPrecondition, "ROLLOUT_ACTIVE");
        calls.push(req);
        const t = { ...queued(RolloutTargetState.PENDING), position: 4 };
        rollouts = [{ id: "rol_9", releaseId: "rel_1.5.0", version: "1.5.0", mode: RolloutMode.EASY, stage: RolloutStage.CANARY,
          state: RolloutState.RUNNING, etag: "r9" }];
        list = [t];
        return { rollout: rollouts[0], rolloutTargets: [t] };
      },
    });
  });
  return calls;
}

function row(name: string) {
  return within(screen.getByRole("link", { name }).closest("tr")!);
}

describe("the Update button", () => {
  it("updates a connector to the controller's version after a step-up, and then shows its place in the queue", async () => {
    const calls = page();
    await screen.findByRole("link", { name: "db-host" });
    const button = await row("db-host").findByRole("button", { name: "Update to 1.5.0" }) as HTMLButtonElement;
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(dialog.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(calls).toEqual([expect.objectContaining({ agentIds: ["con_db"] })]));
    expect(await row("db-host").findByText("Number 4 in the queue.")).toBeTruthy();
    expect((row("db-host").getByRole("button", { name: "Update to 1.5.0" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("is disabled with its reason for an agent without the updater or on the release already", async () => {
    page();
    await screen.findByRole("link", { name: "box" });
    expect(await row("box").findByText("No over-the-air updater on its host.")).toBeTruthy();
    expect((row("box").getByRole("button", { name: "Update to 1.5.0" }) as HTMLButtonElement).disabled).toBe(true);
    expect(row("new-host").getByText("Up to date.")).toBeTruthy();
  });

  it("is refused while a staged rollout runs, and shows the server's refusal", async () => {
    page({ active: { id: "rol_1", releaseId: "rel_1.5.0", version: "1.5.0", mode: RolloutMode.ADVANCED, stage: RolloutStage.CANARY,
      state: RolloutState.RUNNING, etag: "r1" } });
    await screen.findByRole("link", { name: "db-host" });
    expect(await row("db-host").findByText("A staged rollout runs; let it end first.")).toBeTruthy();
    cleanup();
    page({ refuse: true });
    await screen.findByRole("link", { name: "db-host" });
    fireEvent.click(await row("db-host").findByRole("button", { name: "Update to 1.5.0" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(dialog.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
    expect(await row("db-host").findByRole("alert")).toBeTruthy();
  });

  it("is not shown to someone who is no Instance Admin", async () => {
    page({ admin: false });
    await screen.findByRole("link", { name: "db-host" });
    expect(screen.queryByRole("button", { name: /^Update/ })).toBeNull();
  });
});
