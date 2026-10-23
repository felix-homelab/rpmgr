// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import {
  ReleaseService, ReleaseSource, RolloutStage, RolloutState,
  type AdvanceRolloutRequest, type CreateRolloutRequest, type PauseRolloutRequest,
  type ResumeRolloutRequest, type CancelRolloutRequest, type UploadReleaseRequest,
} from "@/gen/rpmgr/v1/release_pb";
import { InstanceSettingsSchema, SettingsService, UpdateChannel } from "@/gen/rpmgr/v1/settings_pb";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";
import { create } from "@bufbuild/protobuf";

afterEach(cleanup);

// confirmStepUp fills the step-up dialog the API's STEP_UP_REQUIRED opens.
async function confirmStepUp() {
  const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
  fireEvent.change(dialog.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
}

// release is a release the controller recorded; controller and newer are the two marks the page
// shows.
function release(version: string, over: Partial<{ id: string; mirrored: boolean; controllerVersion: boolean; newerThanController: boolean }> = {}) {
  return { id: over.id ?? `rel_${version}`, version, channel: UpdateChannel.STABLE, manifestSeq: 7n,
    source: ReleaseSource.CHECK, mirrored: over.mirrored ?? true, createTime: { seconds: 1791590400n, nanos: 0 },
    controllerVersion: over.controllerVersion ?? false, newerThanController: over.newerThanController ?? false };
}

// rollout is a rollout the page follows, with its counts.
function rollout(over: Partial<{ id: string; state: RolloutState; stage: RolloutStage; percentage: number; pauseReason: string }> = {}) {
  return { id: over.id ?? "rol_1", releaseId: "rel_1.5.0", version: "1.5.0", stage: over.stage ?? RolloutStage.PERCENTAGE,
    percentage: over.percentage ?? 25, state: over.state ?? RolloutState.RUNNING, pauseReason: over.pauseReason ?? "", etag: "r1",
    counts: { pending: 4, offered: 2, staged: 1, updated: 31, rolledBack: 1, refused: 0, skipped: 6, stalled: 0 } };
}

function page({ admin = true, active, target, wrongEtag = false } = {} as {
  admin?: boolean;
  active?: ReturnType<typeof rollout>;
  target?: Record<string, unknown>;
  wrongEtag?: boolean;
}) {
  const calls = {
    create: [] as CreateRolloutRequest[], advance: [] as AdvanceRolloutRequest[], pause: [] as PauseRolloutRequest[],
    resume: [] as ResumeRolloutRequest[], cancel: [] as CancelRolloutRequest[], upload: [] as UploadReleaseRequest[], steppedUp: 0,
  };
  let current = active;
  let steppedUp = false;
  // guarded is a call that needs a step-up: the first call asks for one, as the API does, and the
  // retry runs.
  const guarded = <T,>(f: () => T): T => {
    if (!steppedUp) throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
    steppedUp = false;
    return f();
  };
  const view = show("/settings/updates", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", instanceAdmin: admin,
      memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: () => (calls.steppedUp++, steppedUp = true, {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: 0 } }) });
    router.service(SettingsService, {
      getInstanceSettings: () => ({ settings: create(InstanceSettingsSchema, { releaseCheck: true, updateChannel: UpdateChannel.STABLE }), etag: "i1" }),
      updateInstanceSettings: (req) => ({ settings: req.settings, etag: "i2" }),
    });
    router.service(ConnectorService, {
      listConnectors: () => ({ connectors: [{ id: "con_db", name: "db-host", enabled: true, ephemeral: false, labels: {}, transport: 0 }] }),
    });
    router.service(GatewayService, {
      listGateways: () => ({ gateways: [{ id: "gw_1", gatewayGroupId: "ggr_1", name: "edge", slot: 1, tunnelEndpoints: ["edge:443"], enabled: true }] }),
    });
    router.service(ReleaseService, {
      listReleases: () => ({ releases: [release("1.5.0"), release("1.4.2", { controllerVersion: true }), release("1.6.0", { newerThanController: true, mirrored: false }), release("1.3.0", { mirrored: false })], controllerVersion: "1.4.2" }),
      listRollouts: () => ({ rollouts: current ? [current] : [] }),
      listRolloutTargets: () => ({ rolloutTargets: target ? [target] : [] }),
      createRollout: (req) => guarded(() => (calls.create.push(req), { rollout: current ?? rollout() })),
      advanceRollout: (req) => guarded(() => {
        if (wrongEtag) throw apiError(Code.FailedPrecondition, "ETAG_MISMATCH");
        calls.advance.push(req);
        current = { ...(current ?? rollout()), stage: RolloutStage.ALL, percentage: 100 };
        return { rollout: current };
      }),
      pauseRollout: (req) => (calls.pause.push(req), { rollout: { ...(current ?? rollout()), state: RolloutState.PAUSED } }),
      resumeRollout: (req) => guarded(() => (calls.resume.push(req), { rollout: { ...(current ?? rollout()), state: RolloutState.RUNNING } })),
      cancelRollout: (req) => guarded(() => (calls.cancel.push(req), { rollout: { ...(current ?? rollout()), state: RolloutState.CANCELLED } })),
      uploadRelease: (req) => guarded(() => (calls.upload.push(req), { release: release("1.5.0") })),
    });
  });
  return { ...view, calls };
}

describe("Updates", () => {
  it("lists the releases with their source, mirror and controller marks, and offers rollouts of every release no newer than the controller, mirrored or not", async () => {
    page();
    const card = within(await screen.findByRole("region", { name: "Releases" }));
    const rows = (await card.findAllByRole("row")).slice(1).map((r) => within(r).getAllByRole("cell").map((c) => c.textContent));
    expect(rows.map((r) => r.slice(0, 5))).toEqual([
      ["1.5.0", "stable", "release check", "yes", "—"],
      ["1.4.2", "stable", "release check", "yes", "this controller"],
      ["1.6.0", "stable", "release check", "no", "newer than this controller"],
      ["1.3.0", "stable", "release check", "no", "—"],
    ]);
    const buttons = card.getAllByRole("button", { name: "Roll out…" }) as HTMLButtonElement[];
    expect(buttons.map((b) => b.disabled)).toEqual([false, false, true, false]);
  });

  it("uploads the four signed files after a step-up", async () => {
    const { calls } = page();
    const card = within(await screen.findByRole("region", { name: "Releases" }));
    fireEvent.click(card.getByRole("button", { name: "Upload release…" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Upload a release" }));
    for (const [label, body] of [["signing-key.json", "statement"], ["signing-key.json.minisig", "st-sig"],
      ["manifest.json", "manifest"], ["manifest.json.minisig", "m-sig"]] as const) {
      fireEvent.change(dialog.getByLabelText(label), { target: { files: [new File([body], label)] } });
    }
    fireEvent.click(dialog.getByRole("button", { name: "Upload" }));
    await confirmStepUp();
    await waitFor(() => expect(calls.upload).toHaveLength(1));
    expect(new TextDecoder().decode(calls.upload[0]!.manifest)).toBe("manifest");
    expect(new TextDecoder().decode(calls.upload[0]!.signingKeyStatement)).toBe("statement");
    expect(calls.steppedUp).toBe(1);
  });

  it("shows nothing but the way back to others", async () => {
    page({ admin: false });
    expect(await screen.findByText("Only the Instance Admin sees and changes these.")).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Releases" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Rollout" })).toBeNull();
  });
});
