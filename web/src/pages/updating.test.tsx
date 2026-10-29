// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ControllerUpdateState, ReleaseService, ReleaseSource, type ControllerUpdate, type UpdateControllerRequest } from "@/gen/rpmgr/v1/release_pb";
import { InstanceSettingsSchema, SettingsService, UpdateChannel } from "@/gen/rpmgr/v1/settings_pb";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { keepFailure, stepStates, timing, updateSteps } from "@/pages/updating";
import { apiError, auth, show } from "@/testing/api";
import { create } from "@bufbuild/protobuf";

const original = { ...timing };
beforeEach(() => Object.assign(timing, { poll: 15, giveUp: 400 }));
afterEach(() => {
  cleanup();
  keepFailure(undefined);
  Object.assign(timing, original);
});

const state = ControllerUpdateState;

function update(over: Partial<ControllerUpdate> = {}) {
  return { version: "1.6.0", state: state.UPDATING, step: "", reason: "", previous: "1.5.0", ...over };
}

describe("stepStates", () => {
  it("marks the reported step current, the earlier ones done and the later ones pending", () => {
    expect(stepStates(undefined, false, false, 1)).toEqual(["done", "current", "pending", "pending", "pending", "pending"]);
    expect(stepStates(update({ step: "backing_up" }) as ControllerUpdate, false, false, 1))
      .toEqual(["done", "done", "current", "pending", "pending", "pending"]);
    expect(stepStates(update({ step: "waiting" }) as ControllerUpdate, false, false, 1)).toEqual(["done", "done", "done", "done", "current", "pending"]);
  });
  it("never goes back to an earlier step, as while the controller is down", () => {
    expect(stepStates(undefined, false, false, 3)[3]).toBe("current");
  });
  it("marks the step reached as failed, and every step done when the new version answers", () => {
    expect(stepStates(undefined, false, true, 2)).toEqual(["done", "done", "failed", "pending", "pending", "pending"]);
    expect(stepStates(undefined, true, false, 1)).toEqual(updateSteps.map(() => "done"));
  });
});

// updating shows the page for an update from 1.5.0 to 1.6.0, with a session that answers as
// answers says, in order, and an update as updates says.
function updating(answers: (n: number) => object | Error, updates: () => { update?: ReturnType<typeof update> }) {
  let n = 0;
  return show("/updating?to=1.6.0&from=1.5.0", auth({
    getSession: () => {
      const a = answers(n++);
      if (a instanceof Error) throw a;
      return { userId: "usr_ada", displayName: "Ada", ...a };
    },
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: 0 } }) });
    router.service(ReleaseService, { getControllerUpdate: () => ({ runningVersion: "1.5.0", ...updates() }) });
  });
}

describe("Updating", () => {
  it("shows the steps and the step the updater reports", async () => {
    updating(() => ({ controllerVersion: "1.5.0" }), () => ({ update: update({ step: "backing_up" }) }));
    expect(await screen.findByRole("heading", { name: "Updating the controller to 1.6.0" })).toBeTruthy();
    const steps = within(screen.getByRole("list", { name: "Steps of the update" })).getAllByRole("listitem");
    expect(steps.map((s) => s.textContent?.split("the")[0]?.trim())).toEqual(["Downloading", "Verifying", "Backing up", "Handing over", "Migrating", "Ready"]);
    await waitFor(() => expect(steps[2]!.getAttribute("aria-current")).toBe("step"));
  });

  it("says that the controller restarts while it answers nothing, and goes to the dashboard when the new version answers", async () => {
    const view = updating((n) => (n < 3 ? new ConnectError("unavailable", Code.Unavailable) : { controllerVersion: "1.6.0",
      memberships: [{ orgId: "org_1", role: "owner" }] }), () => ({ update: update({ step: "handing_over" }) }));
    expect(await screen.findByText("The controller is restarting…")).toBeTruthy();
    await waitFor(() => expect(view.history.location.pathname).toBe("/"));
  });

  it("says that the old version still runs, with the reason, when the update rolled back", async () => {
    updating(() => ({ controllerVersion: "1.5.0" }), () => ({ update: update({ state: state.ROLLED_BACK,
      reason: "the database was migrated by 1.6.0 and restored from /usr/local/bin/rpmgr.backup" }) }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Version 1.5.0 still runs.");
    expect(alert.textContent).toContain("restored from /usr/local/bin/rpmgr.backup");
    expect(screen.getByRole("link", { name: "Go to the dashboard" })).toBeTruthy();
    expect(screen.queryByText("The controller is restarting…")).toBeNull();
  });

  it("says that nothing changed when the updater refused, and which step failed", async () => {
    updating(() => ({ controllerVersion: "1.5.0" }), () => ({ update: update({ state: state.REFUSED, reason: "the backup of the all-in-one failed, so nothing was updated" }) }));
    expect((await screen.findByRole("alert")).textContent).toContain("so nothing was updated");
    const steps = within(screen.getByRole("list", { name: "Steps of the update" })).getAllByRole("listitem");
    expect(steps[1]!.querySelector(".text-destructive")).toBeTruthy();
  });

  it("keeps the failure in memory, so that it shows after the sign-in a restore causes", async () => {
    updating(() => ({ controllerVersion: "1.5.0" }), () => ({ update: update({ state: state.ROLLED_BACK, reason: "restored from /usr/local/bin/rpmgr.backup, taken 2026-10-29T12:00:00Z" }) }));
    await screen.findByRole("alert");
    cleanup();
    // The controller then asks for a sign-in and answers nothing else: the stored failure is shown.
    updating(() => new ConnectError("unavailable", Code.Unavailable), () => { throw new ConnectError("unavailable", Code.Unavailable); });
    expect((await screen.findAllByRole("alert"))[0]!.textContent).toContain("still runs");
    expect(screen.getByText(/changes made after it was taken/)).toBeTruthy();
  });

  it("stops asking after it gave up", async () => {
    let asked = 0;
    updating(() => (asked++, new ConnectError("unavailable", Code.Unavailable)), () => { throw new ConnectError("unavailable", Code.Unavailable); });
    await screen.findByText(/systemctl status rpmgr-update/);
    const then = asked;
    await new Promise((r) => setTimeout(r, 120));
    expect(asked).toBe(then);
  });

  it("warns that the previous version could not be put back", async () => {
    updating(() => new ConnectError("unavailable", Code.Unavailable), () => ({ update: update({ state: state.ROLLBACK_FAILED, reason: "restoring failed" }) }));
    // The first answer of the update comes before the session fails; the page keeps it.
    expect((await screen.findByRole("alert")).textContent).toContain("could not be put back");
  });

  it("sends the user to sign in when the controller answers but the session ended, as after a restore", async () => {
    const view = updating(() => apiError(Code.Unauthenticated), () => ({}));
    await waitFor(() => expect(view.history.location.pathname).toBe("/login"));
  });

  it("gives up with a pointer to the host when nothing answers for too long", async () => {
    updating(() => new ConnectError("unavailable", Code.Unavailable), () => { throw new ConnectError("unavailable", Code.Unavailable); });
    expect((await screen.findByRole("alert")).textContent).toContain("systemctl status rpmgr-update");
  });

  it("ignores an update of another version", async () => {
    updating(() => ({ controllerVersion: "1.5.0" }), () => ({ update: update({ version: "1.7.0", state: state.ROLLED_BACK, reason: "old" }) }));
    expect(await screen.findByRole("heading", { name: "Updating the controller to 1.6.0" })).toBeTruthy();
    await new Promise((r) => setTimeout(r, 80));
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

function release(version: string, over: Partial<{ newerThanController: boolean; mirrored: boolean; controllerVersion: boolean }> = {}) {
  return { id: `rel_${version}`, version, channel: UpdateChannel.STABLE, manifestSeq: 7n, source: ReleaseSource.CHECK, mirrored: over.mirrored ?? true,
    createTime: { seconds: 1791590400n, nanos: 0 }, controllerVersion: over.controllerVersion ?? false, newerThanController: over.newerThanController ?? false };
}

// settings shows /settings/updates for the controller 1.5.0 with a release 1.6.0 and the state of
// the update and of the rollouts as given.
function settings(o: { byHand?: boolean; mirrored?: boolean; blocked?: string; running?: boolean; update?: ControllerUpdate; admin?: boolean; fails?: boolean } = {}) {
  const calls: UpdateControllerRequest[] = [];
  let steppedUp = false;
  const view = show("/settings/updates", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", instanceAdmin: o.admin ?? true, controllerVersion: "1.5.0",
      memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: () => (steppedUp = true, {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: 0 } }) });
    router.service(SettingsService, {
      getInstanceSettings: () => ({ settings: create(InstanceSettingsSchema, { releaseCheck: true, updateChannel: UpdateChannel.STABLE }), etag: "i1" }),
    });
    router.service(ReleaseService, {
      listReleases: () => ({ releases: [release("1.6.0", { newerThanController: true, mirrored: o.mirrored ?? true }),
        release("1.5.0", { controllerVersion: true })], controllerVersion: "1.5.0" }),
      listRollouts: () => ({ rollouts: o.running ? [{ id: "rol_1", releaseId: "rel_1.5.0", version: "1.5.0", stage: 1, percentage: 0, state: 1, etag: "r1",
        counts: { pending: 1 } }] : [] }),
      getControllerUpdate: () => ({ runningVersion: "1.5.0", blocked: o.blocked ?? "", update: o.update, byHand: o.byHand ?? false }),
      updateController: (req) => {
        if (!steppedUp) throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
        if (o.fails) throw apiError(Code.FailedPrecondition, "CONTROLLER_UPDATE_REFUSED");
        calls.push(req);
        return { update: update({ state: state.STAGED }) };
      },
    });
  });
  return { ...view, calls };
}

describe("the Update controller button", () => {
  const button = async () => within(await screen.findByRole("region", { name: "Releases" })).findByRole("button", { name: "Update controller to 1.6.0" });

  it("asks for a step-up, updates to the release and opens the Updating page", async () => {
    const view = settings();
    fireEvent.click(await button());
    const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(dialog.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(view.calls.map((c) => c.releaseId)).toEqual(["rel_1.6.0"]));
    await waitFor(() => expect(view.history.location.pathname).toBe("/updating"));
    expect(view.history.location.search).toContain("to=1.6.0");
  });

  it("is only offered for a release newer than the controller", async () => {
    settings();
    await button();
    expect(screen.queryByRole("button", { name: "Update controller to 1.5.0" })).toBeNull();
  });

  for (const [name, o, why] of [
    ["the mirror does not hold the release", { mirrored: false }, "The mirror does not hold it yet."],
    ["a rollout runs", { running: true }, "A rollout runs; let it end first."],
    ["an update is under way", { update: update({ state: state.STAGED }) }, "An update of the controller is under way."],
    ["the host cannot take one", { blocked: "the controller runs on postgres (P2-M08)" }, "the controller runs on postgres (P2-M08)"],
  ] as const) {
    it(`is disabled, with its reason, when ${name}`, async () => {
      settings(o as Parameters<typeof settings>[0]);
      const b = (await button()) as HTMLButtonElement;
      await screen.findByText(why);
      expect(b.disabled).toBe(true);
    });
  }

  it("shows the by-hand text instead of the button for a controller that cannot update itself yet", async () => {
    settings({ byHand: true });
    expect(await screen.findByText(/Update this controller by hand once \(install.sh --upgrade --restart\); later updates can start here/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Update controller to 1.6.0" })).toBeNull();
  });

  it("shows what the controller refused, and stays on the page", async () => {
    const view = settings({ fails: true });
    fireEvent.click(await button());
    const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(dialog.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
    expect((await screen.findAllByRole("alert")).length).toBeGreaterThan(0);
    expect(view.history.location.pathname).toBe("/settings/updates");
  });
});
