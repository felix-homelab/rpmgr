// SPDX-License-Identifier: Apache-2.0

import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { CAKeyKind, CAKeyState, PkiService, type CAKeySchema } from "@/gen/rpmgr/v1/pki_pb";
import { InstanceSettingsSchema, PasswordHashProfile, SettingsService, type UpdateInstanceSettingsRequest } from "@/gen/rpmgr/v1/settings_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const at = (iso: string) => timestampFromDate(new Date(iso));
const days = (n: number) => ({ seconds: BigInt(n * 86400), nanos: 0 });

function key(kind: CAKeyKind, state: CAKeyState, subject: string, rotate?: string) {
  return { kind, state, subject, notBefore: at("2026-10-01T00:00:00Z"), notAfter: at("2027-10-01T00:00:00Z"), rotateTime: rotate ? at(rotate) : undefined };
}

function page({ admin = true, failRotate = false } = {}) {
  const calls = { rotate: 0, status: 0, settings: [] as UpdateInstanceSettingsRequest[] };
  let keys: MessageInitShape<typeof CAKeySchema>[] = [
    key(CAKeyKind.CA_KEY_KIND_ROOT, CAKeyState.CA_KEY_STATE_ACTIVE, "CN=rpmgr root"),
    key(CAKeyKind.CA_KEY_KIND_INTERMEDIATE, CAKeyState.CA_KEY_STATE_ACTIVE, "CN=rpmgr intermediate 1", "2027-04-01T00:00:00Z"),
    key(CAKeyKind.CA_KEY_KIND_CONFIG_SIGNING, CAKeyState.CA_KEY_STATE_NEXT, "CN=rpmgr config signing 2"),
  ];
  let steppedUp = false;
  const view = show("/settings/pki", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", instanceAdmin: admin, memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: () => ((steppedUp = true), {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(PkiService, {
      getPkiStatus: () => (calls.status++, { trustDomain: "td-7f3a.rpmgr.internal", rootPin: "sha256:Zm9vYmFy", keys }),
      rotateIntermediate: () => {
        if (!steppedUp) {
          throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
        }
        if (failRotate) {
          throw apiError(Code.FailedPrecondition);
        }
        calls.rotate++;
        const next = key(CAKeyKind.CA_KEY_KIND_INTERMEDIATE, CAKeyState.CA_KEY_STATE_ACTIVE, "CN=rpmgr intermediate 2", "2027-04-09T00:00:00Z");
        keys = [keys[0]!, next, { ...keys[1]!, state: CAKeyState.CA_KEY_STATE_RETIRED, rotateTime: undefined }, keys[2]!];
        return { intermediate: next };
      },
    });
    router.service(SettingsService, {
      getInstanceSettings: () => ({
        settings: create(InstanceSettingsSchema, { leafCertificateLifetime: days(30), expiredCertificateGrace: days(7), passwordHashProfile: PasswordHashProfile.DEFAULT }),
        etag: "i1",
      }),
      updateInstanceSettings: (req) => (calls.settings.push(req), { settings: req.settings, etag: "i2" }),
    });
  });
  return { ...view, calls };
}

const keysRegion = async () => within(await screen.findByRole("region", { name: "Certificate authority" }));

describe("Pki", () => {
  it("shows the trust domain, the root's pin and every key with its state", async () => {
    page();
    const region = await keysRegion();
    expect(await region.findByText("td-7f3a.rpmgr.internal")).toBeTruthy();
    expect(region.getByLabelText("Root pin, for rpmgr enroll --ca-pin").textContent).toBe("sha256:Zm9vYmFy");
    const rows = region.getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell").map((c) => c.textContent));
    expect(rows.map((r) => [r[0], r[1], r[2]])).toEqual([
      ["Root", "Active", "CN=rpmgr root"],
      ["Intermediate", "Active", "CN=rpmgr intermediate 1"],
      ["Snapshot signing", "Next", "CN=rpmgr config signing 2"],
    ]);
    expect(rows[0]![4]).toBe("—");
    expect(rows[1]![4]).not.toBe("—");
  });

  it("rotates the intermediate after a confirmation and a step-up, and shows the new one", async () => {
    const { calls } = page();
    const region = await keysRegion();
    fireEvent.click(await region.findByRole("button", { name: "Rotate the intermediate now…" }));
    expect(region.getByText(/^Make a new intermediate active now\?/)).toBeTruthy();
    fireEvent.click(region.getByRole("button", { name: "Rotate it" }));
    const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));
    expect(await region.findByText("A new intermediate is active.")).toBeTruthy();
    expect(calls.rotate).toBe(1);
    expect(await region.findByText("CN=rpmgr intermediate 2")).toBeTruthy();
    const old = region.getByText("CN=rpmgr intermediate 1").closest("tr")!;
    expect(within(old).getByText("Retired")).toBeTruthy();
    expect(region.getByRole("button", { name: "Rotate the intermediate now…" })).toBeTruthy();
  });

  it("rotates nothing when the confirmation is cancelled", async () => {
    const { calls } = page();
    const region = await keysRegion();
    fireEvent.click(await region.findByRole("button", { name: "Rotate the intermediate now…" }));
    fireEvent.click(region.getByRole("button", { name: "Cancel" }));
    expect(region.queryByRole("button", { name: "Rotate it" })).toBeNull();
    expect(calls.rotate).toBe(0);
  });

  it("shows why the rotation failed", async () => {
    page({ failRotate: true });
    const region = await keysRegion();
    fireEvent.click(await region.findByRole("button", { name: "Rotate the intermediate now…" }));
    fireEvent.click(region.getByRole("button", { name: "Rotate it" }));
    const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));
    expect((await region.findByRole("alert")).textContent).toBe("api error");
    expect(region.getByRole("button", { name: "Rotate it" })).toBeTruthy();
  });

  it("saves the leaf-certificate lifetime, the grace period and the password-hash profile, and nothing else", async () => {
    const { calls } = page();
    const form = within(await screen.findByRole("form", { name: "Agent certificates and passwords" }));
    fireEvent.change(form.getByLabelText("Agent certificate lifetime (days)"), { target: { value: "14" } });
    fireEvent.change(form.getByLabelText("Grace after expiry (days, 0 for none)"), { target: { value: "0" } });
    fireEvent.change(form.getByLabelText("Password hashing"), { target: { value: String(PasswordHashProfile.LOW_MEMORY) } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.settings).toHaveLength(1));
    const req = calls.settings[0]!;
    expect(req.updateMask?.paths).toEqual(["leaf_certificate_lifetime", "expired_certificate_grace", "password_hash_profile"]);
    expect(req.settings?.leafCertificateLifetime?.seconds).toBe(14n * 86400n);
    expect(req.settings?.expiredCertificateGrace?.seconds).toBe(0n);
    expect(req.settings?.passwordHashProfile).toBe(PasswordHashProfile.LOW_MEMORY);
  });

  it("shows nothing of the PKI to others than the Instance Admin", async () => {
    const { calls } = page({ admin: false });
    expect(await screen.findByText("Only the Instance Admin sees and changes these.")).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Certificate authority" })).toBeNull();
    expect(calls.status).toBe(0);
  });
});
