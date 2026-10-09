// SPDX-License-Identifier: Apache-2.0

import { clone, create } from "@bufbuild/protobuf";
import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import {
  InstanceSettingsSchema, OrgSettingsSchema, SettingsService, SmtpSecurity, TransportPolicy, UpdateChannel,
  type InstanceSettings, type OrgSettings, type UpdateInstanceSettingsRequest, type UpdateOrgSettingsRequest,
} from "@/gen/rpmgr/v1/settings_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const days = (n: number) => ({ seconds: BigInt(n * 86400), nanos: 0 });

const instance = create(InstanceSettingsSchema, {
  defaultTransport: TransportPolicy.AUTO,
  leafCertificateLifetime: days(30),
  expiredCertificateGrace: days(7),
  releaseCheck: true,
  publicUrlAliases: ["https://alias.example.com"],
  hourlyRollupRetention: days(14),
  dailyRollupRetention: days(400),
  auditRetention: days(365),
  smtp: { server: "mail.example.com:587", from: "rpmgr@example.com", username: "relay", security: SmtpSecurity.STARTTLS },
});

function page({ role = "owner", admin = false, passwordSet = false, path = "/settings", revocationLog = { sink: true } as object } = {}) {
  const calls = { org: [] as UpdateOrgSettingsRequest[], instance: [] as UpdateInstanceSettingsRequest[], password: [] as string[] };
  const state = { org: create(OrgSettingsSchema, { requireMfa: false, operatorsMayEnroll: false }) as OrgSettings, orgEtag: "o1",
    instance: clone(InstanceSettingsSchema, instance) as InstanceSettings, instanceEtag: "i1", passwordSet, conflict: false };
  let steppedUp = false;
  const view = show(path, auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", instanceAdmin: admin, memberships: [{ orgId: "org_1", role }] }),
    stepUp: () => ((steppedUp = true), {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGatewayGroups: () => ({ gatewayGroups: [{ id: "gwg_edge", orgId: "org_1", name: "edge" }] }) });
    router.service(SettingsService, {
      getOrgSettings: () => ({ settings: state.org, etag: state.orgEtag }),
      updateOrgSettings: (req) => {
        if (req.settings?.requireMfa !== state.org.requireMfa && !steppedUp) {
          throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
        }
        calls.org.push(req);
        state.org = req.settings!;
        state.orgEtag = "o2";
        return { settings: state.org, etag: state.orgEtag };
      },
      getInstanceSettings: () => ({ settings: state.instance, etag: state.instanceEtag, smtpPasswordSet: state.passwordSet, revocationLog }),
      updateInstanceSettings: (req) => {
        if (state.conflict) {
          state.conflict = false;
          state.instance = clone(InstanceSettingsSchema, instance);
          state.instance.acmeEmail = "ops@example.com";
          state.instanceEtag = "i9";
          throw apiError(Code.FailedPrecondition, "ETAG_MISMATCH");
        }
        if ((req.settings?.hourlyRollupRetention?.seconds ?? 0n) > 400n * 86400n) {
          throw apiError(Code.InvalidArgument);
        }
        calls.instance.push(req);
        return { settings: req.settings, etag: "i2" };
      },
      setSmtpPassword: (req) => {
        calls.password.push(req.password);
        state.passwordSet = req.password !== "";
        return {};
      },
    });
  });
  return { ...view, calls, state };
}

const orgForm = () => within(screen.getByRole("form", { name: "Organisation settings" }));
const instanceForm = async () => within(await screen.findByRole("form", { name: "Instance settings" }));

describe("Settings", () => {
  it("saves the org's settings with their mask and etag, and asks for a step-up to require MFA", async () => {
    const { calls } = page();
    await screen.findByRole("option", { name: "edge" });
    fireEvent.click(orgForm().getByLabelText("Operators may enroll and revoke connectors"));
    fireEvent.change(orgForm().getByLabelText("Gateway group preselected for new routes"), { target: { value: "gwg_edge" } });
    fireEvent.click(orgForm().getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.org).toHaveLength(1));
    expect(calls.org[0]).toMatchObject({ orgId: "org_1", etag: "o1", settings: { operatorsMayEnroll: true, defaultGatewayGroupId: "gwg_edge", requireMfa: false } });
    expect(calls.org[0]!.updateMask?.paths).toEqual(["require_mfa", "operators_may_enroll", "default_gateway_group_id"]);
    expect(await screen.findByText("Saved.")).toBeTruthy();

    await waitFor(() => expect((orgForm().getByLabelText("Operators may enroll and revoke connectors") as HTMLInputElement).checked).toBe(true));
    fireEvent.click(orgForm().getByLabelText("Every member must sign in with a second factor"));
    fireEvent.click(orgForm().getByRole("button", { name: "Save" }));
    const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(calls.org).toHaveLength(2));
    expect(calls.org[1]).toMatchObject({ etag: "o2", settings: { requireMfa: true } });
  });

  it("shows the org's settings read-only to members other than the Owner, and no instance settings", async () => {
    page({ role: "admin" });
    expect(await screen.findByText("Only the organisation's Owner changes these.")).toBeTruthy();
    await waitFor(() => expect(orgForm().getByRole("button", { name: "Save" }).matches(":disabled")).toBe(true));
    expect(orgForm().getByLabelText("Every member must sign in with a second factor").matches(":disabled")).toBe(true);
    expect(screen.queryByRole("form", { name: "Instance settings" })).toBeNull();
  });

  it("saves the instance's settings as read with the changed fields, every field's mask and the etag", async () => {
    const { calls } = page({ admin: true });
    const form = await instanceForm();
    expect((form.getByLabelText("Keep hourly statistics (days)") as HTMLInputElement).value).toBe("14");
    expect((form.getByLabelText("Further public URLs of the web UI") as HTMLTextAreaElement).value).toBe("https://alias.example.com");
    expect(form.queryByLabelText("Agent certificate lifetime (days)")).toBeNull();
    expect(form.queryByLabelText("Check for releases once a day")).toBeNull();
    fireEvent.change(form.getByLabelText("Keep hourly statistics (days)"), { target: { value: " 7 " } });
    fireEvent.change(form.getByLabelText("Default transport"), { target: { value: String(TransportPolicy.QUIC) } });
    fireEvent.change(form.getByLabelText("Controller endpoints for agents"), { target: { value: "https://a.example.com\n\n https://b.example.com " } });
    fireEvent.change(form.getByLabelText("Keep audit entries (days)"), { target: { value: "" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.instance).toHaveLength(1));
    const req = calls.instance[0]!;
    expect(req.etag).toBe("i1");
    expect(req.updateMask?.paths).toEqual([
      "default_transport", "public_url_aliases", "controller_endpoints", "hourly_rollup_retention", "daily_rollup_retention",
      "acme_directory_url", "acme_email", "smtp", "audit_retention",
    ]);
    expect(req.settings?.defaultTransport).toBe(TransportPolicy.QUIC);
    expect(req.settings?.hourlyRollupRetention?.seconds).toBe(7n * 86400n);
    expect(req.settings?.leafCertificateLifetime?.seconds).toBe(30n * 86400n);
    expect(req.settings?.controllerEndpoints).toEqual(["https://a.example.com", "https://b.example.com"]);
    expect(req.settings?.auditRetention).toBeUndefined();
    expect(req.settings?.smtp).toMatchObject({ server: "mail.example.com:587", from: "rpmgr@example.com", username: "relay" });
    expect(await screen.findByText("Saved.")).toBeTruthy();
  });

  it("sends no mail relay when its server is emptied", async () => {
    const { calls } = page({ admin: true });
    const form = await instanceForm();
    fireEvent.change(form.getByLabelText("Relay host:port"), { target: { value: "  " } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.instance).toHaveLength(1));
    expect(calls.instance[0]!.settings?.smtp).toBeUndefined();
    expect(calls.instance[0]!.updateMask?.paths).toContain("smtp");
  });

  it("refuses days that are not whole numbers before calling the server", async () => {
    const { calls } = page({ admin: true });
    const form = await instanceForm();
    fireEvent.change(form.getByLabelText("Keep hourly statistics (days)"), { target: { value: "1.5" } });
    fireEvent.change(form.getByLabelText("Keep daily statistics (days)"), { target: { value: "-3" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Enter whole days for: Keep hourly statistics (days), Keep daily statistics (days).");
    expect(calls.instance).toEqual([]);
  });

  it("shows the server's refusal and keeps the form as typed", async () => {
    const { calls } = page({ admin: true });
    const form = await instanceForm();
    fireEvent.change(form.getByLabelText("Keep hourly statistics (days)"), { target: { value: "401" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    expect((await screen.findByRole("alert")).textContent).toBe("api error");
    expect((form.getByLabelText("Keep hourly statistics (days)") as HTMLInputElement).value).toBe("401");
    expect(calls.instance).toEqual([]);
  });

  it("reloads the settings when someone else changed them since they were read", async () => {
    const { state, calls } = page({ admin: true });
    state.conflict = true;
    const form = await instanceForm();
    fireEvent.change(form.getByLabelText("Keep hourly statistics (days)"), { target: { value: "5" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/^The settings changed since this page loaded them/);
    const reloaded = await instanceForm();
    await waitFor(() => expect((reloaded.getByLabelText("ACME account e-mail address") as HTMLInputElement).value).toBe("ops@example.com"));
    expect((reloaded.getByLabelText("Keep hourly statistics (days)") as HTMLInputElement).value).toBe("14");
    fireEvent.click(reloaded.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.instance.map((r) => r.etag)).toEqual(["i9"]));
  });

  it("sets and removes the relay password, which it never shows", async () => {
    const { calls } = page({ admin: true });
    const form = within(await screen.findByRole("form", { name: "Relay password" }));
    const input = form.getByLabelText("Relay password") as HTMLInputElement;
    expect(input.placeholder).toBe("not set");
    expect((form.getByRole("button", { name: "Remove the password" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(input, { target: { value: "s3cret-relay" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    expect(await form.findByText("The relay password is saved.")).toBeTruthy();
    await waitFor(() => expect(input.placeholder).toBe("set; type to replace"));
    expect(input.value).toBe("");
    fireEvent.click(form.getByRole("button", { name: "Remove the password" }));
    expect(await form.findByText("The relay password is removed.")).toBeTruthy();
    expect(calls.password).toEqual(["s3cret-relay", ""]);
  });

  it("saves only the release check and the channel on the Updates page", async () => {
    const { calls } = page({ admin: true, path: "/settings/updates" });
    const form = within(await screen.findByRole("form", { name: "Updates" }));
    fireEvent.click(form.getByLabelText("Check for releases once a day"));
    fireEvent.change(form.getByLabelText("Release channel"), { target: { value: String(UpdateChannel.PRERELEASE) } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.instance).toHaveLength(1));
    expect(calls.instance[0]!.updateMask?.paths).toEqual(["release_check", "update_channel"]);
    expect(calls.instance[0]!.settings).toMatchObject({ releaseCheck: false, updateChannel: UpdateChannel.PRERELEASE });
    expect(screen.queryByRole("form", { name: "Relay password" })).toBeNull();
  });

  it("shows the Updates page only to the Instance Admin", async () => {
    page({ path: "/settings/updates" });
    expect(await screen.findByText("Only the Instance Admin sees and changes these.")).toBeTruthy();
    expect(screen.queryByRole("form", { name: "Updates" })).toBeNull();
  });

  it("warns the Instance Admin of a revocation log without an off-host copy, and alerts on one waiting for its sink", async () => {
    page({ admin: true, revocationLog: { sink: false } });
    const warning = await screen.findByText(/^The revocation log has no copy off this host/);
    expect(warning.getAttribute("role")).toBe("status");
    cleanup();
    page({ admin: true, revocationLog: { sink: true, unshipped: 3n, alert: true, oldestUnshippedTime: { seconds: 1791590400n, nanos: 0 } } });
    expect((await screen.findByRole("alert")).textContent).toMatch(/^The revocation log is not yet off-host: 3 entries have waited since /);
    cleanup();
    page({ admin: true, revocationLog: { sink: true, unshipped: 1n } });
    await screen.findByRole("form", { name: "Instance settings" });
    expect(screen.queryByText(/revocation log/)).toBeNull();
    cleanup();
    page({ revocationLog: { sink: false } });
    await screen.findByRole("form", { name: "Organisation settings" });
    expect(screen.queryByText(/revocation log/)).toBeNull(); // not the Instance Admin
  });
});
