// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import {
  DnsRecordState, DnsZoneService, ZoneDelegationState, ZoneProviderStatus, ZoneSyncState,
  type AdoptRecordsRequest, type ApproveZonePlanRequest, type ListZoneRecordsRequest, type PlanZoneSyncRequest, type ReleaseRecordRequest, type RemoveZoneRequest, type UpdateZoneRequest,
} from "@/gen/rpmgr/v1/dns_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";
import { RecordContent } from "@/pages/dns-records";

afterEach(cleanup);

const hash1 = "9f3c".padEnd(62, "0") + "e1";
const hash2 = "7a10".padEnd(62, "0") + "b2";
const wipeHash = "55aa".padEnd(62, "0") + "c3";

const held = { id: "dnz_1", name: "example.com", dnsProviderId: "dnp_1", providerZoneId: "pz1", syncState: ZoneSyncState.HELD, heldReason: "imported",
  providerStatus: ZoneProviderStatus.OK, publishRouteHostnames: true, deleteThreshold: 10, etag: "5" };

const plan = (hash: string) => ({
  creates: [{ id: "", name: "wiki.example.com", type: "CNAME", content: "eu.gw.example.net", ttl: 1 }],
  updates: [{ id: "pr_u", name: "api.example.com", type: "A", content: "192.0.2.9", ttl: 1 }],
  deletes: [{ id: "pr_d", name: "old.example.com", type: "A", content: "192.0.2.1", ttl: 1 }],
  conflicts: [
    { name: "grafana.example.com", kind: "foreign_address", records: [{ id: "pr_f", name: "grafana.example.com", type: "A", content: "203.0.113.5", ttl: 1 }] },
    { name: "mail.example.com", kind: "cname_beside_data", records: [{ id: "pr_m", name: "mail.example.com", type: "MX", content: "10 mx.example.net", ttl: 1 }] },
    { name: "sub.example.com", kind: "delegated", records: [{ id: "pr_n", name: "sub.example.com", type: "NS", content: "ns.example.net", ttl: 1 }] },
  ],
  orphans: [{ id: "pr_o", name: "stray.example.com", type: "TXT", content: "marker", ttl: 1 }],
  adoptedChanged: [{ id: "pr_a", name: "app.example.com", type: "A", content: "192.0.2.77", ttl: 1 }],
  shadows: ["wiki.example.com"], lost: [], hash,
});

const owned = [
  { id: "dnr_1", providerRecordId: "pr_1", name: "wiki.example.com", type: "CNAME", content: "eu.gw.example.net", state: DnsRecordState.SYNCED },
  { id: "dnr_2", providerRecordId: "pr_2", name: "app.example.com", type: "A", content: "192.0.2.7", state: DnsRecordState.DRIFTED, reason: "changed twice",
    adoptedTime: { seconds: 1798848000n, nanos: 0 } },
];
const foreign = [
  { id: "", providerRecordId: "pr_f", name: "grafana.example.com", type: "A", content: "203.0.113.5", state: DnsRecordState.FOREIGN, adoptable: true },
  { id: "", providerRecordId: "pr_x", name: "mail.example.com", type: "MX", content: "10 mx.example.net", state: DnsRecordState.FOREIGN, adoptable: false, adoptReason: "type_not_adoptable" },
  { id: "", providerRecordId: "pr_n", name: "www.example.com", type: "A", content: "203.0.113.9", state: DnsRecordState.FOREIGN, adoptable: false, adoptReason: "not_published" },
];

interface Opts { role?: string; updateFails?: Code; zone?: typeof held; planOf?: (n: number) => string; approveFails?: boolean; warning?: string }

function page(opts: Opts = {}) {
  const calls = {
    getZone: 0, plans: [] as PlanZoneSyncRequest[], records: [] as ListZoneRecordsRequest[], approve: [] as ApproveZonePlanRequest[], adopt: [] as AdoptRecordsRequest[],
    release: [] as ReleaseRecordRequest[], remove: [] as RemoveZoneRequest[], update: [] as UpdateZoneRequest[], enable: 0, sync: 0, stepUps: 0,
  };
  let steppedUp = false;
  const needStepUp = () => {
    if (!steppedUp) {
      throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
    }
  };
  let current = opts.zone ?? held;
  show("/dns/dnz_1", auth({
    getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: opts.role ?? "owner" }] }),
    stepUp: () => ((steppedUp = true), calls.stepUps++, {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(DnsZoneService, {
      getZone: () => (calls.getZone++, { dnsZone: current }),
      planZoneSync: (req) => {
        calls.plans.push(req);
        return { dnsZone: current, plan: req.deleteRecords ? { ...plan(wipeHash), creates: [], updates: [], conflicts: [], orphans: [], adoptedChanged: [] } : plan(opts.planOf?.(calls.plans.length) ?? hash1) };
      },
      listZoneRecords: (req) => (calls.records.push(req), { records: req.includeForeign ? [...owned, ...foreign] : owned }),
      approveZonePlan: (req) => {
        needStepUp();
        if (opts.approveFails) {
          throw apiError(Code.FailedPrecondition, "PLAN_CHANGED");
        }
        calls.approve.push(req);
        current = { ...current, syncState: ZoneSyncState.ACTIVE };
        return { dnsZone: current };
      },
      adoptRecords: (req) => (needStepUp(), calls.adopt.push(req), { records: [] }),
      releaseRecord: (req) => (needStepUp(), calls.release.push(req), { warning: opts.warning ?? "" }),
      enableZone: () => (needStepUp(), calls.enable++, { dnsZone: { ...current, syncState: ZoneSyncState.HELD } }),
      syncZone: () => (calls.sync++, { dnsZone: current }),
      updateZone: (req) => {
        if (opts.updateFails !== undefined) {
          throw apiError(opts.updateFails, opts.updateFails === Code.FailedPrecondition ? "ETAG_MISMATCH" : "INVALID_ARGUMENT");
        }
        calls.update.push(req);
        current = { ...current, ...req.dnsZone, etag: "6" } as typeof held;
        return { dnsZone: current };
      },
      removeZone: (req) => {
        needStepUp();
        calls.remove.push(req);
        if (req.deleteRecords) {
          current = { ...current, syncState: ZoneSyncState.DISABLED, removalPending: true } as typeof held;
        }
        return {};
      },
    });
  });
  return calls;
}

async function confirm() {
  const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
  fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));
}

const card = async (name: string) => within(await screen.findByRole("region", { name }));

describe("DNS zone: plan", () => {
  it("shows the plan with its parts, its short hash and a hint for each conflict (U4)", async () => {
    page();
    const p = await card("Plan 9f3c…e1");
    expect(p.getByText("wiki.example.com", { selector: "td" })).toBeTruthy();
    expect(p.getByText("api.example.com")).toBeTruthy();
    expect(p.getByText("old.example.com")).toBeTruthy();
    expect(p.getByText("stray.example.com")).toBeTruthy();
    expect(p.getByText("192.0.2.77")).toBeTruthy();
    expect(p.getByText(/adopted records no longer hold/)).toBeTruthy();
    expect(p.getByText(/Adopt it, or remove it at the provider/)).toBeTruthy();
    expect(p.getByText(/A CNAME cannot share a name with other records/)).toBeTruthy();
    expect(p.getByText(/An NS delegation covers this name/)).toBeTruthy();
    expect(p.getByText(/Orphans carry rpmgr's marker/)).toBeTruthy();
    expect(p.getByText(/no longer follows the foreign wildcard/)).toBeTruthy();
    expect(screen.getByText(/The zone is held: nothing is published/)).toBeTruthy();
  });

  it("approves the plan it showed, bound to its hash, after a confirmation naming it and a step-up", async () => {
    const calls = page();
    const p = await card("Plan 9f3c…e1");
    fireEvent.click(p.getByRole("button", { name: "Approve plan" }));
    expect(p.getByText("Approve plan 9f3c…e1 of example.com? The next pass applies exactly this plan.")).toBeTruthy();
    expect(calls.approve).toHaveLength(0);
    fireEvent.click(p.getByRole("button", { name: "Approve" }));
    await confirm();
    await waitFor(() => expect(calls.approve.map((a) => [a.dnsZoneId, a.planHash])).toEqual([["dnz_1", hash1]]));
    expect(calls.stepUps).toBe(1);
    await waitFor(() => expect(screen.getAllByText("publishing").length).toBeGreaterThan(0));
    expect(screen.queryByRole("button", { name: "Approve plan" })).toBeNull();
  });

  it("warns that the domain is delegated elsewhere, before and in the approval, and says where to point it (#1144)", async () => {
    const calls = page({ zone: { ...held, assignedNameservers: ["ada.ns.example.net", "bob.ns.example.net"], delegationState: ZoneDelegationState.MISMATCH,
      delegationNameservers: ["ns1.lander.example.net"] } as typeof held });
    const warning = await screen.findByText(/example\.com is delegated to ns1\.lander\.example\.net, not to the provider/);
    expect(warning.textContent).toContain("set the nameservers at your registrar to ada.ns.example.net, bob.ns.example.net");
    expect(screen.getByText(/Nameservers at the provider: ada.ns.example.net, bob.ns.example.net/)).toBeTruthy();
    const p = await card("Plan 9f3c…e1");
    fireEvent.click(p.getByRole("button", { name: "Approve plan" }));
    expect(p.getByText(/Approve plan 9f3c…e1 of example.com\?.*is delegated to ns1\.lander\.example\.net/)).toBeTruthy();
    expect(calls.approve).toHaveLength(0);
  });

  it("shows no delegation warning for a zone that is delegated to the provider or not checked", async () => {
    page({ zone: { ...held, assignedNameservers: ["ada.ns.example.net"], delegationState: ZoneDelegationState.OK } as typeof held });
    await card("Plan 9f3c…e1");
    expect(screen.queryByText(/is delegated to/)).toBeNull();
    expect(screen.getByText("Delegated to the provider")).toBeTruthy();
    cleanup();
    page();
    await card("Plan 9f3c…e1");
    expect(screen.queryByText(/is delegated to/)).toBeNull();
    expect(screen.queryByText(/Nameservers at the provider/)).toBeNull();
  });

  it("does not approve when the step-up is cancelled", async () => {
    const calls = page();
    const p = await card("Plan 9f3c…e1");
    fireEvent.click(p.getByRole("button", { name: "Approve plan" }));
    fireEvent.click(p.getByRole("button", { name: "Approve" }));
    const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.click(stepUp.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(calls.approve).toHaveLength(0);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("says the plan changed on a stale hash, reloads the plan and keeps the zone held", async () => {
    const calls = page({ approveFails: true, planOf: (n) => (n === 1 ? hash1 : hash2) });
    const p = await card("Plan 9f3c…e1");
    fireEvent.click(p.getByRole("button", { name: "Approve plan" }));
    fireEvent.click(p.getByRole("button", { name: "Approve" }));
    await confirm();
    expect(await screen.findByText(/The plan changed since it was shown/)).toBeTruthy();
    expect(await screen.findByRole("region", { name: "Plan 7a10…b2" })).toBeTruthy();
    expect(calls.plans.length).toBeGreaterThan(1);
    expect(calls.approve).toHaveLength(0);
    expect(screen.getAllByText("held").length).toBeGreaterThan(0);
  });

  it("adopts the foreign record of a conflict from the plan", async () => {
    const calls = page();
    const p = await card("Plan 9f3c…e1");
    fireEvent.click(p.getByRole("button", { name: "Adopt" }));
    expect(p.getByText(/Adopt A grafana\.example\.com → 203\.0\.113\.5\?/)).toBeTruthy();
    fireEvent.click(p.getByRole("button", { name: "Adopt record" }));
    await confirm();
    await waitFor(() => expect(calls.adopt.map((a) => a.providerRecordIds)).toEqual([["pr_f"]]));
  });

  it("shows no approval for an active zone, and a disabled zone only offers to enable it", async () => {
    page({ zone: { ...held, syncState: ZoneSyncState.ACTIVE } });
    await card("Plan 9f3c…e1");
    expect(screen.queryByRole("button", { name: "Approve plan" })).toBeNull();
    cleanup();
    const calls = page({ zone: { ...held, syncState: ZoneSyncState.DISABLED } });
    fireEvent.click(await screen.findByRole("button", { name: "Enable zone" }));
    await confirm();
    await waitFor(() => expect(calls.enable).toBe(1));
    expect(calls.plans).toHaveLength(0);
    expect(screen.queryByRole("region", { name: /^Plan/ })).toBeNull();
  });

  it("asks for a pass with Sync now", async () => {
    const calls = page();
    fireEvent.click(await screen.findByRole("button", { name: "Sync now" }));
    expect(await screen.findByText(/A full pass was requested/)).toBeTruthy();
    expect(calls.sync).toBe(1);
  });
});

describe("DNS zone: records", () => {
  it("shows an Owner the owned and the foreign records, read with include_foreign", async () => {
    const calls = page();
    const r = await card("Records");
    await r.findByText("grafana.example.com");
    expect(calls.records.map((q) => q.includeForeign)).toEqual([true]);
    expect(r.getByText("wiki.example.com")).toBeTruthy();
    expect(r.getByText("changed twice")).toBeTruthy();
    expect(r.getAllByText("foreign", { selector: "td" })).toHaveLength(3);
    // Only a record the API marks adoptable gets the button; the others say why not.
    expect(r.getAllByRole("button", { name: "Adopt" })).toHaveLength(1);
    expect(r.getAllByText("Not published by rpmgr — create a route or DNS name for this name first, then adopt it from the plan.")).toHaveLength(1);
    expect(r.getAllByText(/does not manage records of this type/)).toHaveLength(1);
  });

  it("adopts a foreign record after a confirmation and a step-up", async () => {
    const calls = page();
    const r = await card("Records");
    fireEvent.click(await r.findByRole("button", { name: "Adopt" }));
    expect(r.getByText(/rpmgr keeps this content for a later release/)).toBeTruthy();
    expect(calls.adopt).toHaveLength(0);
    fireEvent.click(r.getByRole("button", { name: "Adopt record" }));
    await confirm();
    await waitFor(() => expect(calls.adopt.map((a) => [a.dnsZoneId, a.providerRecordIds])).toEqual([["dnz_1", ["pr_f"]]]));
    expect(calls.stepUps).toBe(1);
  });

  it("releases an owned record, keeping it, or restoring it only if it was adopted", async () => {
    const calls = page();
    const r = await card("Records");
    const rows = await r.findAllByRole("button", { name: "Release" });
    fireEvent.click(rows[0]!);
    const restore = r.getByLabelText("Put it back to the content it had when it was adopted") as HTMLInputElement;
    expect(restore.disabled).toBe(true);
    fireEvent.click(r.getByRole("button", { name: "Release it" }));
    fireEvent.click(r.getByRole("button", { name: "Release record" }));
    await confirm();
    await waitFor(() => expect(calls.release.map((x) => [x.recordId, x.restore])).toEqual([["dnr_1", false]]));
    expect(await r.findByText("wiki.example.com is released at the next pass.")).toBeTruthy();
  });

  it("restores an adopted record and shows the staleness warning of the API", async () => {
    const calls = page({ warning: "The original is old: the address may belong to someone else." });
    const r = await card("Records");
    const rows = await r.findAllByRole("button", { name: "Release" });
    fireEvent.click(rows[1]!);
    fireEvent.click(r.getByLabelText("Put it back to the content it had when it was adopted"));
    fireEvent.click(r.getByRole("button", { name: "Release it" }));
    expect(r.getByText("Release A app.example.com and restore its original content?")).toBeTruthy();
    fireEvent.click(r.getByRole("button", { name: "Release record" }));
    await confirm();
    await waitFor(() => expect(calls.release.map((x) => [x.recordId, x.restore])).toEqual([["dnr_2", true]]));
    expect((await r.findByRole("alert")).textContent).toContain("may belong to someone else");
  });

  it("shows an Operator the owned records only: no foreign records, no plan, no approval, no actions", async () => {
    const calls = page({ role: "operator" });
    const r = await card("Records");
    await r.findByText("wiki.example.com");
    expect(calls.records.map((q) => q.includeForeign)).toEqual([false]);
    expect(r.queryByText("grafana.example.com")).toBeNull();
    expect(r.queryByRole("button", { name: "Adopt" })).toBeNull();
    expect(r.queryByRole("button", { name: "Release" })).toBeNull();
    expect(calls.getZone).toBe(0);
    expect(calls.plans).toHaveLength(0);
    expect(screen.queryByRole("button", { name: "Approve plan" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Sync now" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove the zone" })).toBeNull();
    expect(screen.getByText(/You see the records rpmgr owns/)).toBeTruthy();
  });

  it("shows the API's refusal of a record list", async () => {
    show("/dns/dnz_1", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "viewer" }] }) }), (router) => {
      router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
      router.service(DnsZoneService, { listZoneRecords: () => { throw apiError(Code.PermissionDenied, "PERMISSION_MISSING"); } });
    });
    expect(await screen.findByRole("alert")).toBeTruthy();
  });
});

describe("DNS zone: removal", () => {
  it("removes a zone and keeps its records, after a confirmation naming it and a step-up", async () => {
    const calls = page();
    fireEvent.click(await screen.findByRole("button", { name: "Remove the zone" }));
    fireEvent.click(screen.getByRole("button", { name: "Remove it" }));
    expect(screen.getByText("Stop managing example.com? The records stay at the provider.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    await confirm();
    await waitFor(() => expect(calls.remove.map((x) => [x.dnsZoneId, x.etag, x.deleteRecords, x.planHash])).toEqual([["dnz_1", "5", false, ""]]));
    expect(calls.plans.filter((x) => x.deleteRecords)).toHaveLength(0);
  });

  it("deletes the records under the hash of the removal plan and then shows removal pending", async () => {
    const calls = page();
    fireEvent.click(await screen.findByRole("button", { name: "Remove the zone" }));
    fireEvent.click(screen.getByLabelText("Delete the records rpmgr owns, then remove the zone"));
    expect(await screen.findByText(/The job deletes 1 record under plan 55aa…c3/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Remove it" }));
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    await confirm();
    await waitFor(() => expect(calls.remove.map((x) => [x.deleteRecords, x.planHash])).toEqual([[true, wipeHash]]));
    expect((await screen.findAllByText("removal pending")).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Remove the zone" })).toBeNull();
  });

  it("does not offer a zone with a removal pending for removal again", async () => {
    page({ zone: { ...held, syncState: ZoneSyncState.DISABLED, removalPending: true } as typeof held });
    expect((await screen.findAllByText("removal pending")).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Remove the zone" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Enable zone" })).toBeNull();
  });
});

describe("DNS zone: long record content", () => {
  it("cuts long content to one line and keeps the whole value as its tooltip", () => {
    const long = "v=DKIM1; k=rsa; p=" + "A".repeat(400);
    const r = render(<RecordContent content={long} proxied />);
    const cell = r.getByTitle(`${long} (proxied)`);
    expect(cell.textContent).toBe(`${long} (proxied)`);
    expect(cell.className).toContain("truncate");
  });

  it("shows short content whole, without a proxied suffix when not proxied", () => {
    const r = render(<RecordContent content="192.0.2.7" />);
    expect(r.getByTitle("192.0.2.7").textContent).toBe("192.0.2.7");
  });
});

describe("DNS zone: settings", () => {
  it("saves only the changed fields, with the etag, and shows the saved zone", async () => {
    const calls = page();
    const form = within(await screen.findByRole("form", { name: "Settings" }));
    expect((form.getByLabelText("Publish the hostnames of the org's routes in this zone") as HTMLInputElement).checked).toBe(true);
    fireEvent.click(form.getByLabelText("Allow wildcard names"));
    fireEvent.change(form.getByLabelText("Delete threshold"), { target: { value: "25" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.update).toHaveLength(1));
    const req = calls.update[0]!;
    expect(req.updateMask?.paths).toEqual(["allow_wildcards", "delete_threshold"]);
    expect([req.dnsZone?.id, req.dnsZone?.allowWildcards, req.dnsZone?.deleteThreshold, req.etag]).toEqual(["dnz_1", true, 25, "5"]);
    expect(await screen.findByText("The zone's settings are saved.")).toBeTruthy();
    await waitFor(() => expect(calls.getZone).toBeGreaterThan(1));
    expect(calls.stepUps).toBe(0);
    await waitFor(() => expect((within(screen.getByRole("form", { name: "Settings" })).getByLabelText("Allow wildcard names") as HTMLInputElement).checked).toBe(true));
  });

  it("sends nothing when nothing changed", async () => {
    const calls = page();
    fireEvent.click(within(await screen.findByRole("form", { name: "Settings" })).getByRole("button", { name: "Save" }));
    await new Promise((r) => setTimeout(r, 50));
    expect(calls.update).toHaveLength(0);
  });

  it("shows no form to an Operator", async () => {
    page({ role: "operator" });
    expect((await screen.findAllByText(/owns/)).length).toBeGreaterThan(0);
    expect(screen.queryByRole("form", { name: "Settings" })).toBeNull();
    expect(screen.queryByLabelText("Delete threshold")).toBeNull();
  });

  it.each(["", "-1", "1001", "1.5", "abc", "1e2", "99999999999"])("refuses the threshold %j and sends nothing", async (value) => {
    const calls = page();
    const form = within(await screen.findByRole("form", { name: "Settings" }));
    fireEvent.change(form.getByLabelText("Delete threshold"), { target: { value } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    expect(await form.findByText("Enter a whole number from 0 to 1000.")).toBeTruthy();
    expect(calls.update).toHaveLength(0);
  });

  it.each([["0", 0], ["1000", 1000]])("accepts the boundary threshold %s", async (value, n) => {
    const calls = page();
    const form = within(await screen.findByRole("form", { name: "Settings" }));
    fireEvent.change(form.getByLabelText("Delete threshold"), { target: { value } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.update.map((x) => x.dnsZone?.deleteThreshold)).toEqual([n]));
  });

  it("shows the refusal of a change made meanwhile and reloads the zone", async () => {
    const calls = page({ updateFails: Code.FailedPrecondition });
    const form = within(await screen.findByRole("form", { name: "Settings" }));
    fireEvent.click(form.getByLabelText("Allow Cloudflare-proxied records"));
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByText("The zone's settings are saved.")).toBeNull();
    await waitFor(() => expect(calls.getZone).toBeGreaterThan(1));
  });

  it("shows the refusal of a value the API rejects", async () => {
    page({ updateFails: Code.InvalidArgument });
    const form = within(await screen.findByRole("form", { name: "Settings" }));
    fireEvent.click(form.getByLabelText("Allow wildcard names"));
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
  });
});
