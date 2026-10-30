// SPDX-License-Identifier: Apache-2.0

import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Code } from "@connectrpc/connect";
import { AuditService, type ListAuditEntriesRequest, type ListInstanceAuditEntriesRequest } from "@/gen/rpmgr/v1/audit_pb";
import { OrgService } from "@/gen/rpmgr/v1/org_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const entry = (seq: number, over: object = {}) => ({
  id: `aud_${seq}`, seq: BigInt(seq), time: timestampFromDate(new Date(Date.UTC(2026, 9, 9, 10, seq))), actorType: "user", actorId: "usr_ada",
  action: "rpmgr.v1.RouteService/UpdateRoute", targetType: "route", targetId: "rte_1", result: "success", ...over,
});

function page(path: string, instanceAdmin = false, verification: object = { intact: true, headSeq: 3n, lastCheckpoint: { seq: 2n, time: timestampFromDate(new Date("2026-10-09T09:00:00Z")) } }) {
  const org: ListAuditEntriesRequest[] = [];
  const inst: ListInstanceAuditEntriesRequest[] = [];
  const view = show(path, auth({ getSession: () => ({ userId: "usr_ada", instanceAdmin, memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(OrgService, { listMembers: () => ({ members: [{ userId: "usr_ada", displayName: "Ada" }] }) });
    router.service(AuditService, {
      listAuditEntries: (req) => {
        org.push(req);
        return req.pageToken === ""
          ? { entries: [entry(3, { diff: '{"route":{"name":"<script>x</script>"}}', ip: "192.0.2.1" }), entry(2, { result: "denied", actorId: "usr_eve" })], nextPageToken: "p2" }
          : { entries: [entry(1, { actorType: "system", actorId: "" })] };
      },
      listInstanceAuditEntries: (req) => (inst.push(req), { entries: [entry(9, { action: "instance.settings", targetType: "settings", targetId: "" })] }),
      verifyAuditChain: () => ({ verification }),
      verifyInstanceAuditChain: () => ({ verification: { intact: true, headSeq: 9n } }),
    });
  });
  return { ...view, org, inst };
}

async function entries() {
  const list = (await within(await screen.findByRole("region", { name: "Audit log" })).findAllByRole("list"))[0]!;
  return within(list);
}

describe("Audit", () => {
  it("lists the log newest first with actors by name, and shows an entry's request as text", async () => {
    page("/audit");
    const list = await entries();
    await waitFor(() => expect(list.getAllByRole("listitem")).toHaveLength(2));
    const [first, second] = list.getAllByRole("listitem");
    expect(first!.querySelector("summary")?.textContent).toMatch(/rpmgr\.v1\.RouteService\/UpdateRouteroute rte_1Adasuccess$/);
    expect(second!.querySelector("summary")?.textContent).toMatch(/usr_evedenied$/);
    fireEvent.click(first!.querySelector("summary")!);
    expect(within(first!).getByText('{"route":{"name":"<script>x</script>"}}')).toBeTruthy();
    expect(first!.querySelector("script")).toBeNull();
    expect(within(first!).getByText("192.0.2.1")).toBeTruthy();
  });

  it("wraps an entry's long request, which would otherwise widen the page", async () => {
    page("/audit");
    const list = await entries();
    await waitFor(() => expect(list.getAllByRole("listitem")).toHaveLength(2));
    const first = list.getAllByRole("listitem")[0]!;
    fireEvent.click(first.querySelector("summary")!);
    const request = within(first).getByText('{"route":{"name":"<script>x</script>"}}');
    // jsdom lays nothing out, so the test checks the classes: the text wraps, at any character
    // where a word is longer than the line, and nothing scrolls sideways.
    expect(request.tagName).toBe("PRE");
    expect(request.className.split(" ")).toEqual(expect.arrayContaining(["whitespace-pre-wrap", "wrap-anywhere"]));
    expect(request.className).not.toMatch(/overflow-x/);
  });

  it("loads older entries, and filters by action and actor in the URL", async () => {
    const { org, history } = page("/audit");
    fireEvent.click(await screen.findByRole("button", { name: "Older entries" }));
    await waitFor(async () => expect((await entries()).getAllByRole("listitem")).toHaveLength(3));
    expect(org.map((r) => r.pageToken)).toEqual(["", "p2"]);
    fireEvent.change(screen.getByLabelText("Action, exactly"), { target: { value: " token.use " } });
    fireEvent.change(screen.getByLabelText("Actor ID"), { target: { value: "usr_eve" } });
    fireEvent.click(screen.getByRole("button", { name: "Filter" }));
    await waitFor(() => expect(org.at(-1)).toMatchObject({ orgId: "org_1", action: "token.use", actorId: "usr_eve", pageToken: "" }));
    expect(new URLSearchParams(history.location.search).get("action")).toBe("token.use");
  });

  it("verifies the chain", async () => {
    page("/audit");
    fireEvent.click(await screen.findByRole("button", { name: "Verify the chain" }));
    expect((await screen.findByRole("status")).textContent).toMatch(/The chain is intact up to entry 3\. Its last signed checkpoint covers entry 2/);
    cleanup();
    page("/audit", false, { intact: false, brokenAt: 7n, problem: "hash mismatch" });
    fireEvent.click(await screen.findByRole("button", { name: "Verify the chain" }));
    const status = await screen.findByRole("status");
    expect(status.textContent).toBe("The chain is broken at entry 7: hash mismatch"); // the icon is a drawing
    expect(status.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
  });

  it("says when no entry matches, without an empty list", async () => {
    show("/audit?action=nothing", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
      router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
      router.service(OrgService, { listMembers: () => ({ members: [] }) });
      router.service(AuditService, { listAuditEntries: () => ({ entries: [] }) });
    });
    const region = within(await screen.findByRole("region", { name: "Audit log" }));
    expect(await region.findByText("No entry matches.")).toBeTruthy();
    expect(region.queryByRole("list")).toBeNull();
    expect(region.queryByRole("button", { name: "Older entries" })).toBeNull();
  });

  it("shows the instance's log to the Instance Admin only", async () => {
    page("/audit");
    await screen.findByRole("button", { name: "Verify the chain" });
    expect(screen.queryByRole("button", { name: "The instance" })).toBeNull();
    cleanup();
    const { inst } = page("/audit", true);
    fireEvent.click(await screen.findByRole("button", { name: "The instance" }));
    expect(await screen.findByRole("heading", { name: "Instance audit log" })).toBeTruthy();
    await waitFor(() => expect(inst).toHaveLength(1));
    expect(await screen.findByText("instance.settings")).toBeTruthy();
  });

  // exportPage is the audit page with an export that asks for a step-up first, or fails.
  function exportPage(path: string, instanceAdmin: boolean, fail?: Code) {
    const calls = { org: [] as string[], inst: 0, steppedUp: 0 };
    let steppedUp = false;
    const guard = () => {
      if (fail !== undefined) throw apiError(fail);
      if (!steppedUp) throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
    };
    show(path, auth({ getSession: () => ({ userId: "usr_ada", instanceAdmin, memberships: [{ orgId: "org_1", role: "owner" }] }),
      stepUp: () => (calls.steppedUp++, steppedUp = true, {}) }), (router) => {
      router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
      router.service(OrgService, { listMembers: () => ({ members: [] }) });
      router.service(AuditService, {
        listAuditEntries: () => ({ entries: [] }),
        listInstanceAuditEntries: () => ({ entries: [] }),
        exportAudit: async function* (req) {
          calls.org.push(req.orgId);
          guard();
          yield { lines: ['{"type":"header"}', '{"type":"entry","seq":1}'] };
          yield { lines: ['{"type":"entry","seq":2}'] };
        },
        exportInstanceAudit: async function* () {
          calls.inst++;
          guard();
          yield { lines: ['{"type":"header"}'] };
        },
      });
    });
    return calls;
  }

  // download stubs the browser's file download and returns what was saved.
  function download() {
    const saved: { name: string; blob: Blob }[] = [];
    let blob: Blob | undefined;
    URL.createObjectURL = (b: Blob | MediaSource) => ((blob = b as Blob), "blob:audit");
    URL.revokeObjectURL = () => {};
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      saved.push({ name: this.download, blob: blob! });
    });
    return { saved, restore: () => click.mockRestore() };
  }

  it("exports the chain after a step-up and downloads it as JSON Lines", async () => {
    const dl = download();
    const calls = exportPage("/audit", false);
    fireEvent.click(await screen.findByRole("button", { name: "Export" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(dialog.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(dialog.getByRole("button", { name: "Confirm" }));
    expect((await screen.findByRole("status")).textContent).toMatch(/^Saved audit-org_1\.jsonl\. .*rpmgr audit verify-export/);
    expect(calls).toEqual({ org: ["org_1", "org_1"], inst: 0, steppedUp: 1 });
    expect(dl.saved.map((s) => s.name)).toEqual(["audit-org_1.jsonl"]);
    expect(await dl.saved[0]!.blob.text()).toBe('{"type":"header"}\n{"type":"entry","seq":1}\n{"type":"entry","seq":2}\n');
    dl.restore();
  });

  it("exports the instance's chain to the Instance Admin, and saves nothing when the export is refused", async () => {
    const dl = download();
    const calls = exportPage("/audit?log=instance", true);
    fireEvent.click(await screen.findByRole("button", { name: "Export" }));
    fireEvent.click(within(await screen.findByRole("dialog", { name: "Confirm it is you" })).getByRole("button", { name: "Cancel" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/The export failed/);
    expect(dl.saved).toEqual([]);
    expect(calls.inst).toBe(1);
    cleanup();
    exportPage("/audit", false, Code.PermissionDenied);
    fireEvent.click(await screen.findByRole("button", { name: "Export" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/The export failed/);
    expect(dl.saved).toEqual([]);
    dl.restore();
  });
});
