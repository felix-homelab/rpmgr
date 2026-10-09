// SPDX-License-Identifier: Apache-2.0

import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { AuditService, type ListAuditEntriesRequest, type ListInstanceAuditEntriesRequest } from "@/gen/rpmgr/v1/audit_pb";
import { OrgService } from "@/gen/rpmgr/v1/org_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

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
  const list = within(await screen.findByRole("region", { name: "Audit log" })).getAllByRole("list")[0]!;
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
    expect((await screen.findByRole("status")).textContent).toBe("✕ The chain is broken at entry 7: hash mismatch");
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
});
