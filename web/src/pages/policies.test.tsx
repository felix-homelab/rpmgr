// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import {
  PolicyService, type CreateAccessPolicyRequest, type DeleteAccessPolicyRequest, type UpdateAccessPolicyRequest,
} from "@/gen/rpmgr/v1/policy_pb";
import { RouteService } from "@/gen/rpmgr/v1/route_pb";
import { ApplyState, StatusService } from "@/gen/rpmgr/v1/status_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

const applied = { revision: { dbEpoch: "e", seq: 31n }, applyStatus: { state: ApplyState.APPLIED, agentsTotal: 1, agentsApplied: 1 } };
const office = {
  id: "pol_1", name: "office", description: "office only", etag: "3", routeIds: ["rte_1"],
  rules: [
    { rule: { case: "ipDeny" as const, value: { cidrs: ["10.9.0.0/16"] } } },
    { rule: { case: "ipAllow" as const, value: { cidrs: ["10.0.0.0/8"] } } },
    { rule: { case: "basicAuth" as const, value: { users: [{ name: "ada" }, { name: "bob" }] } } },
  ],
};

function page() {
  const calls = { create: [] as CreateAccessPolicyRequest[], update: [] as UpdateAccessPolicyRequest[], remove: [] as DeleteAccessPolicyRequest[] };
  show("/policies", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGateways: () => ({}) });
    router.service(ConnectorService, { listConnectors: () => ({}) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(RouteService, { listRoutes: () => ({ routes: [{ id: "rte_1", name: "wiki" }] }) });
    router.service(PolicyService, {
      listAccessPolicies: () => ({ accessPolicies: [office, { id: "pol_2", name: "admins", etag: "1", rules: [{ rule: { case: "ipAllow", value: { cidrs: ["192.0.2.0/24"] } } }] }] }),
      createAccessPolicy: (req) => (calls.create.push(req), { accessPolicy: req.accessPolicy, ...applied }),
      updateAccessPolicy: (req) => (calls.update.push(req), { accessPolicy: req.accessPolicy, ...applied }),
      deleteAccessPolicy: (req) => {
        calls.remove.push(req);
        throw new ConnectError("apisvc: routes use the policy: wiki", Code.FailedPrecondition);
      },
    });
  });
  return calls;
}

async function policy(name: string) {
  const region = within(await screen.findByRole("region", { name: "Access policies" }));
  await region.findByText(name);
  const list = region.getAllByRole("list")[0]!; // the policies; each holds a list of its rules
  return within(within(list).getByText(name).closest("li")!);
}

describe("Policies", () => {
  it("lists policies by name, with their rules in order and the routes that use them", async () => {
    page();
    const p = await policy("office");
    expect(p.getAllByRole("listitem").map((li) => li.textContent)).toEqual(["deny 10.9.0.0/16", "allow 10.0.0.0/8", "basic auth: ada, bob"]);
    await waitFor(() => expect(p.getByText("used by wiki")).toBeTruthy());
    expect((await policy("admins")).getByText("used by no route")).toBeTruthy();
  });

  it("creates a policy with rules in the order given", async () => {
    const calls = page();
    fireEvent.click(await screen.findByRole("button", { name: "New access policy" }));
    const form = within(await screen.findByRole("form", { name: "New access policy" }));
    fireEvent.change(form.getByLabelText("Name"), { target: { value: "lab" } });
    const first = within(form.getByRole("group", { name: "Rule 1" }));
    fireEvent.change(first.getByLabelText("Addresses (CIDRs, one per line)"), { target: { value: "10.1.0.0/16" } });
    fireEvent.click(form.getByRole("button", { name: "Add a rule" }));
    const second = within(form.getByRole("group", { name: "Rule 2" }));
    fireEvent.change(second.getByLabelText("Kind"), { target: { value: "basicAuth" } });
    fireEvent.click(second.getByRole("button", { name: "Add a user" }));
    fireEvent.change(second.getByLabelText("User"), { target: { value: "carol" } });
    fireEvent.change(second.getByLabelText("Password"), { target: { value: "a long password!" } });
    fireEvent.click(second.getByRole("button", { name: "Up" }));
    fireEvent.click(form.getByRole("button", { name: "Create the policy" }));
    expect(await screen.findByText("Revision 31: applied by all 1 agents.")).toBeTruthy();
    const c = calls.create[0]!;
    expect([c.orgId, c.accessPolicy?.name, c.accessPolicy?.rules.map((r) => r.rule)]).toEqual(["org_1", "lab", [
      { case: "basicAuth", value: expect.objectContaining({ users: [expect.objectContaining({ name: "carol", password: "a long password!" })] }) },
      { case: "ipAllow", value: expect.objectContaining({ cidrs: ["10.1.0.0/16"] }) },
    ]]);
  });

  it("keeps the users' passwords it does not change", async () => {
    const calls = page();
    fireEvent.click((await policy("office")).getByRole("button", { name: "Edit…" }));
    const form = within(await screen.findByRole("form", { name: "Edit access policy" }));
    const auth = within(form.getByRole("group", { name: "Rule 3" }));
    const passwords = auth.getAllByLabelText("Password") as HTMLInputElement[];
    expect(passwords.map((p) => [p.value, p.placeholder])).toEqual([["", "unchanged"], ["", "unchanged"]]);
    fireEvent.change(passwords[1]!, { target: { value: "bob's new password" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.update).toHaveLength(1));
    const u = calls.update[0]!;
    expect([u.accessPolicy?.id, u.accessPolicy?.routeIds, u.updateMask?.paths, u.etag]).toEqual(["pol_1", ["rte_1"], ["name", "description", "rules"], "3"]);
    const users = u.accessPolicy?.rules[2]?.rule.case === "basicAuth" ? u.accessPolicy.rules[2].rule.value.users : [];
    expect(users.map((x) => [x.name, x.password])).toEqual([["ada", ""], ["bob", "bob's new password"]]);
  });

  it("shows why a policy in use is not removed", async () => {
    const calls = page();
    const p = await policy("office");
    fireEvent.click(p.getByRole("button", { name: "Remove…" }));
    expect(p.getByText("Remove the access policy office?")).toBeTruthy();
    fireEvent.click(p.getByRole("button", { name: "Remove it" }));
    expect((await p.findByRole("alert")).textContent).toBe("apisvc: routes use the policy: wiki");
    expect(calls.remove.map((r) => [r.accessPolicyId, r.etag])).toEqual([["pol_1", "3"]]);
  });
});
