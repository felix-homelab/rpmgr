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
import { marked, unmatched } from "@/testing/required";

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

const admins = { id: "pol_2", name: "admins", etag: "1", rules: [{ rule: { case: "ipAllow" as const, value: { cidrs: ["192.0.2.0/24"] } } }] };

const cdn = { id: "pol_3", name: "cdn", etag: "2", routeIds: [], rules: [{ rule: { case: "requireHeader" as const, value: { name: "X-Origin-Token" } } }] };

function page(policies: object[] = [office, admins]) {
  const calls = { create: [] as CreateAccessPolicyRequest[], update: [] as UpdateAccessPolicyRequest[], remove: [] as DeleteAccessPolicyRequest[] };
  show("/policies", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(GatewayService, { listGateways: () => ({}) });
    router.service(ConnectorService, { listConnectors: () => ({}) });
    router.service(StatusService, { async *watchApplyStatus() {} });
    router.service(RouteService, { listRoutes: () => ({ routes: [{ id: "rte_1", name: "wiki" }] }) });
    router.service(PolicyService, {
      listAccessPolicies: () => ({ accessPolicies: policies }),
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
  it("lists policies by name, with their rules and the routes that use them", async () => {
    page();
    const p = await policy("office");
    expect(p.getAllByRole("listitem").map((li) => li.textContent)).toEqual(["deny 10.9.0.0/16", "allow 10.0.0.0/8", "basic auth: ada, bob"]);
    await waitFor(() => expect(p.getByText("used by wiki")).toBeTruthy());
    expect((await policy("admins")).getByText("used by no route")).toBeTruthy();
  });

  it("creates a policy with its rules, says that a deny wins, and offers no order to set (D85)", async () => {
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
    expect(form.getByText("A deny rule wins: an address it matches is refused, whatever allows it.")).toBeTruthy();
    expect([form.queryByRole("button", { name: "Up" }), form.queryByRole("button", { name: "Down" })]).toEqual([null, null]);
    fireEvent.click(form.getByRole("button", { name: "Create the policy" }));
    expect(await screen.findByText("Revision 31: applied by all 1 agents.")).toBeTruthy();
    const c = calls.create[0]!;
    expect([c.orgId, c.accessPolicy?.name, c.accessPolicy?.rules.map((r) => r.rule)]).toEqual(["org_1", "lab", [
      { case: "ipAllow", value: expect.objectContaining({ cidrs: ["10.1.0.0/16"] }) },
      { case: "basicAuth", value: expect.objectContaining({ users: [expect.objectContaining({ name: "carol", password: "a long password!" })] }) },
    ]]);
  });

  it("adds a per-client rate limit, a second's worth at once when no burst is given, and shows it", async () => {
    const limited = { id: "pol_3", name: "slow", etag: "2", routeIds: [], rules: [{ rule: { case: "rateLimit" as const, value: { perSecond: 5, burst: 20 } } }] };
    const calls = page([limited]);
    const p = await policy("slow");
    expect(p.getAllByRole("listitem").map((li) => li.textContent)).toEqual(["rate limit: 5 a second per client, 20 at once"]);
    fireEvent.click(p.getByRole("button", { name: "Edit…" }));
    const form = within(await screen.findByRole("form", { name: "Edit access policy" }));
    const rule = within(form.getByRole("group", { name: "Rule 1" }));
    expect([(rule.getByLabelText(/^Requests or new connections a second/) as HTMLInputElement).value,
      (rule.getByLabelText("At once (burst)") as HTMLInputElement).value]).toEqual(["5", "20"]);
    expect(rule.getByText(/Over it, HTTP gets 429/)).toBeTruthy();
    fireEvent.change(rule.getByLabelText(/^Requests or new connections a second/), { target: { value: "50" } });
    fireEvent.change(rule.getByLabelText("At once (burst)"), { target: { value: "" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.update).toHaveLength(1));
    expect(calls.update[0]!.accessPolicy?.rules.map((r) => r.rule)).toEqual([
      { case: "rateLimit", value: expect.objectContaining({ perSecond: 50, burst: 50 }) },
    ]);
  });

  it("refuses a rate limit that is not a whole number in its bounds, or a second one, before sending it", async () => {
    const calls = page([]);
    fireEvent.click(await screen.findByRole("button", { name: "New access policy" }));
    const form = within(await screen.findByRole("form", { name: "New access policy" }));
    fireEvent.change(form.getByLabelText("Name"), { target: { value: "slow" } });
    const first = within(form.getByRole("group", { name: "Rule 1" }));
    fireEvent.change(first.getByLabelText("Kind"), { target: { value: "rateLimit" } });
    for (const [perSecond, burst] of [["2.5", ""], ["abc", ""], ["0", ""], ["10001", ""], ["5", "1.5"], ["5", "-1"]]) {
      fireEvent.change(first.getByLabelText(/^Requests or new connections a second/), { target: { value: perSecond } });
      fireEvent.change(first.getByLabelText("At once (burst)"), { target: { value: burst } });
      fireEvent.click(form.getByRole("button", { name: "Create the policy" }));
      expect((await form.findByRole("alert")).textContent).toContain("whole numbers from 1 to 10000");
    }
    fireEvent.change(first.getByLabelText(/^Requests or new connections a second/), { target: { value: "5" } });
    fireEvent.change(first.getByLabelText("At once (burst)"), { target: { value: "" } });
    fireEvent.click(form.getByRole("button", { name: "Add a rule" }));
    const second = within(form.getByRole("group", { name: "Rule 2" }));
    fireEvent.change(second.getByLabelText("Kind"), { target: { value: "rateLimit" } });
    fireEvent.change(second.getByLabelText(/^Requests or new connections a second/), { target: { value: "9" } });
    fireEvent.click(form.getByRole("button", { name: "Create the policy" }));
    expect((await form.findByRole("alert")).textContent).toContain("at most one rate limit");
    expect(calls.create).toHaveLength(0);
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

  it("marks a new user's password as required, but not a password the policy keeps", async () => {
    page();
    fireEvent.click((await policy("office")).getByRole("button", { name: "Edit…" }));
    const form = await screen.findByRole("form", { name: "Edit access policy" });
    const rule = within(within(form).getByRole("group", { name: "Rule 3" }));
    expect(marked(form)).toEqual(["Name", "Addresses (CIDRs, one per line)", "Addresses (CIDRs, one per line)", "User", "User"]);
    expect(unmatched(form)).toEqual([]);
    const placeholders = (r: typeof rule) => (r.getAllByLabelText("Password") as HTMLInputElement[]).map((p) => p.placeholder);
    fireEvent.click(rule.getByRole("button", { name: "Add a user" }));
    fireEvent.change(rule.getAllByLabelText("User")[2]!, { target: { value: "carol" } });
    // A new user needs a password, so nothing is kept for them.
    await waitFor(() => expect(marked(form).filter((m) => m === "Password")).toHaveLength(1));
    expect(placeholders(rule)).toEqual(["unchanged", "unchanged", ""]);
    expect(unmatched(form)).toEqual([]);
    // The policy keeps a stored user's password by name, also in another rule.
    fireEvent.click(within(form).getByRole("button", { name: "Add a rule" }));
    const added = within(within(form).getByRole("group", { name: "Rule 4" }));
    fireEvent.change(added.getByLabelText("Kind"), { target: { value: "basicAuth" } });
    fireEvent.click(added.getByRole("button", { name: "Add a user" }));
    fireEvent.change(added.getByLabelText("User"), { target: { value: "ada" } });
    await waitFor(() => expect(placeholders(added)).toEqual(["unchanged"]));
    expect(marked(form).filter((m) => m === "Password")).toHaveLength(1);
    expect(unmatched(form)).toEqual([]);
  });

  it("requires a header with values it never shows, and generates one", async () => {
    const calls = page([office, cdn]);
    expect((await policy("cdn")).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["requires header X-Origin-Token"]);
    fireEvent.click(await screen.findByRole("button", { name: "New access policy" }));
    const form = within(await screen.findByRole("form", { name: "New access policy" }));
    fireEvent.change(form.getByLabelText("Name"), { target: { value: "edge" } });
    const rule = within(form.getByRole("group", { name: "Rule 1" }));
    fireEvent.change(rule.getByLabelText("Kind"), { target: { value: "requireHeader" } });
    fireEvent.change(rule.getByLabelText("Header"), { target: { value: "X-Edge" } });
    expect(marked(form.getByRole("group", { name: "Rule 1" }))).toEqual(["Header", "Value"]);
    fireEvent.change(rule.getByLabelText("Value"), { target: { value: "edge-secret-0123456789abcdefghijklmnop" } });
    fireEvent.click(rule.getByRole("button", { name: "Generate a value" }));
    const values = () => (rule.getAllByLabelText("Value") as HTMLInputElement[]).map((v) => v.value);
    const [, generated] = values();
    expect(values()).toHaveLength(2);
    expect(generated).toMatch(/^[A-Za-z0-9_-]{43}$/);
    fireEvent.click(rule.getByRole("button", { name: "Add a value" }));
    fireEvent.click(rule.getByRole("button", { name: "Add a value" }));
    expect((rule.getByRole("button", { name: "Add a value" }) as HTMLButtonElement).disabled).toBe(true); // four at most
    expect((rule.getByRole("button", { name: "Generate a value" }) as HTMLButtonElement).disabled).toBe(false); // an empty one is left
    fireEvent.click(form.getByRole("button", { name: "Create the policy" }));
    await waitFor(() => expect(calls.create).toHaveLength(1));
    const r = calls.create[0]!.accessPolicy?.rules[0]?.rule;
    expect(r?.case).toBe("requireHeader");
    if (r?.case === "requireHeader") {
      expect([r.value.name, r.value.values]).toEqual(["X-Edge", ["edge-secret-0123456789abcdefghijklmnop", generated]]); // empty ones left out
    }
  });

  it("keeps a required header's values it does not change", async () => {
    const calls = page([cdn]);
    fireEvent.click((await policy("cdn")).getByRole("button", { name: "Edit…" }));
    const form = await screen.findByRole("form", { name: "Edit access policy" });
    const rule = within(within(form).getByRole("group", { name: "Rule 1" }));
    const value = rule.getByLabelText("Value") as HTMLInputElement;
    expect([(rule.getByLabelText("Header") as HTMLInputElement).value, value.value, value.placeholder]).toEqual(["X-Origin-Token", "", "unchanged"]);
    expect(marked(form)).toEqual(["Name", "Header"]);
    expect(unmatched(form)).toEqual([]);
    // Another header is new, so it needs a value; the stored one, in any case, does not.
    fireEvent.change(rule.getByLabelText("Header"), { target: { value: "X-Other" } });
    await waitFor(() => expect(marked(form)).toEqual(["Name", "Header", "Value"]));
    fireEvent.change(rule.getByLabelText("Header"), { target: { value: "x-origin-token" } });
    await waitFor(() => expect(marked(form)).toEqual(["Name", "Header"]));
    fireEvent.click(within(form).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.update).toHaveLength(1));
    const r = calls.update[0]!.accessPolicy?.rules[0]?.rule;
    expect(r?.case === "requireHeader" && [r.value.name, r.value.values]).toEqual(["x-origin-token", []]);
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

  it("offers the first policy when there is none", async () => {
    page([]);
    const region = within(await screen.findByRole("region", { name: "Access policies" }));
    expect(await region.findByText("The org has no access policy.")).toBeTruthy();
    expect(region.queryByRole("list")).toBeNull();
    const add = region.getAllByRole("button", { name: "New access policy" }); // the header's and the empty list's
    expect(add).toHaveLength(2);
    fireEvent.click(add[1]!);
    expect(await region.findByRole("form", { name: "New access policy" })).toBeTruthy();
    expect(region.getAllByRole("button", { name: "New access policy" })).toHaveLength(1); // the empty list's goes while the form is open
  });
});
