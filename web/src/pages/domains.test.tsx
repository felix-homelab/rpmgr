// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import {
  DomainMethod, DomainService, DomainStatus, type CreateDomainRequest, type DeleteDomainRequest,
} from "@/gen/rpmgr/v1/domain_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";

afterEach(cleanup);

const domains = [
  { id: "dom_2", fqdn: "example.org", wildcard: true, status: DomainStatus.VERIFIED, method: DomainMethod.DNS_TXT, etag: "1" },
  { id: "dom_1", fqdn: "example.com", status: DomainStatus.PENDING, method: DomainMethod.DNS_TXT, etag: "4",
    challenge: { txtName: "_rpmgr-challenge.example.com", value: "rpmgr-verify=abc123", httpUrl: "http://example.com/.well-known/rpmgr-challenge/dom_1" } },
  { id: "dom_3", fqdn: "web.example.net", status: DomainStatus.FAILED, method: DomainMethod.HTTP, lastError: "no token at the URL", etag: "2",
    challenge: { value: "rpmgr-verify=xyz", httpUrl: "http://web.example.net/.well-known/rpmgr-challenge/dom_3" } },
];

function page(instanceAdmin = false) {
  const calls = { create: [] as CreateDomainRequest[], verify: [] as string[], remove: [] as DeleteDomainRequest[], trust: [] as string[] };
  let steppedUp = false;
  show("/domains", auth({
    getSession: () => ({ userId: "usr_ada", instanceAdmin, memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: () => ((steppedUp = true), {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(DomainService, {
      listDomains: () => ({ domains }),
      createDomain: (req) => (calls.create.push(req), { domain: req.domain }),
      verifyDomain: (req) => (calls.verify.push(req.domainId), { domain: domains[1] }),
      deleteDomain: (req) => (calls.remove.push(req), {}),
      markDomainTrusted: (req) => {
        if (!steppedUp) {
          throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
        }
        calls.trust.push(req.domainId);
        return {};
      },
    });
  });
  return calls;
}

async function item(name: string) {
  const list = await screen.findByRole("list");
  await within(list).findByText(name);
  return within(within(list).getByText(name).closest("li")!);
}

describe("Domains", () => {
  it("lists the claims by name, and the proof each pending one waits for", async () => {
    page();
    const list = await screen.findByRole("list");
    await waitFor(() => expect(within(list).getAllByRole("listitem")).toHaveLength(3));
    expect(within(list).getAllByRole("listitem").map((li) => li.querySelector(".font-medium")?.textContent)).toEqual(["example.com", "*.example.org", "web.example.net"]);
    const pending = await item("example.com");
    expect(pending.getByText("pending")).toBeTruthy();
    expect(pending.getByLabelText("TXT record name").textContent).toBe("_rpmgr-challenge.example.com");
    expect(pending.getByLabelText("Value").textContent).toBe("rpmgr-verify=abc123");
    const verified = await item("*.example.org");
    expect(verified.queryByLabelText("Value")).toBeNull();
    expect(verified.queryByRole("button", { name: "Check now" })).toBeNull();
    const failed = await item("web.example.net");
    expect(failed.getByText("no token at the URL")).toBeTruthy();
    expect(failed.getByText(/they serve the token at http:\/\/web\.example\.net\/\.well-known\/rpmgr-challenge\/dom_3/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Mark as trusted" })).toBeNull(); // not an Instance Admin
  });

  it("claims a domain", async () => {
    const calls = page();
    fireEvent.click(await screen.findByRole("button", { name: "Claim a domain" }));
    const form = within(await screen.findByRole("form", { name: "Claim a domain" }));
    fireEvent.change(form.getByLabelText("Domain"), { target: { value: " Example.NET. " } });
    fireEvent.click(form.getByLabelText("Also every name below it"));
    fireEvent.click(form.getByLabelText("An HTTP token, served by your gateways"));
    fireEvent.click(form.getByRole("button", { name: "Claim it" }));
    await waitFor(() => expect(calls.create).toHaveLength(1));
    const c = calls.create[0]!;
    expect([c.orgId, c.domain?.fqdn, c.domain?.wildcard, c.domain?.method]).toEqual(["org_1", "example.net", true, DomainMethod.HTTP]);
    expect(c.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("checks a claim now and removes one after a confirmation", async () => {
    const calls = page();
    const pending = await item("example.com");
    fireEvent.click(pending.getByRole("button", { name: "Check now" }));
    await waitFor(() => expect(calls.verify).toEqual(["dom_1"]));
    fireEvent.click(pending.getByRole("button", { name: "Remove…" }));
    expect(pending.getByText("Remove the claim for example.com?")).toBeTruthy();
    fireEvent.click(pending.getByRole("button", { name: "Remove it" }));
    await waitFor(() => expect(calls.remove.map((r) => [r.domainId, r.etag])).toEqual([["dom_1", "4"]]));
  });

  it("lets the Instance Admin mark a claim trusted after a step-up", async () => {
    const calls = page(true);
    fireEvent.click((await item("example.com")).getByRole("button", { name: "Mark as trusted" }));
    const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(calls.trust).toEqual(["dom_1"]));
  });
});
