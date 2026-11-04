// SPDX-License-Identifier: Apache-2.0

import { Code } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import {
  DnsProviderService, DnsZoneService, ProviderStatus, ZoneProviderStatus, ZoneSyncState,
  type ConnectDnsProviderRequest, type DeleteDnsProviderRequest, type ImportZoneRequest, type RemoveZoneRequest, type UpdateDnsProviderRequest,
} from "@/gen/rpmgr/v1/dns_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { apiError, auth, show } from "@/testing/api";
import { marked, unmatched } from "@/testing/required";

afterEach(cleanup);

// theToken is a made-up token the tests look for everywhere in the page.
const theToken = "cf-token-of-the-test-0001";

const providers = [
  { id: "dnp_1", name: "home", status: ProviderStatus.OK, etag: "3", tokenExpiring: true, tokenExpiresAt: { seconds: 1798848000n, nanos: 0 },
    kind: { case: "cloudflare" as const, value: { accountId: "acc", apiToken: "" } } },
  { id: "dnp_2", name: "work", status: ProviderStatus.INVALID, etag: "9", lastError: "the token was refused",
    kind: { case: "cloudflare" as const, value: { accountId: "", apiToken: "" } } },
];

const zones = [
  { id: "dnz_1", name: "example.com", dnsProviderId: "dnp_1", providerZoneId: "pz1", syncState: ZoneSyncState.HELD, heldReason: "imported",
    providerStatus: ZoneProviderStatus.OK, etag: "5" },
  { id: "dnz_2", name: "example.net", dnsProviderId: "dnp_1", providerZoneId: "pz9", syncState: ZoneSyncState.ACTIVE,
    providerStatus: ZoneProviderStatus.PERMISSION_DENIED, etag: "6" },
];

const offered = [
  { id: "pz1", name: "example.com", status: "active", type: "full" },
  { id: "pz2", name: "example.org", status: "active", type: "full" },
  { id: "pz3", name: "pending.example", status: "pending", type: "full" },
  { id: "pz4", name: "partial.example", status: "active", type: "partial" },
];

function page(opts: { connectFails?: boolean } = {}) {
  const calls = {
    connect: [] as ConnectDnsProviderRequest[], update: [] as UpdateDnsProviderRequest[], remove: [] as DeleteDnsProviderRequest[],
    import: [] as ImportZoneRequest[], removeZone: [] as RemoveZoneRequest[], stepUps: 0,
  };
  let steppedUp = false;
  const needStepUp = () => {
    if (!steppedUp) {
      throw apiError(Code.Unauthenticated, "STEP_UP_REQUIRED");
    }
  };
  show("/dns", auth({
    getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }),
    stepUp: () => ((steppedUp = true), calls.stepUps++, {}),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(DnsProviderService, {
      listDnsProviders: () => ({ dnsProviders: providers }),
      connectDnsProvider: (req) => {
        needStepUp();
        if (opts.connectFails) {
          throw apiError(Code.FailedPrecondition, "TOKEN_REFUSED");
        }
        calls.connect.push(req);
        return { dnsProvider: { name: req.dnsProvider?.name ?? "", id: "dnp_3" } };
      },
      updateDnsProvider: (req) => (needStepUp(), calls.update.push(req), { dnsProvider: providers[0] }),
      deleteDnsProvider: (req) => (needStepUp(), calls.remove.push(req), {}),
      listProviderZones: () => ({ zones: offered }),
    });
    router.service(DnsZoneService, {
      listZones: () => ({ dnsZones: zones }),
      importZone: (req) => (calls.import.push(req), { dnsZone: zones[0] }),
      removeZone: (req) => (calls.removeZone.push(req), {}),
    });
  });
  return calls;
}

async function provider(name: string) {
  const list = within(await screen.findByRole("region", { name: "DNS providers" })).getByRole("list");
  await within(list).findByText(name);
  return within(within(list).getByText(name).closest("li")!);
}

async function zone(name: string) {
  const list = within(await screen.findByRole("region", { name: "Managed zones" })).getByRole("list");
  await within(list).findByText(name);
  return within(within(list).getByText(name).closest("li")!);
}

// nowhere is true when the token is neither in the page's text nor in the value of a field.
function nowhere() {
  const values = [...document.querySelectorAll("input")].map((i) => i.value).join(" ");
  return !(document.body.textContent + values).includes(theToken);
}

async function confirm() {
  const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
  fireEvent.change(stepUp.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(stepUp.getByRole("button", { name: "Confirm" }));
}

describe("DNS providers and zones", () => {
  it("lists the providers with their token status, and each zone with what its provider answered", async () => {
    page();
    const home = await provider("home");
    expect(home.getByText("token valid")).toBeTruthy();
    expect(home.getByText("token expires soon")).toBeTruthy();
    const work = await provider("work");
    expect(work.getByText("token invalid")).toBeTruthy();
    expect(work.getByText("the token was refused")).toBeTruthy();
    const held = await zone("example.com");
    expect(held.getByText("held")).toBeTruthy();
    expect(held.getByText("held: imported, no plan approved yet")).toBeTruthy();
    expect(held.queryByText(/has no permission/)).toBeNull();
    const denied = await zone("example.net");
    expect(denied.getByText("permission denied")).toBeTruthy();
    expect(denied.getByText(/The token has no permission for example\.net/)).toBeTruthy();
  });

  it("connects a provider after a step-up, with a write-only token that the page forgets", async () => {
    const calls = page();
    fireEvent.click(await screen.findByRole("button", { name: "Connect a provider" }));
    const formEl = await screen.findByRole("form", { name: "Connect a DNS provider" });
    expect([marked(formEl), unmatched(formEl)]).toEqual([["Name", "API token"], []]);
    const form = within(formEl);
    const token = form.getByLabelText("API token") as HTMLInputElement;
    expect(token.type).toBe("password");
    expect(token.value).toBe("");
    fireEvent.change(form.getByLabelText("Name"), { target: { value: " cf " } });
    fireEvent.change(form.getByLabelText("Cloudflare account ID"), { target: { value: "acc" } });
    fireEvent.change(token, { target: { value: ` ${theToken} ` } });
    fireEvent.click(form.getByRole("button", { name: "Connect it" }));
    await confirm();
    await waitFor(() => expect(calls.connect).toHaveLength(1));
    const c = calls.connect[0]!;
    expect([c.orgId, c.dnsProvider?.name, c.dnsProvider?.kind.case]).toEqual(["org_1", "cf", "cloudflare"]);
    expect(c.dnsProvider?.kind.value).toMatchObject({ apiToken: theToken, accountId: "acc" });
    expect(calls.stepUps).toBe(1);
    await waitFor(() => expect(screen.queryByRole("form", { name: "Connect a DNS provider" })).toBeNull());
    // Opened again, the form is empty; the token is nowhere in the page.
    fireEvent.click(await screen.findByRole("button", { name: "Connect a provider" }));
    expect(((await screen.findByLabelText("API token")) as HTMLInputElement).value).toBe("");
    expect(nowhere()).toBe(true);
  });

  it("refuses a missing token before sending anything, and shows a refusal without the token", async () => {
    const calls = page({ connectFails: true });
    fireEvent.click(await screen.findByRole("button", { name: "Connect a provider" }));
    const form = within(await screen.findByRole("form", { name: "Connect a DNS provider" }));
    fireEvent.change(form.getByLabelText("Name"), { target: { value: "cf" } });
    fireEvent.change(form.getByLabelText("API token"), { target: { value: "   " } });
    fireEvent.click(form.getByRole("button", { name: "Connect it" }));
    expect(await form.findByText("Enter the API token.")).toBeTruthy();
    expect(calls.stepUps).toBe(0);
    fireEvent.change(form.getByLabelText("API token"), { target: { value: theToken } });
    fireEvent.click(form.getByRole("button", { name: "Connect it" }));
    await confirm();
    await waitFor(() => expect(calls.stepUps).toBe(1));
    expect(await form.findByRole("alert")).toBeTruthy();
    expect(calls.connect).toHaveLength(0);
    // The token stays in the field the user typed it in, never in text of the page.
    expect(screen.getByRole("alert").textContent).not.toContain(theToken);
    expect(screen.queryByText(theToken)).toBeNull();
  });

  it("replaces a token after a step-up, from an empty field, and sends nothing else", async () => {
    const calls = page();
    fireEvent.click((await provider("home")).getByRole("button", { name: "Replace token" }));
    const form = within(await screen.findByRole("form", { name: "Replace the token of home" }));
    const token = form.getByLabelText("API token") as HTMLInputElement;
    expect(token.value).toBe("");
    fireEvent.change(token, { target: { value: theToken } });
    fireEvent.click(form.getByRole("button", { name: "Replace it" }));
    await confirm();
    await waitFor(() => expect(calls.update).toHaveLength(1));
    const u = calls.update[0]!;
    expect([u.dnsProvider?.id, u.updateMask?.paths, u.etag]).toEqual(["dnp_1", ["cloudflare.api_token"], "3"]);
    expect(u.dnsProvider?.kind.value).toMatchObject({ apiToken: theToken, accountId: "acc" });
    await waitFor(() => expect(screen.queryByRole("form", { name: "Replace the token of home" })).toBeNull());
    expect(nowhere()).toBe(true);
  });

  it("deletes a provider after a confirmation that names it and a step-up", async () => {
    const calls = page();
    const home = await provider("home");
    fireEvent.click(home.getByRole("button", { name: "Remove…" }));
    expect(home.getByText(/Delete the provider home\?/)).toBeTruthy();
    expect(calls.remove).toHaveLength(0);
    fireEvent.click(home.getByRole("button", { name: "Remove it" }));
    await confirm();
    await waitFor(() => expect(calls.remove.map((r) => [r.dnsProviderId, r.etag])).toEqual([["dnp_1", "3"]]));
  });

  it("does not delete when the step-up is cancelled", async () => {
    const calls = page();
    const home = await provider("home");
    fireEvent.click(home.getByRole("button", { name: "Remove…" }));
    fireEvent.click(home.getByRole("button", { name: "Remove it" }));
    const stepUp = within(await screen.findByRole("dialog", { name: "Confirm it is you" }));
    fireEvent.click(stepUp.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(calls.remove).toHaveLength(0);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("offers only the active, full zones that are not imported yet, and says why for the others", async () => {
    const calls = page();
    const home = await provider("home");
    fireEvent.click(home.getByRole("button", { name: "Zones" }));
    await home.findByText("example.org");
    expect(home.getByRole("button", { name: "Import example.com" }).hasAttribute("disabled")).toBe(true);
    expect(home.getByText("already imported")).toBeTruthy();
    expect(home.getByRole("button", { name: "Import pending.example" }).hasAttribute("disabled")).toBe(true);
    expect(home.getByText("not importable: its status is pending")).toBeTruthy();
    expect(home.getByRole("button", { name: "Import partial.example" }).hasAttribute("disabled")).toBe(true);
    expect(home.getByText(/its type is partial, only full zones can be imported/)).toBeTruthy();
    fireEvent.click(home.getByRole("button", { name: "Import example.org" }));
    await waitFor(() => expect(calls.import.map((r) => [r.dnsProviderId, r.providerZoneId])).toEqual([["dnp_1", "pz2"]]));
    expect(await home.findByText("Imported example.org. It is held until its first plan is approved.")).toBeTruthy();
  });

  it("removes a zone after a confirmation that names it", async () => {
    const calls = page();
    const z = await zone("example.net");
    fireEvent.click(z.getByRole("button", { name: "Remove…" }));
    expect(z.getByText(/Stop managing example\.net\?/)).toBeTruthy();
    fireEvent.click(z.getByRole("button", { name: "Remove it" }));
    await waitFor(() => expect(calls.removeZone.map((r) => [r.dnsZoneId, r.etag])).toEqual([["dnz_2", "6"]]));
  });
});
