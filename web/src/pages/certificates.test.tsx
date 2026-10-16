// SPDX-License-Identifier: Apache-2.0

import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { act, cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CertificateService, CertificateSource, CertificateStatus,
  type CreateCABundleRequest, type DeleteCertificateRequest, type UpdateCABundleRequest, type UploadCertificateRequest,
} from "@/gen/rpmgr/v1/certificate_pb";
import { DomainService } from "@/gen/rpmgr/v1/domain_pb";
import { RouteService } from "@/gen/rpmgr/v1/route_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";
import { marked, unmatched } from "@/testing/required";

afterEach(cleanup);

const day = 86400_000;
const chain = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const key = "-----BEGIN EC PRIVATE KEY-----\nMHcC\n-----END EC PRIVATE KEY-----\n";

function page() {
  const calls = { upload: [] as UploadCertificateRequest[], renew: [] as string[], remove: [] as DeleteCertificateRequest[],
    addBundle: [] as CreateCABundleRequest[], updateBundle: [] as UpdateCABundleRequest[] };
  show("/domains", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(DomainService, { listDomains: () => ({}) });
    router.service(RouteService, { listRoutes: () => ({ routes: [{ id: "rte_1", name: "wiki" }] }) });
    router.service(CertificateService, {
      listCertificates: () => ({ certificates: [
        { id: "crt_1", source: CertificateSource.ACME, status: CertificateStatus.ACTIVE, sans: ["wiki.example.com"], issuer: "Let's Encrypt R10",
          notAfter: timestampFromDate(new Date(Date.now() + 10 * day)), routeIds: ["rte_1"], etag: "2" },
        { id: "crt_2", source: CertificateSource.UPLOADED, status: CertificateStatus.ACTIVE, sans: ["*.example.org", "example.org"], issuer: "Office CA",
          notAfter: timestampFromDate(new Date(Date.now() + 200 * day)), etag: "1" },
      ] }),
      uploadCertificate: (req) => (calls.upload.push(req), { certificate: { id: "crt_3" } }),
      renewCertificate: (req) => (calls.renew.push(req.certificateId), { started: true }),
      deleteCertificate: (req) => {
        calls.remove.push(req);
        throw new ConnectError("apisvc: routes use the certificate: wiki", Code.FailedPrecondition);
      },
      listCABundles: () => ({ caBundles: [{ id: "cab_1", name: "office", pem: chain, certificates: [{ subject: "CN=Office CA", notAfter: timestampFromDate(new Date("2030-01-01T00:00:00Z")) }], targetIds: ["tgt_1", "tgt_2"], etag: "5" }] }),
      createCABundle: (req) => (calls.addBundle.push(req), { caBundle: req.caBundle }),
      updateCABundle: (req) => (calls.updateBundle.push(req), { caBundle: req.caBundle }),
    });
  });
  return calls;
}

// empty shows the page of an org without domain claims, certificates and CA bundles.
function empty() {
  show("/domains", auth({ getSession: () => ({ userId: "usr_ada", memberships: [{ orgId: "org_1", role: "owner" }] }) }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(DomainService, { listDomains: () => ({}) });
    router.service(RouteService, { listRoutes: () => ({}) });
    router.service(CertificateService, { listCertificates: () => ({}), listCABundles: () => ({}) });
  });
}

async function cert(name: string) {
  const s = within(await screen.findByRole("region", { name: "Certificates" }));
  await s.findByText(name);
  return within(s.getByText(name).closest("li")!);
}

describe("Certificates", () => {
  it("lists certificates with their source, expiry and routes", async () => {
    page();
    const acme = await cert("wiki.example.com");
    expect(acme.getByText("from ACME")).toBeTruthy();
    expect(acme.getByText(/^expires soon: /)).toBeTruthy();
    await waitFor(() => expect(acme.getByText("used by wiki")).toBeTruthy());
    const uploaded = await cert("*.example.org, example.org");
    expect(uploaded.getByText(/^expires .*Office CA$/)).toBeTruthy();
    expect(uploaded.queryByRole("button", { name: "Renew now" })).toBeNull();
  });

  it("uploads a chain and its key, and forgets the key", async () => {
    const calls = page();
    fireEvent.click(await screen.findByRole("button", { name: "Upload a certificate" }));
    const form = within(await screen.findByRole("form", { name: "Upload a certificate" }));
    expect([marked(screen.getByRole("form", { name: "Upload a certificate" })), unmatched(screen.getByRole("form", { name: "Upload a certificate" }))]).toEqual([["Certificate chain (PEM, the certificate first)", "Private key (PEM)"], []]);
    fireEvent.change(form.getByLabelText("Certificate chain (PEM, the certificate first)"), { target: { value: chain } });
    fireEvent.change(form.getByLabelText("Private key (PEM)"), { target: { value: key } });
    fireEvent.click(form.getByRole("button", { name: "Upload" }));
    await waitFor(() => expect(calls.upload).toHaveLength(1));
    expect([calls.upload[0]!.orgId, calls.upload[0]!.chainPem, calls.upload[0]!.privateKeyPem]).toEqual(["org_1", chain, key]);
    await waitFor(() => expect(screen.queryByRole("form", { name: "Upload a certificate" })).toBeNull());
    expect(document.body.textContent).not.toContain("MHcC");
  });

  it("renews an ACME certificate, and offers no removal, which the server always refuses", async () => {
    const calls = page();
    const acme = await cert("wiki.example.com");
    fireEvent.click(acme.getByRole("button", { name: "Renew now" }));
    expect((await acme.findByRole("status")).textContent).toBe("Renewal started.");
    expect(calls.renew).toEqual(["crt_1"]);
    expect(acme.queryByRole("button", { name: "Remove…" })).toBeNull();
    expect(acme.getByText("ACME manages it; it cannot be removed.")).toBeTruthy();
  });

  it("removes an uploaded certificate after a confirmation, and says why one in use is not", async () => {
    const calls = page();
    const uploaded = await cert("*.example.org, example.org");
    expect(uploaded.queryByText("ACME manages it; it cannot be removed.")).toBeNull();
    fireEvent.click(uploaded.getByRole("button", { name: "Remove…" }));
    expect(uploaded.getByText("Remove the certificate for *.example.org?")).toBeTruthy();
    fireEvent.click(uploaded.getByRole("button", { name: "Remove it" }));
    expect((await uploaded.findByRole("alert")).textContent).toBe("apisvc: routes use the certificate: wiki");
    expect(calls.remove.map((r) => [r.certificateId, r.etag])).toEqual([["crt_2", "1"]]);
  });

  it.each([
    ["Certificates", "*.example.org, example.org", "crt_2"],
    ["Certificates", "wiki.example.com", "crt_1"],
    ["CA bundles", "office", "cab_1"],
  ])("shows the ID of each item of %s, %s, which other forms and the command line take, and copies it", async (region, name, id) => {
    const write = vi.fn(() => Promise.resolve());
    Object.assign(navigator, { clipboard: { writeText: write } });
    page();
    const s = within(await screen.findByRole("region", { name: region }));
    const row = within((await s.findByText(name)).closest("li")!);
    const copy = row.getByRole("button", { name: "Copy" });
    expect(document.getElementById(copy.getAttribute("aria-describedby")!)?.textContent).toBe(id);
    expect(row.getByText(id).tagName).toBe("CODE");
    fireEvent.click(copy);
    await act(async () => {});
    expect(write).toHaveBeenCalledWith(id);
    expect(row.getByRole("button", { name: "Copied" })).toBeTruthy();
  });

  it("says to copy an ID by hand when the browser does not copy it", async () => {
    Object.assign(navigator, { clipboard: undefined });
    page();
    const row = await cert("wiki.example.com");
    fireEvent.click(row.getByRole("button", { name: "Copy" }));
    expect((await row.findByRole("status")).textContent).toBe("The browser did not copy it. Select the text and copy it by hand.");
    expect(row.getByText("crt_1")).toBeTruthy();
  });
});

describe("CABundles", () => {
  it("lists bundles, adds one and changes one as a whole", async () => {
    const calls = page();
    const s = within(await screen.findByRole("region", { name: "CA bundles" }));
    expect(await s.findByText(/^CN=Office CA, expires/)).toBeTruthy();
    expect(s.getByText("used by 2 targets")).toBeTruthy();
    fireEvent.click(s.getByRole("button", { name: "Add a CA bundle" }));
    let form = within(s.getByRole("form", { name: "New CA bundle" }));
    expect([marked(screen.getByRole("form", { name: "New CA bundle" })), unmatched(screen.getByRole("form", { name: "New CA bundle" }))]).toEqual([["Name", "CA certificates (PEM)"], []]);
    fireEvent.change(form.getByLabelText("Name"), { target: { value: " lab " } });
    fireEvent.change(form.getByLabelText("CA certificates (PEM)"), { target: { value: chain } });
    fireEvent.click(form.getByRole("button", { name: "Add the bundle" }));
    await waitFor(() => expect(calls.addBundle.map((b) => [b.orgId, b.caBundle?.name, b.caBundle?.pem])).toEqual([["org_1", "lab", chain]]));
    fireEvent.click(await s.findByRole("button", { name: "Edit…" }));
    form = within(s.getByRole("form", { name: "Edit CA bundle" }));
    fireEvent.change(form.getByLabelText("Name"), { target: { value: "office-2" } });
    fireEvent.click(form.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.updateBundle).toHaveLength(1));
    const u = calls.updateBundle[0]!;
    expect([u.caBundle?.id, u.caBundle?.name, u.caBundle?.pem, u.caBundle?.targetIds, u.updateMask?.paths, u.etag]).toEqual(["cab_1", "office-2", chain, ["tgt_1", "tgt_2"], ["name", "pem"], "5"]);
  });

  it("says what each empty section is for, and still offers to add the first", async () => {
    empty();
    for (const [region, text, add] of [
      ["Domains", "The org has no domain claim. Routes need a verified domain for their hostnames.", "Claim a domain"],
      ["Certificates", "The org has no certificate yet. HTTP routes with ACME get theirs on their own.", "Upload a certificate"],
      ["CA bundles", "The org has no CA bundle. HTTPS targets are verified with the system's roots unless they name one.", "Add a CA bundle"],
    ]) {
      const s = within(await screen.findByRole("region", { name: region }));
      expect(await s.findByText(text!)).toBeTruthy();
      expect(s.queryByRole("listitem")).toBeNull();
      expect(s.getByRole("button", { name: add })).toBeTruthy();
    }
  });
});
