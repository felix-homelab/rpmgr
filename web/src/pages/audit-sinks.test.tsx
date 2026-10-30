// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ViolationsSchema } from "@/gen/buf/validate/validate_pb";
import { AuditSinkKind, AuditSinkService, type CreateAuditSinkRequest, type UpdateAuditSinkRequest } from "@/gen/rpmgr/v1/audit_sink_pb";
import { Theme, UserService } from "@/gen/rpmgr/v1/user_pb";
import { auth, show } from "@/testing/api";

afterEach(cleanup);

const at = timestampFromDate(new Date("2026-10-30T08:00:00Z"));
const hook = {
  id: "ask_1", name: "siem", kind: AuditSinkKind.WEBHOOK, url: "https://siem.example.com/rpmgr", secretSet: true, entries: true, enabled: true, etag: "e1",
  status: { lastSuccessTime: at, backlog: 3n, oldestUnshippedTime: at, lastError: "" },
};
const syslog = {
  id: "ask_2", name: "logs", kind: AuditSinkKind.SYSLOG, address: "logs.example.com:6514", entries: false, enabled: false, etag: "e2",
  status: { backlog: 0n, lastError: "tls: certificate signed by unknown authority" },
};

interface Calls { creates: CreateAuditSinkRequest[]; updates: UpdateAuditSinkRequest[]; deleted: string[]; tested: string[]; lists: number }

// page renders Settings → Audit sinks; the options shape or refuse single calls.
function sinks(role: "admin" | "viewer" = "admin", opts: { sinks?: object[]; create?: ConnectError; test?: { ok: boolean; error: string }; list?: ConnectError } = {}) {
  const c: Calls = { creates: [], updates: [], deleted: [], tested: [], lists: 0 };
  let rows = opts.sinks ?? [hook, syslog];
  show("/settings/audit-sinks", auth({
    getSession: () => ({ userId: "usr_ada", displayName: "Ada", instanceAdmin: role === "admin", memberships: [{ orgId: "org_1", role: role === "admin" ? "owner" : "viewer" }] }),
  }), (router) => {
    router.service(UserService, { getMe: () => ({ user: { id: "usr_ada", theme: Theme.SYSTEM } }) });
    router.service(AuditSinkService, {
      listAuditSinks: () => {
        c.lists++;
        if (opts.list) {
          throw opts.list;
        }
        return { auditSinks: rows };
      },
      createAuditSink: (req) => {
        c.creates.push(req);
        if (opts.create) {
          throw opts.create;
        }
        rows = [...rows, { ...req.auditSink, id: "ask_3", secret: "", secretSet: req.auditSink?.secret !== "" }];
        return { auditSink: rows.at(-1) };
      },
      updateAuditSink: (req) => {
        c.updates.push(req);
        rows = rows.map((r) => ((r as { id: string }).id === req.auditSink?.id ? { ...r, enabled: req.auditSink.enabled } : r));
        return { auditSink: req.auditSink };
      },
      deleteAuditSink: (req) => (c.deleted.push(`${req.auditSinkId} ${req.etag}`), (rows = rows.filter((r) => (r as { id: string }).id !== req.auditSinkId)), {}),
      testAuditSink: (req) => (c.tested.push(req.auditSinkId), opts.test ?? { ok: true, error: "" }),
    });
  });
  return c;
}

const rowOf = async (name: string) => within((await screen.findByText(name)).closest("li")!);
const form = async (name: string) => within(await screen.findByRole("form", { name }));

describe("Audit sinks", () => {
  it("lists each sink with its state, target, last shipped, backlog and last error", async () => {
    sinks();
    const a = await rowOf("siem");
    expect(a.getByText("Enabled")).toBeTruthy();
    expect(a.getByText("https://siem.example.com/rpmgr")).toBeTruthy();
    expect(a.getByText(/checkpoints and entries/)).toBeTruthy();
    expect(a.getByText(/3 items waiting since/)).toBeTruthy();
    expect(a.queryByText("Last error")).toBeNull();
    const b = await rowOf("logs");
    expect(b.getByText("Disabled: last attempt failed")).toBeTruthy();
    expect(b.getByText("tls: certificate signed by unknown authority")).toBeTruthy();
    expect(b.getByText("logs.example.com:6514")).toBeTruthy();
    expect(b.getByText("Last shipped").nextSibling?.textContent).toBe("never");
    expect(b.getByText("nothing waiting")).toBeTruthy();
  });

  it("shows a failing but enabled sink as failing with its error", async () => {
    sinks("admin", { sinks: [{ ...hook, status: { backlog: 1n, oldestUnshippedTime: at, lastError: "the receiver refused the item: 404" } }] });
    const a = await rowOf("siem");
    expect(a.getByText("Failing")).toBeTruthy();
    expect(a.getByText("the receiver refused the item: 404")).toBeTruthy();
    expect(a.getByText(/1 item waiting/)).toBeTruthy();
  });

  it("says so when there is no sink", async () => {
    sinks("admin", { sinks: [] });
    expect(await screen.findByText(/No audit sink yet/)).toBeTruthy();
  });

  it("shows why the list failed", async () => {
    sinks("admin", { list: new ConnectError("database unavailable", Code.Unavailable) });
    expect((await screen.findByRole("alert")).textContent).toContain("database unavailable");
  });

  it("never renders a secret, and says only whether one is stored", async () => {
    sinks("admin", { sinks: [{ ...hook, secret: "rpmgr_whs_SECRET2" }] });
    const a = await rowOf("siem");
    expect(a.getByText(/secret stored/)).toBeTruthy();
    fireEvent.click(a.getByRole("button", { name: "Edit" }));
    const f = await form("Edit");
    const field = f.getByLabelText("Signing secret") as HTMLInputElement;
    expect(field.type).toBe("password");
    expect(field.value).toBe("");
    expect(document.body.textContent).not.toContain("rpmgr_whs_SECRET2");
    expect([...document.querySelectorAll("input, textarea")].map((e) => (e as HTMLInputElement).value).join()).not.toContain("rpmgr_whs_SECRET2");
  });

  it("creates a webhook sink, sends the secret once and shows it nowhere afterwards", async () => {
    const c = sinks("admin", { sinks: [] });
    fireEvent.click(await screen.findByRole("button", { name: "New audit sink…" }));
    const f = await form("New audit sink…");
    fireEvent.change(f.getByLabelText("Name"), { target: { value: "siem" } });
    fireEvent.change(f.getByLabelText("URL"), { target: { value: "https://siem.example.com/x" } });
    fireEvent.change(f.getByLabelText(/Signing secret/), { target: { value: "rpmgr_whs_SECRET3" } });
    fireEvent.click(f.getByRole("button", { name: "Create the sink" }));
    expect(await rowOf("siem")).toBeTruthy();
    expect(c.creates).toHaveLength(1);
    expect(c.creates[0]!.auditSink).toMatchObject({ name: "siem", kind: AuditSinkKind.WEBHOOK, url: "https://siem.example.com/x", secret: "rpmgr_whs_SECRET3", entries: true, enabled: true });
    expect(document.body.textContent).not.toContain("rpmgr_whs_SECRET3");
  });

  it("creates a syslog sink from its own section, with no URL or secret", async () => {
    const c = sinks("admin", { sinks: [] });
    fireEvent.click(await screen.findByRole("button", { name: "New audit sink…" }));
    const f = await form("New audit sink…");
    fireEvent.change(f.getByLabelText("Kind"), { target: { value: String(AuditSinkKind.SYSLOG) } });
    expect(f.queryByLabelText("URL")).toBeNull();
    expect(f.queryByLabelText(/Signing secret/)).toBeNull();
    fireEvent.change(f.getByLabelText("Name"), { target: { value: "syslog" } });
    fireEvent.change(f.getByLabelText("Address"), { target: { value: "logs.example.com:6514" } });
    fireEvent.change(f.getByLabelText("CA certificates"), { target: { value: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----" } });
    fireEvent.click(f.getByRole("switch", { name: "Send the entries too" }));
    fireEvent.click(f.getByRole("button", { name: "Create the sink" }));
    await waitFor(() => expect(c.creates).toHaveLength(1));
    expect(c.creates[0]!.auditSink).toMatchObject({ name: "syslog", kind: AuditSinkKind.SYSLOG, address: "logs.example.com:6514", url: "", secret: "", entries: false });
    expect(c.creates[0]!.auditSink?.caBundle).toContain("BEGIN CERTIFICATE");
  });

  it.each([
    ["a bad name", { name: "Bad Name", url: "https://a.example.com", secret: "rpmgr_whs_SECRET5" }, "Name", /^use 1 to 63 lowercase/],
    ["an http URL", { name: "siem", url: "http://a.example.com", secret: "rpmgr_whs_SECRET5" }, "URL", /must start with https/],
    ["a URL that is none", { name: "siem", url: "nonsense", secret: "rpmgr_whs_SECRET5" }, "URL", /not a URL/],
    ["a URL with a password", { name: "siem", url: "https://u:p@a.example.com", secret: "rpmgr_whs_SECRET5" }, "URL", /^The URL must not carry/],
    ["no secret", { name: "siem", url: "https://a.example.com", secret: "" }, "Signing secret", /at least 16/],
    ["a secret of 15 characters", { name: "siem", url: "https://a.example.com", secret: "rpmgr_whs_SECRE" }, "Signing secret", /at least 16/],
  ])("refuses %s before it sends anything", async (_n, v, label, message) => {
    const c = sinks("admin", { sinks: [] });
    fireEvent.click(await screen.findByRole("button", { name: "New audit sink…" }));
    const f = await form("New audit sink…");
    fireEvent.change(f.getByLabelText("Name"), { target: { value: v.name } });
    fireEvent.change(f.getByLabelText("URL"), { target: { value: v.url } });
    fireEvent.change(f.getByLabelText(/Signing secret/), { target: { value: v.secret } });
    fireEvent.click(f.getByRole("button", { name: "Create the sink" }));
    expect((await f.findByText(message)).textContent).toMatch(message);
    expect(f.getByLabelText(new RegExp(`^${label}`)).getAttribute("aria-invalid")).toBe("true");
    expect(c.creates).toEqual([]);
  });

  it.each([["no port", "logs.example.com"], ["port 0", "logs.example.com:0"], ["port 65536", "logs.example.com:65536"], ["no host", ":6514"]])(
    "refuses a syslog address with %s", async (_n, address) => {
      const c = sinks("admin", { sinks: [] });
      fireEvent.click(await screen.findByRole("button", { name: "New audit sink…" }));
      const f = await form("New audit sink…");
      fireEvent.change(f.getByLabelText("Kind"), { target: { value: String(AuditSinkKind.SYSLOG) } });
      fireEvent.change(f.getByLabelText("Name"), { target: { value: "syslog" } });
      fireEvent.change(f.getByLabelText("Address"), { target: { value: address } });
      fireEvent.click(f.getByRole("button", { name: "Create the sink" }));
      expect(await f.findByText(/^Write the address as host:port/)).toBeTruthy();
      expect(c.creates).toEqual([]);
    });

  it("shows a violation the API reports at its field", async () => {
    const v = create(ViolationsSchema, { violations: [{ field: { elements: [{ fieldName: "audit_sink" }, { fieldName: "url" }] }, message: "the url does not parse" }] });
    sinks("admin", { sinks: [], create: new ConnectError("invalid", Code.InvalidArgument, undefined, [{ desc: ViolationsSchema, value: v }]) });
    fireEvent.click(await screen.findByRole("button", { name: "New audit sink…" }));
    const f = await form("New audit sink…");
    fireEvent.change(f.getByLabelText("Name"), { target: { value: "siem" } });
    fireEvent.change(f.getByLabelText("URL"), { target: { value: "https://a.example.com" } });
    fireEvent.change(f.getByLabelText(/Signing secret/), { target: { value: "rpmgr_whs_SECRET5" } });
    fireEvent.click(f.getByRole("button", { name: "Create the sink" }));
    expect((await f.findByText("the url does not parse")).id).toMatch(/-error$/);
    expect(f.getByLabelText("URL").getAttribute("aria-invalid")).toBe("true");
    expect(f.queryByRole("alert")).toBeNull();
  });

  it("tells a refusal without a field above the buttons", async () => {
    sinks("admin", { sinks: [], create: new ConnectError("apisvc: a sink named siem exists", Code.AlreadyExists) });
    fireEvent.click(await screen.findByRole("button", { name: "New audit sink…" }));
    const f = await form("New audit sink…");
    fireEvent.change(f.getByLabelText("Name"), { target: { value: "siem" } });
    fireEvent.change(f.getByLabelText("URL"), { target: { value: "https://a.example.com" } });
    fireEvent.change(f.getByLabelText(/Signing secret/), { target: { value: "rpmgr_whs_SECRET5" } });
    fireEvent.click(f.getByRole("button", { name: "Create the sink" }));
    expect((await f.findByRole("alert")).textContent).toContain("a sink named siem exists");
  });

  it("edits a sink with its etag and mask, and keeps the secret unless one is typed", async () => {
    const c = sinks();
    fireEvent.click((await rowOf("siem")).getByRole("button", { name: "Edit" }));
    let f = await form("Edit");
    fireEvent.change(f.getByLabelText("URL"), { target: { value: "https://siem2.example.com/x" } });
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(c.updates).toHaveLength(1));
    expect(c.updates[0]!.etag).toBe("e1");
    expect(c.updates[0]!.updateMask?.paths).toEqual(["name", "entries", "enabled", "url"]);
    expect(c.updates[0]!.auditSink).toMatchObject({ id: "ask_1", url: "https://siem2.example.com/x" });
    fireEvent.click((await rowOf("siem")).getByRole("button", { name: "Edit" }));
    f = await form("Edit");
    fireEvent.change(f.getByLabelText("Signing secret"), { target: { value: "short" } });
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    expect(await f.findByText(/at least 16/)).toBeTruthy();
    fireEvent.change(f.getByLabelText("Signing secret"), { target: { value: "rpmgr_whs_SECRET4" } });
    fireEvent.click(f.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(c.updates).toHaveLength(2));
    expect(c.updates[1]!.updateMask?.paths).toEqual(["name", "entries", "enabled", "url", "secret"]);
  });

  it("does not offer to change the kind of a sink", async () => {
    sinks();
    fireEvent.click((await rowOf("logs")).getByRole("button", { name: "Edit" }));
    const f = await form("Edit");
    expect(f.queryByLabelText("Kind")).toBeNull();
    expect(f.getByLabelText("Address")).toBeTruthy();
  });

  it("enables and disables a sink with the mask of enabled only", async () => {
    const c = sinks();
    fireEvent.click((await rowOf("siem")).getByRole("button", { name: "Disable" }));
    await waitFor(() => expect(c.updates).toHaveLength(1));
    expect(c.updates[0]!.updateMask?.paths).toEqual(["enabled"]);
    expect(c.updates[0]!.auditSink).toMatchObject({ id: "ask_1", enabled: false });
    expect(await (await rowOf("siem")).findByText("Disabled")).toBeTruthy();
    fireEvent.click((await rowOf("siem")).getByRole("button", { name: "Enable" }));
    await waitFor(() => expect(c.updates).toHaveLength(2));
    expect(c.updates[1]!.auditSink?.enabled).toBe(true);
  });

  it("tests a sink and reports the receiver's answer, good or bad", async () => {
    const c = sinks();
    const a = await rowOf("siem");
    fireEvent.click(a.getByRole("button", { name: "Send test item" }));
    expect((await a.findByRole("status")).textContent).toBe("The receiver acknowledged the test item.");
    expect(c.tested).toEqual(["ask_1"]);
    cleanup();
    sinks("admin", { test: { ok: false, error: "the receiver answered 401" } });
    const b = await rowOf("siem");
    fireEvent.click(b.getByRole("button", { name: "Send test item" }));
    expect((await b.findByRole("status")).textContent).toBe("The test item was not acknowledged: the receiver answered 401");
  });

  it("asks before it deletes, and sends the etag", async () => {
    const c = sinks();
    const a = await rowOf("siem");
    fireEvent.click(a.getByRole("button", { name: "Delete…" }));
    expect(c.deleted).toEqual([]);
    fireEvent.click(a.getByRole("button", { name: "Cancel" }));
    fireEvent.click(a.getByRole("button", { name: "Delete…" }));
    fireEvent.click(a.getByRole("button", { name: "Delete the sink" }));
    await waitFor(() => expect(screen.queryByText("siem")).toBeNull());
    expect(c.deleted).toEqual(["ask_1 e1"]);
  });

  it("shows a user who is no Instance Admin a note, no control, and asks the API for nothing", async () => {
    const c = sinks("viewer");
    expect(await screen.findByText(/Only the Instance Admin/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "New audit sink…" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
    expect(c.lists).toBe(0);
  });
});
