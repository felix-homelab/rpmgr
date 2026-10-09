// SPDX-License-Identifier: Apache-2.0

import { createHmac } from "node:crypto";
import AxeBuilder from "@axe-core/playwright";
import { expect, type Page } from "@playwright/test";

export const email = "ada@example.com";
export const password = "correct horse battery staple";

// watchCSP collects the page's Content Security Policy violations.
export async function watchCSP(page: Page): Promise<string[]> {
  const seen: string[] = [];
  await page.exposeFunction("rpmgrViolation", (v: string) => seen.push(v));
  await page.addInitScript(() =>
    document.addEventListener("securitypolicyviolation", (e) =>
      (window as unknown as { rpmgrViolation: (v: string) => void }).rpmgrViolation(`${e.violatedDirective} ${e.blockedURI}`),
    ),
  );
  return seen;
}

// expectAccessible fails on any WCAG 2.2 A or AA violation axe finds (docs/09-web-ui.md, U8).
export async function expectAccessible(page: Page) {
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  expect(r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
}

// call calls an API method from the page, with its session, as the UI does. It runs in the page so
// that a failure reports the answer, never the request's session cookie.
export async function call<T>(page: Page, method: string, body: object): Promise<T> {
  const res = await page.evaluate(
    async ([m, b]) => {
      const r = await fetch(`/rpmgr.v1.${m}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });
      return { status: r.status, text: await r.text() };
    },
    [method, body] as const,
  );
  expect(res.status, `${method}: ${res.text}`).toBe(200);
  return JSON.parse(res.text) as T;
}

// totp is the RFC 6238 code of a base32 secret at time now (SHA-1, 30 s, 6 digits).
export function totp(secret: string, now = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/=+$/, "").toUpperCase()) {
    bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  }
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 30000)));
  const mac = createHmac("sha1", key).update(counter).digest();
  const off = mac[mac.length - 1]! & 0xf;
  return ((mac.readUInt32BE(off) & 0x7fffffff) % 1e6).toString().padStart(6, "0");
}
