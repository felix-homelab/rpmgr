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

// sideways lists what in the open dialog is wider than its box: the dialog itself, or a part of it
// that scrolls, so that a user would have to scroll sideways to read it.
export async function sideways(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const dialog = document.querySelector("dialog[open]");
    if (!dialog) {
      return ["no open dialog"];
    }
    return [dialog, ...dialog.querySelectorAll("*")]
      .filter((e) => e.scrollWidth > e.clientWidth + 1 && (e === dialog || getComputedStyle(e).overflowX !== "visible"))
      .map((e) => `${e.tagName.toLowerCase()} ${e.getAttribute("aria-label") ?? ""}: ${e.scrollWidth} > ${e.clientWidth}`);
  });
}

// unfilled lists what leaves the window's width unused on a signed-in page wider than 1024 px: the
// main area, which spans from the sidebar to the window's right edge, and the page in it, which
// fills the main area's content box (docs/09-web-ui.md, "Layout and navigation").
export async function unfilled(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const px = (n: number) => Math.round(n);
    const main = document.querySelector("main")!;
    const box = main.getBoundingClientRect();
    const from = document.querySelector("aside")!.getBoundingClientRect().right;
    const to = document.documentElement.clientWidth;
    const out: string[] = [];
    if (Math.abs(box.left - from) > 1 || Math.abs(box.right - to) > 1) {
      out.push(`main ${px(box.left)}–${px(box.right)}, window ${px(from)}–${px(to)}`);
    }
    const style = getComputedStyle(main);
    const inner = box.width - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
    for (const e of [...main.children].filter((e) => e.getClientRects().length > 0)) {
      const width = e.getBoundingClientRect().width;
      if (inner - width > 1) {
        out.push(`${e.tagName.toLowerCase()} ${px(width)} of ${px(inner)} px`);
      }
    }
    return out;
  });
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
