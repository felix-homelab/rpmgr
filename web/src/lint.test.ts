// @vitest-environment node
// SPDX-License-Identifier: Apache-2.0

import { join } from "node:path";
import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

const eslint = new ESLint({ cwd: join(import.meta.dirname, "..") });

async function rules(code: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath: join(import.meta.dirname, "x.tsx") });
  return (result?.messages ?? []).map((m) => m.ruleId ?? m.message);
}

// docs/09-web-ui.md, "Security of the frontend": the lint bans that keep untrusted data text and
// browser storage empty.
// The first lint loads typescript-eslint, which takes seconds on a busy machine.
describe("lint bans", { timeout: 60_000 }, () => {
  it.each([
    ["dangerouslySetInnerHTML", "export const A = (p: { h: string }) => <div dangerouslySetInnerHTML={{ __html: p.h }} />;", "no-restricted-syntax"],
    ["dangerouslySetInnerHTML as a prop", 'import { createElement } from "react"; export const a = (h: string) => createElement("div", { dangerouslySetInnerHTML: { __html: h } });', "no-restricted-syntax"],
    ["innerHTML", "export function f(e: HTMLElement, h: string) { e.innerHTML = h; }", "no-restricted-syntax"],
    ["insertAdjacentHTML", 'export function f(e: HTMLElement, h: string) { e.insertAdjacentHTML("beforeend", h); }', "no-restricted-syntax"],
    ["localStorage", 'export const v = localStorage.getItem("token");', "no-restricted-globals"],
    ["window.sessionStorage", 'export const v = window.sessionStorage.getItem("token");', "no-restricted-properties"],
    ["eval", 'export const v = eval("1");', "no-eval"],
  ])("refuses %s", async (_, code, rule) => {
    expect(await rules(code)).toContain(rule);
  });

  it("passes text rendering", async () => {
    expect(await rules("export const A = (p: { h: string }) => <div title={p.h}>{p.h}</div>;")).toEqual([]);
  });
});
