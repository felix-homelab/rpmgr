// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import i18next from "i18next";
import { options } from "@/i18n";
import en from "@/locales/en.json";

function has(tree: unknown, key: string): boolean {
  let node = tree;
  for (const part of key.split(".")) {
    if (typeof node !== "object" || node === null || !(part in node)) {
      return false;
    }
    node = (node as Record<string, unknown>)[part];
  }
  return typeof node === "string";
}

// The source files, without the generated code and the tests.
function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const path = join(dir, e.name);
    if (e.isDirectory()) {
      return e.name === "gen" ? [] : sources(path);
    }
    return /\.tsx?$/.test(e.name) && !/\.test\.tsx?$/.test(e.name) ? [path] : [];
  });
}

describe("i18n", () => {
  it("falls back to English for a key a translation lacks", async () => {
    const de = i18next.createInstance();
    await de.init({ ...options, lng: "de", supportedLngs: ["en", "de"],
      resources: { ...options.resources, de: { translation: { nav: { overview: "Übersicht" } } } } });
    expect(de.t("nav.overview")).toBe("Übersicht");
    expect(de.t("overview.title")).toBe("Overview");
  });

  it("has an English text for every key the code uses", () => {
    const keys = sources(join(import.meta.dirname, ".")).flatMap((f) =>
      [...readFileSync(f, "utf8").matchAll(/\bt\("([^"]+)"/g)].map((m) => m[1] ?? ""),
    );
    expect(keys.length).toBeGreaterThan(5);
    expect(keys.filter((k) => !has(en, k) && !has(en, `${k}_other`))).toEqual([]);
  });
});
