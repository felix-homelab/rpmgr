// @vitest-environment node
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The colours of both themes, as index.css defines them: the light ones in @theme, the dark ones
// in the dark variant of :root.
const css = readFileSync(join(import.meta.dirname, "index.css"), "utf8");

function tokens(block: string): Map<string, string> {
  return new Map([...block.matchAll(/--color-([a-z-]+):\s*(oklch\([^)]*\));/g)].map((m) => [m[1]!, m[2]!]));
}

const light = tokens(css.match(/@theme \{([^}]*)\}/)![1]!);
const dark = tokens(css.match(/@variant dark \{([^}]*)\}/)![1]!);

type RGB = [number, number, number];

// srgb converts an oklch() colour to gamma-encoded sRGB, clipped to its gamut.
function srgb(oklch: string): RGB {
  const [L, C, h] = oklch.slice(6, -1).trim().split(/\s+/).map(Number) as [number, number, number];
  const a = C * Math.cos((h * Math.PI) / 180);
  const b = C * Math.sin((h * Math.PI) / 180);
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const linear = [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ];
  return linear.map((c) => {
    const v = Math.min(1, Math.max(0, c));
    return v <= 0.0031308 ? 12.92 * v : 1.055 * v ** (1 / 2.4) - 0.055;
  }) as RGB;
}

// over is a colour at a share of opacity over another, as Tailwind's bg-ok/10 draws it on a card.
function over(top: RGB, share: number, below: RGB): RGB {
  return top.map((c, i) => share * c + (1 - share) * below[i]!) as RGB;
}

// contrast is the WCAG 2.2 contrast ratio of two colours.
function contrast(x: RGB, y: RGB): number {
  const lum = (c: RGB) => {
    const [r, g, b] = c.map((v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)) as RGB;
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const [hi, lo] = [lum(x), lum(y)].sort((p, q) => q - p) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

// Text on the surfaces it is drawn on needs 4.5:1, and controls' borders, the focus outline and the
// charts' lines 3:1 (docs/09-web-ui.md, U8; WCAG 2.2 1.4.3 and 1.4.11).
const text: [string, string[]][] = [
  ["foreground", ["background", "card", "sidebar", "muted", "accent"]],
  ["muted-foreground", ["background", "card", "sidebar", "muted", "accent"]],
  ["primary-foreground", ["primary"]],
  ["accent-foreground", ["accent"]],
  ["destructive-foreground", ["destructive"]],
  ["destructive", ["background", "card"]],
  ["ok", ["background", "card"]],
  ["warn", ["background", "card"]],
];
const graphics: [string, string[]][] = [
  ["input", ["background", "card"]],
  ["ring", ["background", "card", "sidebar"]],
  ["chart-in", ["card"]],
  ["chart-out", ["card"]],
];
// Badges draw their tone's text on a tint of the tone.
const badges = ["ok", "warn", "destructive", "primary"];

describe.each([["light", light], ["dark", dark]])("the %s theme", (_, theme) => {
  const colour = (name: string) => {
    const value = theme.get(name);
    expect(value, `--color-${name}`).toBeDefined();
    return srgb(value!);
  };

  it("defines every colour of the light theme", () => {
    expect([...theme.keys()].sort()).toEqual([...light.keys()].sort());
  });

  it.each(text)("has %s text readable on its surfaces", (fg, surfaces) => {
    for (const bg of surfaces) {
      expect(contrast(colour(fg), colour(bg)), `${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
    }
  });

  it.each(graphics)("has %s visible on its surfaces", (fg, surfaces) => {
    for (const bg of surfaces) {
      expect(contrast(colour(fg), colour(bg)), `${fg} on ${bg}`).toBeGreaterThanOrEqual(3);
    }
  });

  it.each(badges)("has %s badges readable", (tone) => {
    const text = tone === "primary" ? "accent-foreground" : tone;
    expect(contrast(colour(text), over(colour(tone), 0.12, colour("card"))), `${text} on ${tone}/12`).toBeGreaterThanOrEqual(4.5);
  });
});
