// SPDX-License-Identifier: Apache-2.0

// The red asterisk of a required field is CSS (index.css, "required-mark"), which jsdom does not
// draw, so tests look for the class instead (docs/09-web-ui.md, "Layout and navigation").

const hasMark = (e: Element) => e.classList.contains("required-mark") || e.querySelector(".required-mark") !== null;

// marked lists the text of every label and legend under root that ends in the asterisk, in order.
export function marked(root: ParentNode = document): string[] {
  return [...root.querySelectorAll(".required-mark")].map((e) => e.textContent?.trim() ?? "");
}

// unmatched lists the fields under root whose control and label disagree: a required control whose
// label has no asterisk, or an asterisk on the label of a control that is not required.
export function unmatched(root: ParentNode = document): string[] {
  const controls = [...root.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>("input, select, textarea")];
  return controls
    .filter((c) => c.labels !== null && c.labels.length > 0)
    .filter((c) => c.required !== [...c.labels!].some(hasMark))
    .map((c) => `${c.labels![0]!.textContent?.trim()}: ${c.required ? "required, no asterisk" : "asterisk, not required"}`);
}
