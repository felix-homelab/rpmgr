// SPDX-License-Identifier: Apache-2.0

import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

// docs/09-web-ui.md, "Security of the frontend": untrusted data is rendered as text, and no
// credential is kept in browser storage, where any XSS could read it.
const html = "Render untrusted data as text (docs/09-web-ui.md, \"Security of the frontend\").";
const storage = "The UI keeps nothing in browser storage (docs/09-web-ui.md, \"Security of the frontend\").";

export default defineConfig(
  { ignores: ["src/gen/**", "test-results/**", "playwright-report/**"] },
  js.configs.recommended,
  tseslint.configs.recommended,
  reactHooks.configs.flat.recommended,
  {
    languageOptions: { globals: globals.browser },
    rules: {
      "no-restricted-syntax": [
        "error",
        { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: html },
        { selector: "Property[key.name='dangerouslySetInnerHTML']", message: html },
        { selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]", message: html },
        { selector: "CallExpression[callee.property.name=/^(insertAdjacentHTML|write|writeln)$/]", message: html },
      ],
      "no-restricted-globals": [
        "error",
        { name: "localStorage", message: storage },
        { name: "sessionStorage", message: storage },
        { name: "indexedDB", message: storage },
      ],
      "no-restricted-properties": [
        "error",
        { object: "window", property: "localStorage", message: storage },
        { object: "window", property: "sessionStorage", message: storage },
        { object: "window", property: "indexedDB", message: storage },
      ],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
    },
  },
  // Tests look into browser storage to check that it stays empty.
  { files: ["src/**/*.test.{ts,tsx}"], rules: { "no-restricted-globals": "off" } },
  { files: ["*.config.{js,ts}"], languageOptions: { globals: globals.node } },
  // Browser tests run in Node and look into the page's storage to check that it stays empty.
  { files: ["e2e/**"], languageOptions: { globals: globals.node }, rules: { "no-restricted-globals": "off" } },
);
