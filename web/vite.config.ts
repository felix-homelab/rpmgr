// SPDX-License-Identifier: Apache-2.0
/// <reference types="vitest/config" />

import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The build goes where internal/webui embeds it. RPMGR_CSP_NONCE marks where the controller puts
// each response's style nonce (docs/09-web-ui.md, "Serving").
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  html: { cspNonce: "RPMGR_CSP_NONCE" },
  build: {
    outDir: "../internal/webui/ui/app",
    emptyOutDir: true,
    // Fonts as data: URIs would break the CSP, whose font-src is 'self'.
    assetsInlineLimit: 0,
    // Libraries change less often than the app, so they get chunks of their own, which browsers
    // keep across releases that do not update them.
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            { name: "react", test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/ },
            { name: "tanstack", test: /node_modules[\\/]@tanstack[\\/]/ },
            { name: "protobuf", test: /node_modules[\\/](@bufbuild|@connectrpc)[\\/]/ },
            { name: "api", test: /[\\/]src[\\/]gen[\\/]/ },
          ],
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test-setup.ts"],
  },
});
