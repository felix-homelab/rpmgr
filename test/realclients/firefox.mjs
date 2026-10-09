// SPDX-License-Identifier: Apache-2.0
//
// Runs inside the Playwright image with playwright-core at the version of the image's browsers:
// headless Firefox against every name the gateway's port 443 serves. Certificate errors are
// ignored because the routing is measured, not the browser's trust store. Adapted from spike/s3:
// spikes/s3/scripts/in-container/firefox.mjs.
//
// Usage: node firefox.mjs <port> <host>...
import { firefox } from 'playwright-core';

const [port, ...hosts] = process.argv.slice(2);
const browser = await firefox.launch({ firefoxUserPrefs: { 'network.dns.forceResolve': '127.0.0.1' } });
console.log(`firefox ${browser.version()}`);
const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
for (const h of hosts) {
  const url = `https://${h}:${port}/`;
  const page = await ctx.newPage();
  try {
    const resp = await page.goto(url, { timeout: 15000 });
    console.log(`== ${url}\n${(await page.textContent('body')).trim()} [${resp.status()}]`);
  } catch (e) {
    console.log(`== ${url}\n(no page: ${e.message.split('\n')[0]})`);
  }
  await page.close();
}
await browser.close();
