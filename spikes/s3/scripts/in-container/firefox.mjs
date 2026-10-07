// SPDX-License-Identifier: Apache-2.0
//
// Runs inside the Playwright image with playwright-core 1.63.0 (the version of the image's
// browsers): headless Firefox against every browser-facing route of s3gw, directly and through the
// relay, then app.example.test over HTTP/3 through Firefox's testing Alt-Svc mapping on the same
// port. Certificate errors are ignored only because the routing, not the browser's trust store, is
// measured; this Firefox build does not apply the enterprise certificate policy.
//
// Usage: node firefox.mjs <port> <relay-port>
import { firefox } from 'playwright-core';

const [port, relay] = process.argv.slice(2);
const hosts = ['app.example.test', 'api.example.test', 'pass.example.test', 'panel.example.test', 'unknown.example.test'];

async function run(prefs, urls, label) {
  const browser = await firefox.launch({ firefoxUserPrefs: { 'network.dns.forceResolve': '127.0.0.1', ...prefs } });
  console.log(`firefox ${browser.version()}${label}`);
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  for (const url of urls) {
    const page = await ctx.newPage();
    try {
      // A second load after the first lets an Alt-Svc mapping take effect.
      let resp = await page.goto(url, { timeout: 15000 });
      if (label) resp = await page.reload({ timeout: 15000 });
      const text = (await page.textContent('body')).trim();
      console.log(`== ${url}\n${text} [${resp.status()}]`);
    } catch (e) {
      console.log(`== ${url}\n(no page: ${e.message.split('\n')[0]})`);
    }
    await page.close();
  }
  await browser.close();
}

const urls = [];
for (const p of [port, relay]) for (const h of hosts) urls.push(`https://${h}:${p}/`);
await run({}, urls, '');
await run({ 'network.http.http3.enable': true,
  'network.http.http3.alt-svc-mapping-for-testing': `app.example.test;h3=:${port}` },
  [`https://app.example.test:${port}/`], ' (h3 via testing Alt-Svc mapping)');
