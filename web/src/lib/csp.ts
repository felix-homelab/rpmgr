// SPDX-License-Identifier: Apache-2.0

// cspNonce returns the style nonce the controller put into this page, which style elements need
// under its Content Security Policy (docs/09-web-ui.md, "Security of the frontend"). Browsers hide
// the attribute once the page has loaded, so it is read from the property. Without a controller,
// as in tests, there is none.
export function cspNonce(): string | undefined {
  const nonce = document.querySelector<HTMLMetaElement>('meta[property="csp-nonce"]')?.nonce;
  return nonce && nonce !== "RPMGR_CSP_NONCE" ? nonce : undefined;
}
