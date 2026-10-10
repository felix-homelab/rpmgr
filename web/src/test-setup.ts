// SPDX-License-Identifier: Apache-2.0

// jsdom has no scrolling, which the router's scroll restoration calls.
if (typeof window !== "undefined") {
  window.scrollTo = () => {};
}
