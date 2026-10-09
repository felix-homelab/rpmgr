// SPDX-License-Identifier: Apache-2.0

// safeRedirect returns where to go after signing in: target if it is a path of this UI, else the
// overview, so that a link cannot send a user who signs in to another site.
export function safeRedirect(target: unknown): string {
  if (typeof target !== "string" || !target.startsWith("/") || target.startsWith("//") || target.startsWith("/\\")) {
    return "/";
  }
  return target;
}
