// SPDX-License-Identifier: Apache-2.0

import { Theme } from "@/gen/rpmgr/v1/user_pb";

// applyTheme shows the UI in the user's theme (docs/09-web-ui.md, U10): index.css colours the page
// by the root element's data-theme, and "system" follows the operating system.
export function applyTheme(theme: Theme) {
  const name = theme === Theme.LIGHT ? "light" : theme === Theme.DARK ? "dark" : "system";
  document.documentElement.dataset.theme = name;
}
