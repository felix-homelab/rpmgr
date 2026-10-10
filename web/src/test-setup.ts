// SPDX-License-Identifier: Apache-2.0

import { configure } from "@testing-library/react";

// jsdom has no scrolling, which the router's scroll restoration calls, and no modal dialogs.
if (typeof window !== "undefined") {
  window.scrollTo = () => {};
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.open = true;
  };
}

// The pages answer after several API calls; on a busy machine that takes more than the default
// second of findBy and waitFor.
configure({ asyncUtilTimeout: 5000 });
