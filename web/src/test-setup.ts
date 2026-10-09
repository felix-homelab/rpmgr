// SPDX-License-Identifier: Apache-2.0

// jsdom has no scrolling, which the router's scroll restoration calls, and no modal dialogs.
if (typeof window !== "undefined") {
  window.scrollTo = () => {};
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.open = true;
  };
}
