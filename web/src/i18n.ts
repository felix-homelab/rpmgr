// SPDX-License-Identifier: Apache-2.0

import i18next, { type InitOptions } from "i18next";
import { initReactI18next } from "react-i18next";
import en from "@/locales/en.json";

// English is the source language and the fallback, so a missing key in a translation shows the
// English text, never the key (docs/09-web-ui.md, U11). Phase 1 ships English only.
export const options: InitOptions = {
  resources: { en: { translation: en } },
  lng: "en",
  fallbackLng: "en",
  supportedLngs: ["en"],
  interpolation: { escapeValue: false }, // React escapes what it renders
  returnNull: false,
  returnEmptyString: false,
};

export const i18n = i18next.createInstance();
void i18n.use(initReactI18next).init(options);
