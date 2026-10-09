// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import { CABundles, Certificates } from "@/pages/certificates";
import { Domains } from "@/pages/domains";

// DomainsPage is "Domains & certificates" (docs/09-web-ui.md, "Information architecture").
export function DomainsPage() {
  const { t } = useTranslation();
  return (
    <div className="grid max-w-4xl gap-6">
      <h1 className="text-2xl font-semibold">{t("nav.domains")}</h1>
      <Domains />
      <Certificates />
      <CABundles />
    </div>
  );
}
