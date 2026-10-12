// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/page-header";
import { CABundles, Certificates } from "@/pages/certificates";
import { Domains } from "@/pages/domains";

// DomainsPage is "Domains & certificates" (docs/09-web-ui.md, "Information architecture").
export function DomainsPage() {
  const { t } = useTranslation();
  return (
    <div className="grid max-w-5xl gap-6">
      <PageHeader title={t("nav.domains")} description={t("domains.intro")} />
      <Domains />
      <Certificates />
      <CABundles />
    </div>
  );
}
