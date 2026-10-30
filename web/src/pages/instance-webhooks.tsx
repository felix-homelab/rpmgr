// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import { InstanceAdminPage, InstanceSettingsSection } from "@/pages/settings";
import { InstanceWebhooks } from "@/pages/webhooks";

// InstanceWebhooksPage is Settings → Webhooks for the Instance Admin: the endpoints that receive
// the instance's events, and the private networks organisations' receivers may be in
// (docs/09-web-ui.md, "Live logs, webhooks and audit sinks (Phase 2)").
export function InstanceWebhooksPage() {
  const { t } = useTranslation();
  return (
    <InstanceAdminPage title={t("webhooks.title")}>
      <InstanceWebhooks />
      <InstanceSettingsSection title={t("settings.sections.webhooks")} sections={["webhooks"]} />
    </InstanceAdminPage>
  );
}
