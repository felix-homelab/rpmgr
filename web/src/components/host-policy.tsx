// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import type { HostUpdatePolicy } from "@/gen/rpmgr/v1/common_pb";

// HostPolicy shows the update channel and the auto-update setting an agent's host last reported
// from its local policy file, or says it reported none (an older release).
export function HostPolicy({ policy }: { policy?: HostUpdatePolicy }) {
  const { t } = useTranslation();
  return (
    <span className="text-xs text-muted-foreground">
      {policy
        ? t("hostPolicy.value", { channel: t(`hostPolicy.channel.${policy.updateChannel}`, policy.updateChannel),
          auto: t(`hostPolicy.auto.${policy.autoUpdate}`, policy.autoUpdate) })
        : t("hostPolicy.unknown")}
    </span>
  );
}
