// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@connectrpc/connect-query";
import { useTranslation } from "react-i18next";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";

export function Overview() {
  const { t } = useTranslation();
  const session = useQuery(AuthService.method.getSession, {});
  return (
    <section aria-labelledby="overview-title">
      <h1 id="overview-title" className="text-2xl font-semibold">
        {t("overview.title")}
      </h1>
      {session.data && (
        <p className="mt-2 text-muted-foreground">
          {t("overview.signedIn", { name: session.data.displayName || session.data.email })}
        </p>
      )}
    </section>
  );
}
