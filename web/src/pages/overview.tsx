// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { useQuery } from "@connectrpc/connect-query";
import { useTranslation } from "react-i18next";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";

export function Overview() {
  const { t } = useTranslation();
  const session = useQuery(AuthService.method.getSession, {});
  let status: string;
  if (session.isPending) {
    status = t("overview.loading");
  } else if (session.data) {
    status = t("overview.signedIn", { name: session.data.displayName || session.data.email });
  } else if (ConnectError.from(session.error).code === Code.Unauthenticated) {
    status = t("overview.signedOut");
  } else {
    status = t("overview.error", { message: ConnectError.from(session.error).rawMessage });
  }
  return (
    <section aria-labelledby="overview-title">
      <h1 id="overview-title" className="text-2xl font-semibold">
        {t("overview.title")}
      </h1>
      <p role="status" className="mt-2 text-muted-foreground">
        {status}
      </p>
    </section>
  );
}
