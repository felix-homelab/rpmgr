// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@connectrpc/connect-query";
import { Link } from "@tanstack/react-router";
import { createContext, useContext } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { when } from "@/lib/format";

// RefusedInReview tells the banner that the API refused a change because of the restore review;
// the app's error handler sets it for every refused write.
export const RefusedInReview = createContext<{ refused: boolean; dismiss: () => void }>({ refused: false, dismiss: () => {} });

// RestoreReviewBanner is shown on every page while the instance is in restore review after a
// restore that failed closed, and after a change the review refused (docs/09-web-ui.md, "Restore
// review"). It never offers to end the review: only the Instance Admin does, on the controller host.
export function RestoreReviewBanner() {
  const { t } = useTranslation();
  const since = useQuery(UserService.method.getMe, {}).data?.restoreReviewTime;
  const { refused, dismiss } = useContext(RefusedInReview);
  if (!since && !refused) {
    return null;
  }
  return (
    <section aria-label={t("review.title")} className="border-b border-warn">
      <div className="mx-auto grid max-w-6xl gap-1 px-4 py-3 text-sm">
        {since && (
          <>
            <p className="font-medium">{t("review.banner", { since: when(since) })}</p>
            <p>
              {t("review.bannerHow")}{" "}
              <code className="font-mono">rpmgr restore confirm</code>{" "}
              <Link to="/org" className="underline">{t("review.toOrg")}</Link>
            </p>
          </>
        )}
        {refused && (
          <p role="alert" className="flex flex-wrap items-center gap-2 text-destructive">
            {t("review.refused")}
            <Button size="sm" variant="outline" onClick={dismiss}>{t("review.dismiss")}</Button>
          </p>
        )}
      </div>
    </section>
  );
}
