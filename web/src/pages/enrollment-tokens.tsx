// SPDX-License-Identifier: Apache-2.0

import { timestampDate } from "@bufbuild/protobuf/wkt";
import { createClient } from "@connectrpc/connect";
import { useMutation, useTransport } from "@connectrpc/connect-query";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { EnrollmentService, type EnrollmentToken } from "@/gen/rpmgr/v1/enrollment_pb";
import { when } from "@/lib/format";
import { largestPage, listAll } from "@/lib/list-all";

// EnrollmentTokens lists the org's enrollment tokens that can still enroll, and revokes one after a
// confirmation (docs/09-web-ui.md, "Connectors").
export function EnrollmentTokens({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const transport = useTransport();
  const list = useQuery({
    queryKey: ["enrollment-tokens", orgId],
    queryFn: () => {
      const api = createClient(EnrollmentService, transport);
      return listAll(async (pageToken) => {
        const r = await api.listEnrollmentTokens({ orgId, pageSize: largestPage, pageToken });
        return { items: r.enrollmentTokens, next: r.nextPageToken };
      });
    },
  });
  const tokens = (list.data ?? []).filter((tok) => tok.connectorId === "" && tok.gatewayId === "");
  return (
    <section aria-labelledby="tokens-title" className="grid gap-2">
      <h2 id="tokens-title" className="text-lg font-semibold">{t("enroll.tokensTitle")}</h2>
      {tokens.length === 0 ? <p className="text-sm">{t("enroll.noTokens")}</p> : (
        <ul className="grid gap-2">{tokens.map((tok) => <TokenRow key={tok.id} token={tok} />)}</ul>
      )}
    </section>
  );
}

function TokenRow({ token: tok }: { token: EnrollmentToken }) {
  const { t } = useTranslation();
  const revoke = useMutation(EnrollmentService.method.revokeEnrollmentToken);
  const queryClient = useQueryClient();
  const [asking, setAsking] = useState(false);
  const uses = tok.maxUses === 0 ? t("enroll.usedUnlimited", { count: tok.useCount }) : t("enroll.used", { count: tok.useCount, max: tok.maxUses });
  const expired = tok.expireTime ? timestampDate(tok.expireTime) < new Date() : false;
  return (
    <li className="grid gap-1 rounded-md border border-border p-3 text-sm">
      <div className="flex flex-wrap gap-x-4">
        <span>{t("enroll.createdAt", { when: when(tok.createTime) })}</span>
        <span>{t(expired ? "enroll.expired" : "enroll.expiresAt", { when: when(tok.expireTime) })}</span>
        <span>{uses}</span>
        {tok.ephemeral && <span>{t("enroll.ephemeral")}</span>}
      </div>
      {Object.keys(tok.labels).length > 0 && <div className="text-muted-foreground">{Object.entries(tok.labels).map(([k, v]) => `${k}=${v}`).join(", ")}</div>}
      {tok.lastUseTime && <div className="text-muted-foreground">{t("tokens.lastUse", { when: when(tok.lastUseTime), ip: tok.lastUseIp })}</div>}
      {asking ? (
        <div className="flex items-center gap-2">
          {t("enroll.revokeAsk", { when: when(tok.createTime) })}
          <Button size="sm" variant="destructive" disabled={revoke.isPending}
            onClick={() => void revoke.mutateAsync({ enrollmentTokenId: tok.id }).then(() => queryClient.invalidateQueries())}>{t("tokens.revoke")}</Button>
          <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
        </div>
      ) : (
        <Button size="sm" variant="outline" className="justify-self-start" onClick={() => setAsking(true)}>{t("tokens.revokeAsk")}</Button>
      )}
    </li>
  );
}
