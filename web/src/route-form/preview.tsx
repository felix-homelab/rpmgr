// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import type { PreviewRouteResponse } from "@/gen/rpmgr/v1/route_pb";
import { routeAddress } from "@/routes-data";

// PreviewPanel shows what PreviewRoute found, without anything saved: where the route would be
// reached, the gateways and connectors that would carry it, and what a gateway would refuse.
export function PreviewPanel({ preview, name }: { preview: PreviewRouteResponse; name: (id: string) => string }) {
  const { t } = useTranslation();
  const where = preview.route ? routeAddress(preview.route) : [];
  return (
    <section aria-labelledby="preview-title" className="grid gap-1 rounded-md border border-border p-3 text-sm">
      <h2 id="preview-title" className="font-semibold">{t("preview.title")}</h2>
      {where.length > 0 && <p>{t("preview.address", { address: where.join(", ") })}</p>}
      <p>{t("preview.gateways", { names: preview.gatewayIds.map(name).join(", ") || t("preview.none") })}</p>
      <p>{t("preview.connectors", { names: preview.connectorIds.map(name).join(", ") || t("preview.none") })}</p>
      {preview.problems.length > 0 ? (
        <ul role="alert" className="text-destructive">
          {preview.problems.map((p, i) => <li key={i}>{p.message}</li>)}
        </ul>
      ) : (
        <p className="text-ok">{t("preview.ok")}</p>
      )}
    </section>
  );
}
