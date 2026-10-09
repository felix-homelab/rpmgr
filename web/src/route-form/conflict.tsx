// SPDX-License-Identifier: Apache-2.0

import { timestampDate } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@connectrpc/connect-query";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { OrgService } from "@/gen/rpmgr/v1/org_pb";
import type { Route } from "@/gen/rpmgr/v1/route_pb";
import { i18n } from "@/i18n";
import { routeFields, valuesOf, type RouteValues } from "@/route-form/fields";
import { useOrg } from "@/session";

// A field the user or the other change touched.
export interface Change {
  key: string;
  mine?: string; // set if the user changed it
  theirs?: string; // set if the newer version changed it
}

// changes compares the user's values and the newer version with the version the user started from,
// field by field (docs/09-web-ui.md, U6).
export function changes(base: Route, mine: RouteValues, theirs: Route): Change[] {
  const now = valuesOf(theirs);
  const was = valuesOf(base);
  return routeFields(base)
    .map((f) => ({
      key: f.key,
      mine: mine[f.key] !== was[f.key] ? mine[f.key] : undefined,
      theirs: now[f.key] !== was[f.key] ? now[f.key] : undefined,
    }))
    .filter((c) => c.mine !== undefined || c.theirs !== undefined);
}

// onTop is the newer version with the user's changes put on it.
export function onTop(base: Route, mine: RouteValues, theirs: Route): RouteValues {
  const out = valuesOf(theirs);
  for (const c of changes(base, mine, theirs)) {
    if (c.mine !== undefined) {
      out[c.key] = c.mine;
    }
  }
  return out;
}

// ago says how long ago a time was, in the user's language.
function ago(d: Date): string {
  const s = Math.round((d.getTime() - Date.now()) / 1000);
  const [n, unit] = Math.abs(s) < 3600 ? [Math.round(s / 60), "minute"] : Math.abs(s) < 86400 ? [Math.round(s / 3600), "hour"] : [Math.round(s / 86400), "day"];
  return new Intl.RelativeTimeFormat(i18n.language, { numeric: "auto" }).format(n, unit as Intl.RelativeTimeFormatUnit);
}

// Conflict shows what changed since the user opened the form, who changed it, and lets them put their
// changes on the newer version or drop them (docs/09-web-ui.md, U6).
export function Conflict({ base, mine, theirs, onTop: reapply, onDiscard }: {
  base: Route; mine: RouteValues; theirs: Route; onTop: () => void; onDiscard: () => void;
}) {
  const { t } = useTranslation();
  const org = useOrg();
  const members = useQuery(OrgService.method.listMembers, { orgId: org?.orgId ?? "" }, { enabled: !!org });
  const who = members.data?.members.find((m) => m.userId === theirs.updateUserId);
  const by = who ? who.displayName || who.email : theirs.updateUserId;
  const when = theirs.updateTime ? ago(timestampDate(theirs.updateTime)) : "";
  const list = changes(base, mine, theirs);
  return (
    <section aria-labelledby="conflict-title" className="grid gap-3 rounded-md border border-destructive p-4">
      <h2 id="conflict-title" className="font-semibold">{t("conflict.title")}</h2>
      <p role="alert" className="text-sm">{by ? t("conflict.changedBy", { by, when }) : t("conflict.changed", { when })}</p>
      <table className="w-full text-left text-sm">
        <thead className="text-muted-foreground">
          <tr>
            <th scope="col" className="py-1 font-medium">{t("conflict.field")}</th>
            <th scope="col" className="py-1 font-medium">{t("conflict.mine")}</th>
            <th scope="col" className="py-1 font-medium">{t("conflict.theirs")}</th>
          </tr>
        </thead>
        <tbody>
          {list.map((c) => (
            <tr key={c.key} className="border-t border-border align-top">
              <th scope="row" className="py-1 font-medium">
                {t(`routeForm.fields.${c.key}`)}
                {c.mine !== undefined && c.theirs !== undefined && c.mine !== c.theirs && <span className="ml-1 text-destructive">({t("conflict.both")})</span>}
              </th>
              <td className="whitespace-pre-wrap py-1">{c.mine ?? "—"}</td>
              <td className="whitespace-pre-wrap py-1">{c.theirs ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="flex gap-2">
        <Button type="button" onClick={reapply}>{t("conflict.onTop")}</Button>
        <Button type="button" variant="outline" onClick={onDiscard}>{t("conflict.discard")}</Button>
      </div>
    </section>
  );
}
