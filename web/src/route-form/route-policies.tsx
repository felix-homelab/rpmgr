// SPDX-License-Identifier: Apache-2.0

import { clone } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { RouteSchema, RouteService, type Route } from "@/gen/rpmgr/v1/route_pb";
import { usePolicies } from "@/pages/policies";
import type { Written } from "@/route-form/target-form";

// RoutePolicies shows the access policies a route applies, in order, and changes them: added,
// removed and moved, then saved as the route as read with the mask policy_ids and its etag (U1).
export function RoutePolicies({ orgId, route: r, onDone }: { orgId: string; route: Route; onDone: (w: Written) => void }) {
  const { t } = useTranslation();
  const policies = usePolicies(orgId);
  const update = useMutation(RouteService.method.updateRoute);
  const queryClient = useQueryClient();
  const [ids, setIds] = useState(r.policyIds);
  const [adding, setAdding] = useState("");
  const [error, setError] = useState("");
  const name = (id: string) => policies.data?.find((p) => p.id === id)?.name ?? id;
  const changed = ids.join() !== r.policyIds.join();
  const move = (i: number, by: number) => {
    const next = [...ids];
    [next[i], next[i + by]] = [next[i + by]!, next[i]!];
    setIds(next);
  };
  async function save() {
    setError("");
    const next = clone(RouteSchema, r);
    next.policyIds = ids;
    try {
      const res = await update.mutateAsync({ route: next, updateMask: { paths: ["policy_ids"] }, etag: r.etag });
      onDone({ revision: res.revision, status: res.applyStatus });
      await queryClient.invalidateQueries();
    } catch (err) {
      const e = ConnectError.from(err);
      setError(e.code === Code.FailedPrecondition ? t("route.changed") : e.rawMessage);
    }
  }
  return (
    <section aria-labelledby="route-policies-title" className="grid gap-2">
      <h2 id="route-policies-title" className="text-lg font-semibold">{t("routePolicies.title")}</h2>
      {ids.length === 0 ? <p className="text-sm">{t("routePolicies.none")}</p> : (
        <ol className="grid gap-1 text-sm">
          {ids.map((id, i) => (
            <li key={id} className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{i + 1}. {name(id)}</span>
              <Button size="sm" variant="outline" disabled={i === 0} onClick={() => move(i, -1)}>{t("policies.up")}</Button>
              <Button size="sm" variant="outline" disabled={i === ids.length - 1} onClick={() => move(i, 1)}>{t("policies.down")}</Button>
              <Button size="sm" variant="outline" onClick={() => setIds(ids.filter((x) => x !== id))}>{t("routePolicies.detach")}</Button>
            </li>
          ))}
        </ol>
      )}
      <div className="flex flex-wrap items-end gap-2">
        <label className="grid gap-1 text-sm">
          {t("routePolicies.add")}
          <select className="h-9 rounded-md border border-border bg-background px-2" value={adding} onChange={(e) => setAdding(e.target.value)}>
            <option value="">{t("routePolicies.choose")}</option>
            {(policies.data ?? []).filter((p) => !ids.includes(p.id)).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </label>
        <Button size="sm" variant="outline" disabled={!adding} onClick={() => (setIds([...ids, adding]), setAdding(""))}>{t("routePolicies.attach")}</Button>
        <Button size="sm" disabled={!changed || update.isPending} onClick={() => void save()}>{t("routeForm.save")}</Button>
      </div>
      {error && <Alert>{error}</Alert>}
    </section>
  );
}
