// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@connectrpc/connect-query";
import { getRouteApi } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { RouteStateChip } from "@/components/route-state";
import { Button } from "@/components/ui/button";
import { ConnectorService, DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import { RouteService, RouteState, type Route, type RouteTarget } from "@/gen/rpmgr/v1/route_pb";
import { allowCommand, routeAddress, routeType, useAgentNames, useGroupNames } from "@/routes-data";
import { useOrg } from "@/session";

const route = getRouteApi("/app/routes/$routeId");

// RouteDetail shows a route's desired settings next to what its agents report (docs/09-web-ui.md,
// "Route detail", U3): its targets with their readiness, and for a target that a connector's local
// policy blocks the command that allows it (U4).
export function RouteDetail() {
  const { t } = useTranslation();
  const { routeId } = route.useParams();
  const org = useOrg();
  const got = useQuery(RouteService.method.getRoute, { routeId });
  const groups = useGroupNames(org?.orgId);
  const names = useAgentNames(org?.orgId);
  const r = got.data?.route;
  if (!r) {
    return <p>{got.isError ? t("route.notFound") : t("stepUp.loading")}</p>;
  }
  const name = (id: string) => names.data?.get(id) || id;
  const status = r.status;
  const gatewayProblems = status?.notServing.filter((n) => !r.targets.some((tg) => tg.id === n.id)) ?? [];
  return (
    <div className="grid gap-6">
      <h1 className="text-2xl font-semibold">{t("route.title", { name: r.name, type: t(`routeType.${routeType(r) || "unknown"}`) })}</h1>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
        <dt className="text-muted-foreground">{t("route.desired")}</dt>
        <dd>
          {[r.enabled ? t("route.enabled") : t("route.disabled"), t("route.group", { name: groups.data?.get(r.gatewayGroupId) ?? r.gatewayGroupId }),
            ...routeAddress(r)].join(" · ")}
        </dd>
        <dt className="text-muted-foreground">{t("route.observed")}</dt>
        <dd>
          <RouteStateChip state={status?.state ?? RouteState.UNSPECIFIED} />
          {status && status.gatewaysTotal > 0 && (
            <span className="ml-2 text-muted-foreground">{t("route.gateways", { serving: status.gatewaysServing, total: status.gatewaysTotal })}</span>
          )}
        </dd>
      </dl>
      {r.spec.case === "udp" && <p className="text-sm text-muted-foreground">{t("route.mtu")}</p>}

      <section aria-labelledby="targets-title" className="grid gap-2">
        <h2 id="targets-title" className="text-lg font-semibold">{t("route.targets")}</h2>
        <table className="w-full text-left text-sm">
          <thead className="text-muted-foreground">
            <tr>
              {["connector", "address", "weight", "state"].map((c) => <th key={c} scope="col" className="py-1 font-medium">{t(`route.columns.${c}`)}</th>)}
            </tr>
          </thead>
          <tbody>
            {r.targets.map((tg) => <TargetRow key={tg.id} route={r} target={tg} connector={name(tg.connectorId)} />)}
          </tbody>
        </table>
        {r.targets.length === 0 && <p className="text-sm">{t("route.noTargets")}</p>}
      </section>

      {gatewayProblems.length > 0 && (
        <section aria-labelledby="gateways-title" className="grid gap-2">
          <h2 id="gateways-title" className="text-lg font-semibold">{t("route.gatewaysTitle")}</h2>
          <ul className="text-sm">
            {gatewayProblems.map((g) => <li key={g.id}>{name(g.id)}: {t(`notServing.${g.reason}`, { defaultValue: g.reason })}</li>)}
          </ul>
        </section>
      )}

      {(status?.rejections.length ?? 0) > 0 && (
        <section aria-labelledby="rejections-title" className="grid gap-2">
          <h2 id="rejections-title" className="text-lg font-semibold">{t("route.rejections")}</h2>
          <ul className="grid gap-1 text-sm">
            {status!.rejections.map((a) => (
              <li key={a.agentId}>
                <span className="font-medium">{name(a.agentId)}</span>: {a.errors.map((e) => e.message).join("; ") || t("route.noReason")}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

// TargetRow shows a target and whether it serves; a blocked one gets the command for its host, and
// a served one the transport its connector uses.
function TargetRow({ route: r, target, connector }: { route: Route; target: RouteTarget; connector: string }) {
  const { t } = useTranslation();
  const problem = r.status?.notServing.find((n) => n.id === target.id);
  const status = useQuery(ConnectorService.method.getConnectorStatus, { connectorId: target.connectorId });
  const transports = new Set(status.data?.status?.dataSessions.map((s) => s.transport));
  const address = target.address.case === "hostPort" ? `${target.address.value.host}:${target.address.value.port}` : target.address.value ?? "";
  const fallback = transports.has(DataTransport.H2) && !transports.has(DataTransport.QUIC) && r.transport !== DataTransport.H2;
  return (
    <tr className="border-t border-border align-top">
      <td className="py-2">{connector}</td>
      <td className="py-2 font-mono">{address}</td>
      <td className="py-2">{target.weight}</td>
      <td className="py-2">
        {!target.enabled ? (
          t("route.targetDisabled")
        ) : problem ? (
          <span className="text-warn">{t(`notServing.${problem.reason}`, { defaultValue: problem.reason })}</span>
        ) : (
          <span className="text-ok">{t("route.targetReady")}</span>
        )}
        {fallback && <div className="text-muted-foreground">{t("route.fallback")}</div>}
        {problem?.reason === "BLOCKED_BY_LOCAL_POLICY" && problem.detail && (
          <div className="mt-1 grid gap-1">
            <span>{t("route.runOn", { connector })}</span>
            <span className="flex items-center gap-2">
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono">{allowCommand(problem.detail)}</code>
              <Button size="sm" variant="outline" onClick={() => void navigator.clipboard?.writeText(allowCommand(problem.detail))}>{t("mfa.copy")}</Button>
            </span>
          </div>
        )}
      </td>
    </tr>
  );
}
