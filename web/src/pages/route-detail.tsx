// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { ChevronLeft, Pencil, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ApplyStatusView, useLiveApplyStatus } from "@/components/apply-status";
import { ManifestButton } from "@/components/manifest";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { RouteStateChip } from "@/components/route-state";
import { Status } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { ConnectorService, DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import type { Revision } from "@/gen/rpmgr/v1/common_pb";
import { RouteService, RouteState, UpstreamVerification, type Route, type RouteTarget } from "@/gen/rpmgr/v1/route_pb";
import type { ApplyStatus } from "@/gen/rpmgr/v1/status_pb";
import { RouteTraffic } from "@/pages/route-traffic";
import { RoutePolicies } from "@/route-form/route-policies";
import { Reason, reasonOf } from "@/lib/errors";
import { TargetForm, type Written } from "@/route-form/target-form";
import { allowCommand, routeAddress, routeType, useAgentNames, useGroupHostnames, useGroupNames } from "@/routes-data";
import { useOrg } from "@/session";

const route = getRouteApi("/app/routes/$routeId");

// RouteDetail shows a route's desired settings next to what its agents report (docs/09-web-ui.md,
// "Route detail", U3): its targets with their readiness, and for a target that a connector's local
// policy blocks the command that allows it (U4). A route is deleted after a confirmation that names
// it (U7); the page then follows the deletion to the agents (U2).
export function RouteDetail() {
  const { t } = useTranslation();
  const { routeId } = route.useParams();
  const org = useOrg();
  const [deleted, setDeleted] = useState<string>(); // the deleted route's name
  const got = useQuery(RouteService.method.getRoute, { routeId }, { enabled: !deleted });
  const groups = useGroupNames(org?.orgId);
  const hosts = useGroupHostnames(org?.orgId);
  const names = useAgentNames(org?.orgId);
  const update = useMutation(RouteService.method.updateRoute);
  const del = useMutation(RouteService.method.deleteRoute);
  const [asking, setAsking] = useState(false);
  const queryClient = useQueryClient();
  const [write, setWrite] = useState<{ revision?: Revision; status?: ApplyStatus }>();
  const [editing, setEditing] = useState<string>(); // a target's ID, or "new"
  const remove = useMutation(RouteService.method.deleteRouteTarget);
  const done = async (w: Written) => {
    setEditing(undefined);
    setWrite(w);
    await queryClient.invalidateQueries();
  };
  const [error, setError] = useState("");
  const live = useLiveApplyStatus(org?.orgId ?? "", write?.revision, write?.status);
  const r = got.data?.route;
  const name = (id: string) => names.data?.get(id) || id;
  const connectors = [...(names.data ?? new Map<string, string>())].filter(([id]) => id.startsWith("con_"));

  // toggle switches the route on or off, the only desired switch (U3), and follows the change to
  // the agents (U2).
  async function toggle(current: Route) {
    setError("");
    try {
      const res = await update.mutateAsync({ route: { ...current, enabled: !current.enabled }, updateMask: { paths: ["enabled"] }, etag: current.etag });
      setWrite({ revision: res.revision, status: res.applyStatus });
      await queryClient.invalidateQueries();
    } catch (err) {
      const e = ConnectError.from(err);
      setError(e.code === Code.FailedPrecondition ? t("route.changed") : t("link.failed", { message: e.rawMessage }));
    }
  }

  // removeRoute deletes the route as read, under its etag (U6), with its hostnames, targets and
  // port.
  async function removeRoute(current: Route) {
    setError("");
    try {
      const res = await del.mutateAsync({ routeId: current.id, etag: current.etag });
      setDeleted(current.name);
      setWrite({ revision: res.revision, status: res.applyStatus });
      await queryClient.invalidateQueries();
    } catch (err) {
      setAsking(false);
      const changed = reasonOf(err) === Reason.etagMismatch;
      setError(changed ? t("route.changed") : t("link.failed", { message: ConnectError.from(err).rawMessage }));
      if (changed) {
        await queryClient.invalidateQueries();
      }
    }
  }

  if (deleted) {
    return (
      <div className="grid gap-6">
        <div className="grid gap-2">
          <Link to="/routes" search={{}} className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ChevronLeft aria-hidden="true" className="size-4" />{t("route.back")}
          </Link>
          <PageHeader title={t("route.deletedTitle", { name: deleted })} description={t("route.deletedNote")} />
        </div>
        {live && <ApplyStatusView status={live} revision={write?.revision} name={name} />}
      </div>
    );
  }
  if (!r) {
    return <p className="text-sm text-muted-foreground">{got.isError ? t("route.notFound") : t("stepUp.loading")}</p>;
  }
  const status = r.status;
  const gatewayProblems = status?.notServing.filter((n) => !r.targets.some((tg) => tg.id === n.id)) ?? [];
  return (
    <div className="grid gap-6">
      <div className="grid gap-2">
        <Link to="/routes" search={{}} className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
          <ChevronLeft aria-hidden="true" className="size-4" />{t("route.back")}
        </Link>
        <PageHeader title={t("route.title", { name: r.name, type: t(`routeType.${routeType(r) || "unknown"}`) })} actions={asking ? <>
          <span className="text-sm">{t("route.deleteAsk", { name: r.name })}</span>
          <Button size="sm" variant="destructive" disabled={del.isPending} onClick={() => void removeRoute(r)}>{t("route.deleteConfirm")}</Button>
          <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
        </> : <>
          <Switch checked={r.enabled} disabled={update.isPending} onClick={() => void toggle(r)}>{t("route.enabledSwitch")}</Switch>
          {org && <ManifestButton label={t("manifest.yaml")} title={t("manifest.of", { name: r.name })} orgId={org.orgId} ids={[r.id]} file={r.name} />}
          <Button size="sm" variant="outline" onClick={() => { setError(""); setAsking(true); }}><Trash2 aria-hidden="true" />{t("route.delete")}</Button>
          <Button asChild size="sm">
            <Link to="/routes/$routeId/edit" params={{ routeId: r.id }}><Pencil aria-hidden="true" />{t("route.edit")}</Link>
          </Button>
        </>} />
      </div>
      {error && <Alert>{error}</Alert>}
      {live && <ApplyStatusView status={live} revision={write?.revision} name={name} />}
      <dl className="grid gap-4 rounded-xl border border-border bg-card p-5 text-sm shadow-xs sm:grid-cols-2">
        <div className="grid gap-1.5">
          <dt className="text-muted-foreground">{t("route.desired")}</dt>
          <dd>
            {[r.enabled ? t("route.enabled") : t("route.disabled"), t("route.group", { name: groups.data?.get(r.gatewayGroupId) ?? r.gatewayGroupId }),
              ...routeAddress(r, hosts.data?.get(r.gatewayGroupId))].join(" · ")}
          </dd>
        </div>
        <div className="grid gap-1.5">
          <dt className="text-muted-foreground">{t("route.observed")}</dt>
          <dd className="flex flex-wrap items-center gap-2">
            <RouteStateChip state={status?.state ?? RouteState.UNSPECIFIED} />
            {status && status.gatewaysTotal > 0 && (
              <span className="text-muted-foreground">{t("route.gateways", { serving: status.gatewaysServing, total: status.gatewaysTotal })}</span>
            )}
          </dd>
        </div>
      </dl>
      {(r.spec.case === "tcp" || r.spec.case === "udp" || r.spec.case === "tcpUdp") && r.spec.value.port > 0 && hosts.data?.get(r.gatewayGroupId)?.length === 0 && (
        <p className="text-sm text-muted-foreground">
          {t("route.noHostname")}{" "}
          <Link to="/gateways/$groupId" params={{ groupId: r.gatewayGroupId }} className="underline">{t("route.setHostname")}</Link>
        </p>
      )}
      {(r.spec.case === "udp" || r.spec.case === "tcpUdp") && <p className="text-sm text-muted-foreground">{t("route.mtu")}</p>}

      {gatewayProblems.length > 0 && (
        <Card title={t("route.gatewaysTitle")}>
          <ul className="grid gap-1.5 text-sm">
            {gatewayProblems.map((g) => <li key={g.id}>{name(g.id)}: {t(`notServing.${g.reason}`, { defaultValue: g.reason })}</li>)}
          </ul>
        </Card>
      )}

      {(status?.rejections.length ?? 0) > 0 && (
        <Card title={t("route.rejections")}>
          <ul className="grid gap-1.5 text-sm">
            {status!.rejections.map((a) => (
              <li key={a.agentId}>
                <span className="font-medium">{name(a.agentId)}</span>: {a.errors.map((e) => e.message).join("; ") || t("route.noReason")}
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card title={t("route.targets")} actions={!editing && (
        <Button variant="outline" size="sm" onClick={() => setEditing("new")}><Plus aria-hidden="true" />{t("targetForm.addButton")}</Button>
      )}>
        {r.targets.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("route.noTargets")}</p>
        ) : (
          <Table framed={false}>
            <THead>
              <tr>
                {["connector", "address", "weight", "state"].map((c) => <TH key={c}>{t(`route.columns.${c}`)}</TH>)}
              </tr>
            </THead>
            <tbody>
              {r.targets.map((tg) => (
                <TargetRow key={tg.id} route={r} target={tg} connector={name(tg.connectorId)}
                  onEdit={() => setEditing(tg.id)}
                  onRemove={() => remove.mutateAsync({ routeTargetId: tg.id, etag: tg.etag }).then((res) => done({ revision: res.revision, status: res.applyStatus }))} />
              ))}
            </tbody>
          </Table>
        )}
        {editing && (
          <TargetForm route={r} target={r.targets.find((tg) => tg.id === editing)} connectors={connectors}
            onDone={(w) => void done(w)} onCancel={() => setEditing(undefined)} />
        )}
      </Card>

      <RouteTraffic routeId={r.id} />

      {org && <RoutePolicies key={r.etag} orgId={org.orgId} route={r} onDone={(w) => void done(w)} />}
    </div>
  );
}

// TargetRow shows a target and whether it serves; a blocked one gets the command for its host, and
// a served one the transport its connector uses.
function TargetRow({ route: r, target, connector, onEdit, onRemove }: {
  route: Route; target: RouteTarget; connector: string; onEdit: () => void; onRemove: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const problem = r.status?.notServing.find((n) => n.id === target.id);
  const status = useQuery(ConnectorService.method.getConnectorStatus, { connectorId: target.connectorId });
  const transports = new Set(status.data?.status?.dataSessions.map((s) => s.transport));
  const address = target.address.case === "hostPort" ? `${target.address.value.host}:${target.address.value.port}` : target.address.value ?? "";
  const fallback = transports.has(DataTransport.H2) && !transports.has(DataTransport.QUIC) && r.transport !== DataTransport.H2;
  const [asking, setAsking] = useState(false);
  return (
    <TR>
      <TD className="font-medium">{connector}</TD>
      <TD>
        <span className="font-mono">{address}</span>
        {target.tls?.verification === UpstreamVerification.UNVERIFIED && (
          <Badge tone="warn" className="ml-2" title={t("route.unverifiedTitle")}>{t("route.unverified")}</Badge>
        )}
      </TD>
      <TD>{target.weight}</TD>
      <TD>
        {!target.enabled ? (
          <Status look="off">{t("route.targetDisabled")}</Status>
        ) : problem ? (
          <Status look="warn">{t(`notServing.${problem.reason}`, { defaultValue: problem.reason })}</Status>
        ) : (
          <Status look="ok">{t("route.targetReady")}</Status>
        )}
        {fallback && <div className="mt-1 text-muted-foreground">{t("route.fallback")}</div>}
        <div className="mt-2 flex flex-wrap items-center gap-2">
          {asking ? (
            <>
              <span>{t("targetForm.ask", { address })}</span>
              <Button size="sm" variant="destructive" onClick={() => void onRemove().finally(() => setAsking(false))}>{t("targetForm.remove")}</Button>
              <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
            </>
          ) : (
            <>
              <Button size="sm" variant="outline" onClick={onEdit}>{t("targetForm.edit")}</Button>
              <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("targetForm.removeAsk")}</Button>
            </>
          )}
        </div>
        {problem?.reason === "BLOCKED_BY_LOCAL_POLICY" && problem.detail && (
          <div className="mt-2 grid gap-1.5">
            <span>{t("route.runOn", { connector })}</span>
            <span className="flex flex-wrap items-center gap-2">
              <code className="rounded-md bg-muted px-2 py-1 font-mono">{allowCommand(problem.detail)}</code>
              <Button size="sm" variant="outline" onClick={() => void navigator.clipboard?.writeText(allowCommand(problem.detail))}>{t("mfa.copy")}</Button>
            </span>
          </div>
        )}
      </TD>
    </TR>
  );
}
