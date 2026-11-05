// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import type { TFunction } from "i18next";
import { ChevronLeft, Pencil, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ApplyStatusView, useLiveApplyStatus } from "@/components/apply-status";
import { DnsLine } from "@/components/dns-status";
import { ManifestButton } from "@/components/manifest";
import { PageHeader } from "@/components/page-header";
import { PolicyHint } from "@/components/policy-hint";
import { Alert } from "@/components/public-page";
import { RouteStateChip } from "@/components/route-state";
import { Status } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import type { Revision } from "@/gen/rpmgr/v1/common_pb";
import { HealthCheckType, RouteService, RouteState, UpstreamVerification, type Route, type RouteTarget, type TargetTransport } from "@/gen/rpmgr/v1/route_pb";
import type { ApplyStatus } from "@/gen/rpmgr/v1/status_pb";
import { RouteTraffic } from "@/pages/route-traffic";
import { RoutePolicies } from "@/route-form/route-policies";
import { Reason, reasonOf } from "@/lib/errors";
import { groupLabel, targetGroups, transportSummary } from "@/lib/route-transport";
import { TargetForm, type Written } from "@/route-form/target-form";
import { policyCommand, routeAddress, routeType, useAgentNames, useGroupHostnames, useGroupNames } from "@/routes-data";
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

  // toggle switches the route on or off, its only on/off switch (U3), or switches an http route's
  // maintenance, which changes what it answers (D88); it follows the change to the agents (U2).
  async function toggle(current: Route, what: "enabled" | "maintenance" = "enabled") {
    setError("");
    const next = what === "enabled" ? { ...current, enabled: !current.enabled }
      : current.spec.case === "http" ? { ...current, spec: { case: "http" as const, value: { ...current.spec.value, maintenance: !current.spec.value.maintenance } } }
      : current;
    try {
      const res = await update.mutateAsync({ route: next, updateMask: { paths: [what === "enabled" ? "enabled" : "http.maintenance"] }, etag: current.etag });
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
          {r.spec.case === "http" && (
            <Switch checked={r.spec.value.maintenance} disabled={update.isPending} onClick={() => void toggle(r, "maintenance")}>{t("route.maintenanceSwitch")}</Switch>
          )}
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
            {[r.enabled ? t("route.enabled") : t("route.disabled"), ...(r.spec.case === "http" && r.spec.value.maintenance ? [t("route.inMaintenance")] : []),
              t("route.group", { name: groups.data?.get(r.gatewayGroupId) ?? r.gatewayGroupId }), ...routeAddress(r, hosts.data?.get(r.gatewayGroupId))].join(" · ")}
            {r.spec.case === "http" && r.spec.value.maintenance && r.spec.value.maintenanceMessage && (
              <p className="mt-1.5 whitespace-pre-wrap text-muted-foreground">{t("route.maintenanceMessage", { message: r.spec.value.maintenanceMessage })}</p>
            )}
            <p className="mt-1.5 text-muted-foreground">{checkSummary(r, t)}</p>
          </dd>
        </div>
        <div className="grid gap-1.5">
          <dt className="text-muted-foreground">{t("route.observed")}</dt>
          <dd className="flex flex-wrap items-center gap-2">
            <RouteStateChip state={status?.state ?? RouteState.UNSPECIFIED} />
            {status && status.gatewaysTotal > 0 && (
              <span className="text-muted-foreground">{t("route.gateways", { serving: status.gatewaysServing, total: status.gatewaysTotal })}</span>
            )}
            {transportSummary(r, t) !== "" && (
              <span className="text-muted-foreground" title={t("transport.summaryTitle")}>{t("transport.title")}: {transportSummary(r, t)}</span>
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

      {r.dnsStatus.length > 0 && (
        <Card title={t("dnsStatus.title")} description={t("dnsStatus.intro")}>
          <ul className="grid gap-3 text-sm">{r.dnsStatus.map((s) => <DnsLine key={s.hostname} status={s} />)}</ul>
        </Card>
      )}

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
                {["connector", "address", "weight", "priority", "health", "transport", "state"].map((c) => <TH key={c}>{t(`route.columns.${c}`)}</TH>)}
              </tr>
            </THead>
            <tbody>
              {r.targets.map((tg) => (
                <TargetRow key={tg.id} route={r} target={tg} connector={name(tg.connectorId)} name={name}
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

// TargetRow shows a target, whether it serves and the transport it is served over; a blocked one
// gets the command for its host.
function TargetRow({ route: r, target, connector, name, onEdit, onRemove }: {
  route: Route; target: RouteTarget; connector: string; name: (id: string) => string; onEdit: () => void; onRemove: () => Promise<void>;
}) {
  const { t } = useTranslation();
  // A target whose health check has not decided yet still serves (D156); its Health cell says so.
  const problem = r.status?.notServing.find((n) => n.id === target.id && n.reason !== "TARGET_UNKNOWN");
  const address = target.address.case === "hostPort" ? `${target.address.value.host}:${target.address.value.port}` : target.address.value ?? "";
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
      <TD>{target.priority}</TD>
      <TD><TargetHealth route={r} target={target} /></TD>
      <TD><TargetTransportCell tt={r.status?.targetTransports.find((x) => x.targetId === target.id)} serving={target.enabled && !problem} name={name} /></TD>
      <TD>
        {!target.enabled ? (
          <Status look="off">{t("route.targetDisabled")}</Status>
        ) : problem ? (
          <Status look="warn">{t(`notServing.${problem.reason}`, { defaultValue: problem.reason })}</Status>
        ) : (
          <Status look="ok">{t("route.targetReady")}</Status>
        )}
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
            {policyCommand(problem.detail) !== undefined && <span>{t("route.runOn", { connector })}</span>}
            <PolicyHint detail={problem.detail} className="bg-muted" />
          </div>
        )}
      </TD>
    </TR>
  );
}

// TargetTransportCell says which transport a target's streams take, per gateway where the gateways
// differ (docs/03-connections.md, "Transport selection"). Nothing where the target does not serve.
function TargetTransportCell({ tt, serving, name }: { tt?: TargetTransport; serving: boolean; name: (id: string) => string }) {
  const { t } = useTranslation();
  const groups = serving ? targetGroups(tt) : [];
  if (groups.length === 0) {
    return <span className="text-muted-foreground">{t("transport.none")}</span>;
  }
  return (
    <div className="grid gap-1">
      {groups.map((g) => {
        const label = groupLabel(g.key, tt?.pinnedBy ?? 0, t);
        const names = g.gateways.map(name).join(", ");
        // One group names no gateway; several say where each applies, the names on hover.
        const text = groups.length === 1 ? label
          : g.gateways.length === 1 ? t("transport.onGateway", { label, name: names })
          : t("transport.onGateways", { label, count: g.gateways.length });
        return <span key={g.key} title={names}>{text}</span>;
      })}
    </div>
  );
}

// checkSummary says what health check the route has, if any, and how often it runs when set.
function checkSummary(r: Route, t: TFunction): string {
  const c = r.healthCheck;
  if (!c) {
    return t("route.health.none");
  }
  const kind = c.type === HealthCheckType.HTTP ? t("route.health.http", { path: c.httpPath || "/" }) : t("route.health.tcp");
  return c.intervalSeconds > 0 ? `${kind}, ${t("route.health.every", { interval: c.intervalSeconds })}` : kind;
}

// TargetHealth is what the route's health check found of an enabled target (docs/03-connections.md,
// "Target health"): healthy, unhealthy with the last failure, unknown until its first check, or not
// checked by a connector of an earlier release; nothing without a check or while the target does not serve for another reason,
// which the status column names.
function TargetHealth({ route: r, target }: { route: Route; target: RouteTarget }) {
  const { t } = useTranslation();
  const problem = r.status?.notServing.find((n) => n.id === target.id);
  if (!r.healthCheck || !target.enabled || !r.status) {
    return <span className="text-muted-foreground">{t("route.health.unknown")}</span>;
  }
  if (r.status.healthNotChecked.includes(target.id)) {
    return (
      <>
        <Status look="off">{t("route.health.notChecked")}</Status>
        <div className="mt-1 text-muted-foreground">{t("route.health.notCheckedNote")}</div>
      </>
    );
  }
  if (problem?.reason === "TARGET_UNKNOWN") {
    return (
      <>
        <Status look="off">{t("route.health.undecided")}</Status>
        <div className="mt-1 text-muted-foreground">{t("route.health.undecidedNote")}</div>
      </>
    );
  }
  if (problem?.reason === "TARGETS_UNHEALTHY") {
    return (
      <>
        <Status look="warn">{t("route.health.unhealthy")}</Status>
        {problem.detail && <div className="mt-1 break-words text-muted-foreground">{t("route.health.lastFailure", { detail: problem.detail })}</div>}
      </>
    );
  }
  if (problem) {
    return <span className="text-muted-foreground">{t("route.health.unknown")}</span>;
  }
  return <Status look="ok">{t("route.health.healthy")}</Status>;
}
