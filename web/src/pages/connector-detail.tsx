// SPDX-License-Identifier: Apache-2.0

import { clone, create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { ApplyStatusView, useLiveApplyStatus } from "@/components/apply-status";
import { Field } from "@/components/field";
import { ManifestButton } from "@/components/manifest";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import type { Revision } from "@/gen/rpmgr/v1/common_pb";
import { ConnectorSchema, ConnectorService, DataTransport, UpdateConnectorRequestSchema, type Connector } from "@/gen/rpmgr/v1/connector_pb";
import type { ApplyStatus } from "@/gen/rpmgr/v1/status_pb";
import { when } from "@/lib/format";
import { SessionChip } from "@/pages/connectors";
import { allowCommand, useAgentNames, useRoutes } from "@/routes-data";
import { useOrg } from "@/session";

const page = getRouteApi("/app/connectors/$connectorId");

// The fields of a connector the API changes (internal/apisvc connectorFields).
const connectorMask = ["name", "labels", "enabled", "transport"];

const pairsOf = (m: Record<string, string>) => Object.keys(m).sort().map((k) => `${k}=${m[k]}`).join("\n");
const mapOf = (v: string) => Object.fromEntries(v.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => {
  const i = l.indexOf("=");
  return i < 0 ? [l, ""] : [l.slice(0, i).trim(), l.slice(i + 1).trim()];
}));

// ConnectorDetail shows a connector's sessions to the controller and the gateways, the routes it
// serves and those it cannot, edits its settings, and decommissions it (docs/09-web-ui.md,
// "Information architecture").
export function ConnectorDetail() {
  const { t } = useTranslation();
  const { connectorId } = page.useParams();
  const org = useOrg();
  const got = useQuery(ConnectorService.method.getConnector, { connectorId });
  const status = useQuery(ConnectorService.method.getConnectorStatus, { connectorId });
  const names = useAgentNames(org?.orgId);
  const routes = useRoutes(org?.orgId);
  const [write, setWrite] = useState<{ revision?: Revision; status?: ApplyStatus }>();
  const live = useLiveApplyStatus(org?.orgId ?? "", write?.revision, write?.status);
  const c = got.data?.connector;
  if (!c) {
    return <p>{got.isError ? t("connectors.notFound") : t("stepUp.loading")}</p>;
  }
  const name = (id: string) => names.data?.get(id) || id;
  const routeName = (id: string) => routes.data?.find((r) => r.id === id)?.name ?? id;
  const served = (routes.data ?? []).filter((r) => r.targets.some((tg) => tg.connectorId === c.id));
  const s = status.data?.status;
  return (
    <div className="grid max-w-4xl gap-6">
      <div className="flex flex-wrap items-center gap-4">
        <h1 className="text-2xl font-semibold">{t("connectors.detailTitle", { name: c.name })}</h1>
        <SessionChip connector={c} />
        {c.session?.version && <span className="text-sm text-muted-foreground">{c.session.version}</span>}
        {org && <ManifestButton label={t("manifest.yaml")} title={t("manifest.of", { name: c.name })} orgId={org.orgId} ids={[c.id]} file={c.name} />}
      </div>
      {live && <ApplyStatusView status={live} revision={write?.revision} name={name} />}

      <section aria-labelledby="sessions-title" className="grid gap-2">
        <h2 id="sessions-title" className="text-lg font-semibold">{t("connectors.sessions")}</h2>
        <p className="text-sm">
          {c.session?.connected
            ? t("connectors.controlUp", { addr: c.session.remoteAddr, when: when(c.session.lastSeenTime) })
            : t("connectors.controlDown", { when: when(c.session?.lastSeenTime) || t("connectors.never") })}
        </p>
        {(s?.dataSessions.length ?? 0) > 0 && (
          <table className="w-full text-left text-sm">
            <thead className="text-muted-foreground">
              <tr>{["gateway", "transport", "rtt", "since"].map((k) => <th key={k} scope="col" className="py-1 font-medium">{t(`connectors.data.${k}`)}</th>)}</tr>
            </thead>
            <tbody>
              {s!.dataSessions.map((d) => (
                <tr key={d.gatewayId + d.transport} className="border-t border-border">
                  <td className="py-1">{name(d.gatewayId)}</td>
                  <td className="py-1">{t(`connectors.transports.${DataTransport[d.transport]}`)}</td>
                  <td className="py-1">{d.rtt ? `${Math.round(Number(d.rtt.seconds) * 1000 + d.rtt.nanos / 1e6)} ms` : ""}</td>
                  <td className="py-1">{when(d.establishTime)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section aria-labelledby="served-title" className="grid gap-2">
        <h2 id="served-title" className="text-lg font-semibold">{t("connectors.routes")}</h2>
        {served.length === 0 ? <p className="text-sm">{t("connectors.noRoutes")}</p> : (
          <ul className="text-sm">
            {served.map((r) => <li key={r.id}><Link to="/routes/$routeId" params={{ routeId: r.id }} className="underline">{r.name}</Link></li>)}
          </ul>
        )}
        {(s?.notReady ?? []).map((n) => (
          <div key={n.resourceId} className="grid gap-1 text-sm">
            <span className="text-warn">{routeName(n.resourceId)}: {t(`notServing.${n.reason}`, { defaultValue: n.reason })}</span>
            {n.reason === "BLOCKED_BY_LOCAL_POLICY" && n.detail && (
              <span className="flex items-center gap-2">
                <code className="rounded bg-muted px-1.5 py-0.5 font-mono">{allowCommand(n.detail)}</code>
                <Button size="sm" variant="outline" onClick={() => void navigator.clipboard?.writeText(allowCommand(n.detail))}>{t("mfa.copy")}</Button>
              </span>
            )}
          </div>
        ))}
      </section>

      <Settings connector={c} onWrite={setWrite} />
      <Decommission connector={c} />
    </div>
  );
}

// Settings changes a connector's name, labels, transport and whether it serves: the connector as
// read, with those fields set, their mask and its etag (docs/09-web-ui.md, U1).
function Settings({ connector: c, onWrite }: { connector: Connector; onWrite: (w: { revision?: Revision; status?: ApplyStatus }) => void }) {
  const { t } = useTranslation();
  const update = useMutation(ConnectorService.method.updateConnector);
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ name: c.name, labels: pairsOf(c.labels), transport: String(c.transport), enabled: c.enabled });
  const [error, setError] = useState("");
  async function save(e: FormEvent) {
    e.preventDefault();
    setError("");
    const next = clone(ConnectorSchema, c);
    Object.assign(next, { name: form.name.trim(), labels: mapOf(form.labels), transport: Number(form.transport), enabled: form.enabled });
    try {
      const res = await update.mutateAsync(create(UpdateConnectorRequestSchema, { connector: next, updateMask: { paths: connectorMask }, etag: c.etag }));
      onWrite({ revision: res.revision, status: res.applyStatus });
      await queryClient.invalidateQueries();
    } catch (err) {
      const e = ConnectError.from(err);
      setError(e.code === Code.FailedPrecondition ? t("connectors.changed") : e.code === Code.InvalidArgument ? e.rawMessage : t("link.failed", { message: e.rawMessage }));
    }
  }
  const transports = [DataTransport.UNSPECIFIED, DataTransport.AUTO, DataTransport.QUIC, DataTransport.H2];
  return (
    <section aria-labelledby="settings-title" className="grid gap-3">
      <h2 id="settings-title" className="text-lg font-semibold">{t("connectors.settings")}</h2>
      <form onSubmit={save} className="grid max-w-xl gap-3" noValidate>
        <Field label={t("routeForm.fields.name")} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <label className="grid gap-1.5 text-sm font-medium">
          {t("routeForm.fields.labels")}
          <textarea rows={2} className="rounded-md border border-border bg-background px-3 py-1.5 font-normal" value={form.labels}
            onChange={(e) => setForm({ ...form, labels: e.target.value })} />
        </label>
        <label className="grid gap-1.5 text-sm font-medium">
          {t("routeForm.fields.transport")}
          <select className="h-9 rounded-md border border-border bg-background px-2 font-normal" value={form.transport}
            onChange={(e) => setForm({ ...form, transport: e.target.value })}>
            {transports.map((v) => <option key={v} value={String(v)}>{t(`connectors.transportSetting.${DataTransport[v]}`)}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
          {t("connectors.enabled")}
        </label>
        {error && <Alert>{error}</Alert>}
        <Button type="submit" className="justify-self-start" disabled={update.isPending}>{t("routeForm.save")}</Button>
      </form>
    </section>
  );
}

// Decommission retires the connector for good, after a confirmation that names it (U7).
function Decommission({ connector: c }: { connector: Connector }) {
  const { t } = useTranslation();
  const decommission = useMutation(ConnectorService.method.decommissionConnector);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  async function go() {
    try {
      await decommission.mutateAsync({ connectorId: c.id, etag: c.etag });
      await queryClient.invalidateQueries();
      await navigate({ to: "/connectors", search: {} });
    } catch (err) {
      setError(t("link.failed", { message: ConnectError.from(err).rawMessage }));
    }
  }
  return (
    <section aria-labelledby="decommission-title" className="grid gap-2">
      <h2 id="decommission-title" className="text-lg font-semibold">{t("connectors.decommissionTitle")}</h2>
      {asking ? (
        <div className="grid gap-2">
          <Alert>{t("connectors.decommissionWarning", { name: c.name })}</Alert>
          <div className="flex gap-2">
            <Button variant="destructive" disabled={decommission.isPending} onClick={() => void go()}>{t("connectors.decommissionNamed", { name: c.name })}</Button>
            <Button variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
          </div>
        </div>
      ) : (
        <Button variant="outline" className="justify-self-start" onClick={() => setAsking(true)}>{t("connectors.decommission")}</Button>
      )}
      {error && <Alert>{error}</Alert>}
    </section>
  );
}
