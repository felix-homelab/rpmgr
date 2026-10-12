// SPDX-License-Identifier: Apache-2.0

import { clone, create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { getRouteApi, Link, useNavigate } from "@tanstack/react-router";
import { ChevronLeft, Copy } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { ApplyStatusView, useLiveApplyStatus } from "@/components/apply-status";
import { Field } from "@/components/field";
import { ManifestButton } from "@/components/manifest";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Select, Textarea } from "@/components/ui/input";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
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
    return <p className="text-sm text-muted-foreground">{got.isError ? t("connectors.notFound") : t("stepUp.loading")}</p>;
  }
  const name = (id: string) => names.data?.get(id) || id;
  const routeName = (id: string) => routes.data?.find((r) => r.id === id)?.name ?? id;
  const served = (routes.data ?? []).filter((r) => r.targets.some((tg) => tg.connectorId === c.id));
  const s = status.data?.status;
  return (
    <div className="grid max-w-4xl gap-6">
      <div className="grid gap-2">
        <Link to="/connectors" search={{}} className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
          <ChevronLeft aria-hidden="true" className="size-4" />{t("connectors.back")}
        </Link>
        <PageHeader title={t("connectors.detailTitle", { name: c.name })}
          description={<span className="flex flex-wrap items-center gap-2"><SessionChip connector={c} />{c.session?.version}</span>}
          actions={org && <ManifestButton label={t("manifest.yaml")} title={t("manifest.of", { name: c.name })} orgId={org.orgId} ids={[c.id]} file={c.name} />} />
      </div>
      {live && <ApplyStatusView status={live} revision={write?.revision} name={name} />}

      <Card title={t("connectors.sessions")}>
        <p className="text-sm">
          {c.session?.connected
            ? t("connectors.controlUp", { addr: c.session.remoteAddr, when: when(c.session.lastSeenTime) })
            : t("connectors.controlDown", { when: when(c.session?.lastSeenTime) || t("connectors.never") })}
        </p>
        {(s?.dataSessions.length ?? 0) > 0 && (
          <Table framed={false}>
            <THead>
              <tr>{["gateway", "transport", "rtt", "since"].map((k) => <TH key={k}>{t(`connectors.data.${k}`)}</TH>)}</tr>
            </THead>
            <tbody>
              {s!.dataSessions.map((d) => (
                <TR key={d.gatewayId + d.transport}>
                  <TD className="font-medium">{name(d.gatewayId)}</TD>
                  <TD>{t(`connectors.transports.${DataTransport[d.transport]}`)}</TD>
                  <TD className="tabular-nums">{d.rtt ? `${Math.round(Number(d.rtt.seconds) * 1000 + d.rtt.nanos / 1e6)} ms` : ""}</TD>
                  <TD>{when(d.establishTime)}</TD>
                </TR>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <Card title={t("connectors.routes")}>
        {served.length === 0 ? <p className="text-sm text-muted-foreground">{t("connectors.noRoutes")}</p> : (
          <ul className="grid gap-1.5 text-sm">
            {served.map((r) => <li key={r.id}><Link to="/routes/$routeId" params={{ routeId: r.id }} className="font-medium hover:underline">{r.name}</Link></li>)}
          </ul>
        )}
        {(s?.notReady ?? []).map((n) => (
          <div key={n.resourceId} className="grid gap-2 rounded-lg border border-warn/30 bg-warn/10 p-3 text-sm">
            <span className="text-warn">{routeName(n.resourceId)}: {t(`notServing.${n.reason}`, { defaultValue: n.reason })}</span>
            {n.reason === "BLOCKED_BY_LOCAL_POLICY" && n.detail && (
              <span className="flex flex-wrap items-center gap-2">
                <code className="rounded-md bg-card px-2 py-1 font-mono">{allowCommand(n.detail)}</code>
                <Button size="sm" variant="outline" onClick={() => void navigator.clipboard?.writeText(allowCommand(n.detail))}>
                  <Copy aria-hidden="true" />{t("mfa.copy")}
                </Button>
              </span>
            )}
          </div>
        ))}
      </Card>

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
    <Card title={t("connectors.settings")}>
      <form onSubmit={save} className="grid max-w-xl gap-4" noValidate>
        <Field label={t("routeForm.fields.name")} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <label className="grid gap-1.5 text-sm font-medium">
          {t("routeForm.fields.labels")}
          <Textarea rows={2} className="font-normal" value={form.labels} onChange={(e) => setForm({ ...form, labels: e.target.value })} />
        </label>
        <label className="grid gap-1.5 text-sm font-medium">
          {t("routeForm.fields.transport")}
          <Select className="font-normal" value={form.transport} onChange={(e) => setForm({ ...form, transport: e.target.value })}>
            {transports.map((v) => <option key={v} value={String(v)}>{t(`connectors.transportSetting.${DataTransport[v]}`)}</option>)}
          </Select>
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
          {t("connectors.enabled")}
        </label>
        {error && <Alert>{error}</Alert>}
        <Button type="submit" className="justify-self-start" disabled={update.isPending}>{t("routeForm.save")}</Button>
      </form>
    </Card>
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
    <Card title={t("connectors.decommissionTitle")} className="border-destructive/30">
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
    </Card>
  );
}
