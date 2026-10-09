// SPDX-License-Identifier: Apache-2.0

import { clone, create, type DescMessage } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { useId, useState } from "react";
import { useForm, useWatch, type Path, type Resolver, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { Revision } from "@/gen/rpmgr/v1/common_pb";
import {
  CreateRouteTargetRequestSchema, ProxyProtocol, RouteService, RouteTargetSchema, UpdateRouteTargetRequestSchema, UpstreamProtocol,
  type Route, type RouteTarget,
} from "@/gen/rpmgr/v1/route_pb";
import type { ApplyStatus } from "@/gen/rpmgr/v1/status_pb";
import { protoResolver, serverFieldErrors, type FieldOf } from "@/lib/proto-form";

export interface TargetValues {
  connector: string;
  address: "hostPort" | "unixPath";
  host: string;
  port: string;
  unixPath: string;
  upstream: string;
  serverName: string;
  caBundle: string;
  spki: string;
  proxy: string;
  weight: string;
  priority: string;
  enabled: boolean;
}

// The fields of a target that UpdateRouteTarget changes (internal/apisvc targetFields).
export const targetMask = ["host_port", "unix_path", "upstream_protocol", "tls", "proxy_protocol", "weight", "priority", "enabled"];

const paths: Record<string, keyof TargetValues> = {
  connector_id: "connector", "host_port.host": "host", "host_port.port": "port", unix_path: "unixPath", upstream_protocol: "upstream",
  "tls.server_name": "serverName", "tls.ca_bundle_id": "caBundle", "tls.spki_sha256": "spki", proxy_protocol: "proxy", weight: "weight", priority: "priority",
};

export const targetFieldOf: FieldOf<TargetValues> = (path) => {
  const p = path.replace(/^target\./, "");
  return paths[p] ?? (p.startsWith("host_port") ? "host" : undefined);
};

export function targetValues(t: RouteTarget): TargetValues {
  return {
    connector: t.connectorId,
    address: t.address.case === "unixPath" ? "unixPath" : "hostPort",
    host: t.address.case === "hostPort" ? t.address.value.host : "",
    port: t.address.case === "hostPort" ? String(t.address.value.port) : "",
    unixPath: t.address.case === "unixPath" ? t.address.value : "",
    upstream: String(t.upstreamProtocol),
    serverName: t.tls?.serverName ?? "",
    caBundle: t.tls?.caBundleId ?? "",
    spki: t.tls?.spkiSha256 ?? "",
    proxy: String(t.proxyProtocol),
    weight: String(t.weight),
    priority: String(t.priority),
    enabled: t.enabled,
  };
}

const whole = (v: string) => (/^\d+$/.test(v.trim()) ? Number(v.trim()) : Number.NaN);

// targetWith is the target as read with the form's values in the fields the form shows (U1).
export function targetWith(base: RouteTarget, v: TargetValues): RouteTarget {
  const t = clone(RouteTargetSchema, base);
  t.connectorId = base.connectorId || v.connector; // a target keeps its connector
  t.address = v.address === "unixPath" ? { case: "unixPath", value: v.unixPath.trim() } : { case: "hostPort", value: { $typeName: "rpmgr.v1.HostPort", host: v.host.trim(), port: whole(v.port) } };
  t.upstreamProtocol = Number(v.upstream);
  t.tls = Number(v.upstream) === UpstreamProtocol.HTTPS ? { $typeName: "rpmgr.v1.UpstreamTLSSettings", serverName: v.serverName.trim(), caBundleId: v.caBundle.trim(), spkiSha256: v.spki.trim().toLowerCase() } : undefined;
  t.proxyProtocol = Number(v.proxy);
  t.weight = whole(v.weight);
  t.priority = whole(v.priority);
  t.enabled = v.enabled;
  return t;
}

// The upstream protocols and PROXY versions a route's type allows.
function choices(r: Route) {
  const http = r.spec.case === "http";
  return {
    upstreams: http ? [UpstreamProtocol.HTTP, UpstreamProtocol.HTTPS, UpstreamProtocol.H2C] : [UpstreamProtocol.TCP],
    proxies: r.spec.case === "tcp" || r.spec.case === "tlsPassthrough" ? [ProxyProtocol.NONE, ProxyProtocol.V1, ProxyProtocol.V2] : [],
  };
}

export type Written = { revision?: Revision; status?: ApplyStatus };

// TargetForm adds a target to a route, or edits one: the whole target as read, its update mask and
// its etag (docs/09-web-ui.md, U1); onDone gets the write's revision and apply status.
export function TargetForm({ route, target, connectors, onDone, onCancel }: {
  route: Route; target?: RouteTarget; connectors: [string, string][]; onDone: (w: Written) => void; onCancel: () => void;
}) {
  const { t } = useTranslation();
  const { upstreams, proxies } = choices(route);
  const base = target ?? create(RouteTargetSchema, { enabled: true, weight: 100, upstreamProtocol: upstreams[0], proxyProtocol: proxies[0] ?? ProxyProtocol.UNSPECIFIED });
  const [requestId] = useState(() => crypto.randomUUID());
  const add = useMutation(RouteService.method.createRouteTarget);
  const update = useMutation(RouteService.method.updateRouteTarget);
  const request = (v: TargetValues) => target
    ? create(UpdateRouteTargetRequestSchema, { target: targetWith(base, v), updateMask: { paths: targetMask }, etag: target.etag })
    : create(CreateRouteTargetRequestSchema, { routeId: route.id, target: targetWith(base, v), requestId });
  const schema: DescMessage = target ? UpdateRouteTargetRequestSchema : CreateRouteTargetRequestSchema;
  const checks = protoResolver<TargetValues, DescMessage>(schema, request, targetFieldOf);
  const resolver: Resolver<TargetValues> = (v, ctx, opts) => {
    const bad = (["weight", "priority", ...(v.address === "hostPort" ? ["port"] : [])] as (keyof TargetValues)[]).filter((k) => !/^\d+$/.test(String(v[k]).trim()));
    if (!target && !v.connector) {
      bad.push("connector");
    }
    if (bad.length > 0) {
      return { values: {}, errors: Object.fromEntries(bad.map((k) => [k, { type: "required", message: t(k === "connector" ? "targetForm.connectorNeeded" : "routeForm.number") }])) };
    }
    return checks(v, ctx, opts);
  };
  const form = useForm<TargetValues>({ defaultValues: targetValues(base), resolver });
  const [other, setOther] = useState<string[]>([]);
  const address = useWatch({ control: form.control, name: "address" });
  const https = Number(useWatch({ control: form.control, name: "upstream" })) === UpstreamProtocol.HTTPS;

  async function save(v: TargetValues) {
    setOther([]);
    try {
      const req = request(v);
      const res = req.$typeName === "rpmgr.v1.UpdateRouteTargetRequest" ? await update.mutateAsync(req) : await add.mutateAsync(req);
      onDone({ revision: res.revision, status: res.applyStatus });
    } catch (err) {
      const e = ConnectError.from(err);
      if (e.code === Code.InvalidArgument) {
        const { fields: badFields, other } = serverFieldErrors(err, schema, targetFieldOf);
        badFields.forEach(([f, message]) => form.setError(f, { type: "server", message }));
        setOther(other.length > 0 || badFields.length > 0 ? other : [e.rawMessage]);
      } else {
        setOther([e.code === Code.FailedPrecondition || e.code === Code.NotFound ? e.rawMessage : t("link.failed", { message: e.rawMessage })]);
      }
    }
  }

  return (
    <form onSubmit={form.handleSubmit(save)} aria-label={t(target ? "targetForm.editTitle" : "targetForm.addTitle")}
      className="grid gap-3 rounded-md border border-border p-3" noValidate>
      <Select form={form} name="connector" label={t("route.columns.connector")} disabled={!!target}
        options={[["", t("targetForm.chooseConnector")], ...connectors]} />
      <Select form={form} name="address" label={t("targetForm.address")} options={[["hostPort", t("targetForm.hostPort")], ["unixPath", t("targetForm.unixPath")]]} />
      {address === "hostPort" ? (
        <div className="grid grid-cols-[1fr_8rem] gap-2">
          <Text form={form} name="host" label={t("targetForm.host")} />
          <Text form={form} name="port" label={t("targetForm.port")} />
        </div>
      ) : (
        <Text form={form} name="unixPath" label={t("targetForm.unixPathLabel")} />
      )}
      <Select form={form} name="upstream" label={t("targetForm.upstream")} options={upstreams.map((u) => [String(u), t(`targetForm.upstreams.${UpstreamProtocol[u]}`)])} />
      {https && (
        <>
          <Text form={form} name="serverName" label={t("targetForm.serverName")} />
          <Text form={form} name="caBundle" label={t("targetForm.caBundle")} />
          <Text form={form} name="spki" label={t("targetForm.spki")} />
        </>
      )}
      {proxies.length > 0 && (
        <Select form={form} name="proxy" label={t("targetForm.proxy")} options={proxies.map((p) => [String(p), t(`targetForm.proxies.${ProxyProtocol[p]}`)])} />
      )}
      <div className="grid grid-cols-2 gap-2">
        <Text form={form} name="weight" label={t("route.columns.weight")} />
        <Text form={form} name="priority" label={t("targetForm.priority")} />
      </div>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" {...form.register("enabled")} />{t("targetForm.enabled")}</label>
      {other.map((m) => <Alert key={m}>{m}</Alert>)}
      <div className="flex gap-2">
        <Button type="submit" disabled={add.isPending || update.isPending}>{t(target ? "routeForm.save" : "targetForm.add")}</Button>
        <Button variant="outline" onClick={onCancel}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}

function Text({ form, name, label }: { form: UseFormReturn<TargetValues>; name: Path<TargetValues>; label: string }) {
  const id = useId();
  const error = form.formState.errors[name as keyof TargetValues]?.message;
  return (
    <div className="grid gap-1">
      <label htmlFor={id} className="text-sm font-medium">{label}</label>
      <Input id={id} aria-invalid={error ? true : undefined} aria-describedby={`${id}-error`} {...form.register(name)} />
      {error && <p id={`${id}-error`} role="alert" className="text-sm text-destructive">{error}</p>}
    </div>
  );
}

function Select({ form, name, label, options, disabled }: { form: UseFormReturn<TargetValues>; name: Path<TargetValues>; label: string; options: [string, string][]; disabled?: boolean }) {
  const id = useId();
  const error = form.formState.errors[name as keyof TargetValues]?.message;
  return (
    <div className="grid gap-1">
      <label htmlFor={id} className="text-sm font-medium">{label}</label>
      <select id={id} disabled={disabled} aria-invalid={error ? true : undefined} className="h-9 rounded-md border border-border bg-background px-2 text-sm" {...form.register(name)}>
        {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    </div>
  );
}
