// SPDX-License-Identifier: Apache-2.0

import { clone, create, type DescMessage } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { TriangleAlert } from "lucide-react";
import { useId, useState } from "react";
import { useController, useForm, useWatch, type Path, type Resolver, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { labelClass } from "@/components/field";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Input, Select as SelectBox } from "@/components/ui/input";
import type { Revision } from "@/gen/rpmgr/v1/common_pb";
import {
  CreateRouteTargetRequestSchema, ProxyProtocol, RouteService, RouteTargetSchema, UpdateRouteTargetRequestSchema, UpstreamProtocol,
  UpstreamVerification, type Route, type RouteTarget, type TargetCertificate,
} from "@/gen/rpmgr/v1/route_pb";
import type { ApplyStatus } from "@/gen/rpmgr/v1/status_pb";
import { when } from "@/lib/format";
import { protoResolver, serverFieldErrors, type FieldOf } from "@/lib/proto-form";
import { useCABundles } from "@/pages/certificates";
import { useOrg } from "@/session";

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

// UNVERIFIED is the choice "HTTPS, unverified" of "Protocol to the target": HTTPS whose certificate
// the gateway does not check (D82).
export const UNVERIFIED = "https-unverified";
// PINNED is the choice "HTTPS, pinned key": HTTPS whose key alone the gateway checks (D82).
export const PINNED = "https-pinned";

// upstreamChoice is a target's choice of "Protocol to the target".
export function upstreamChoice(t: RouteTarget): string {
  if (t.upstreamProtocol === UpstreamProtocol.HTTPS && t.tls?.verification === UpstreamVerification.UNVERIFIED) {
    return UNVERIFIED;
  }
  return t.upstreamProtocol === UpstreamProtocol.HTTPS && t.tls?.verification === UpstreamVerification.PINNED_KEY ? PINNED : String(t.upstreamProtocol);
}

export function targetValues(t: RouteTarget): TargetValues {
  return {
    connector: t.connectorId,
    address: t.address.case === "unixPath" ? "unixPath" : "hostPort",
    host: t.address.case === "hostPort" ? t.address.value.host : "",
    port: t.address.case === "hostPort" ? String(t.address.value.port) : "",
    unixPath: t.address.case === "unixPath" ? t.address.value : "",
    upstream: upstreamChoice(t),
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
  const unverified = v.upstream === UNVERIFIED, pinned = v.upstream === PINNED;
  t.upstreamProtocol = unverified || pinned ? UpstreamProtocol.HTTPS : Number(v.upstream);
  t.tls = unverified || pinned
    ? { $typeName: "rpmgr.v1.UpstreamTLSSettings", serverName: v.serverName.trim(), caBundleId: "", spkiSha256: pinned ? v.spki.trim().toLowerCase() : "",
      verification: pinned ? UpstreamVerification.PINNED_KEY : UpstreamVerification.UNVERIFIED }
    : t.upstreamProtocol === UpstreamProtocol.HTTPS
      ? { $typeName: "rpmgr.v1.UpstreamTLSSettings", serverName: v.serverName.trim(), caBundleId: v.caBundle.trim(), spkiSha256: v.spki.trim().toLowerCase(), verification: UpstreamVerification.VERIFIED }
      : undefined;
  t.proxyProtocol = Number(v.proxy);
  t.weight = whole(v.weight);
  t.priority = whole(v.priority);
  t.enabled = v.enabled;
  return t;
}

// The upstream protocols, as choices of "Protocol to the target", and PROXY versions a route's type
// allows. Only http routes choose a protocol; the others have one, the bytes as they come
// (datagrams for udp routes), which the form sends without showing it. A tcp_udp route's PROXY
// header goes on its TCP connections only (D86).
function choices(r: Route) {
  const http = r.spec.case === "http";
  const proxied = r.spec.case === "tcp" || r.spec.case === "tcpUdp" || r.spec.case === "tlsPassthrough";
  return {
    upstreams: http ? [String(UpstreamProtocol.HTTP), String(UpstreamProtocol.HTTPS), PINNED, UNVERIFIED, String(UpstreamProtocol.H2C)] : [String(UpstreamProtocol.TCP)],
    proxies: proxied ? [ProxyProtocol.NONE, ProxyProtocol.V1, ProxyProtocol.V2] : [],
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
  const base = target ?? create(RouteTargetSchema, { enabled: true, weight: 100, upstreamProtocol: Number(upstreams[0]), proxyProtocol: proxies[0] ?? ProxyProtocol.UNSPECIFIED });
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
  const upstream = useWatch({ control: form.control, name: "upstream" });
  const unverified = upstream === UNVERIFIED, pinned = upstream === PINNED;
  const https = unverified || pinned || Number(upstream) === UpstreamProtocol.HTTPS;
  const warning = useId();

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
      className="grid gap-4 rounded-lg border border-border bg-muted/40 p-4" noValidate>
      <Select form={form} name="connector" label={t("route.columns.connector")} disabled={!!target} required={!target}
        options={[["", t("targetForm.chooseConnector")], ...connectors]} />
      <Select form={form} name="address" label={t("targetForm.address")} options={[["hostPort", t("targetForm.hostPort")], ["unixPath", t("targetForm.unixPath")]]} />
      {address === "hostPort" ? (
        <div className="grid grid-cols-[1fr_8rem] gap-2">
          <Text form={form} name="host" label={t("targetForm.host")} required />
          <Text form={form} name="port" label={t("targetForm.port")} required />
        </div>
      ) : (
        <Text form={form} name="unixPath" label={t("targetForm.unixPathLabel")} required />
      )}
      {upstreams.length > 1 && (
        <Select form={form} name="upstream" label={t("targetForm.upstream")} describedBy={unverified ? warning : undefined}
          options={upstreams.map((u) => [u, t(u === UNVERIFIED ? "targetForm.upstreams.UNVERIFIED" : u === PINNED ? "targetForm.upstreams.PINNED"
            : `targetForm.upstreams.${UpstreamProtocol[Number(u)]}`)])} />
      )}
      {unverified && (
        <p id={warning} className="flex items-start gap-2 rounded-lg border border-warn/30 bg-warn/10 px-3 py-2 text-sm">
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-warn" />
          <span>{t("targetForm.unverifiedWarning")}</span>
        </p>
      )}
      {https && (
        <>
          {/* A socket has no host to name, so an HTTPS target on one needs a server name. */}
          <Text form={form} name="serverName" label={t("targetForm.serverName")} required={address === "unixPath"}
            hint={address === "hostPort" ? t(unverified || pinned ? "targetForm.serverNameSentHint" : "targetForm.serverNameHint") : undefined} />
          {pinned ? (
            <>
              <Text form={form} name="spki" label={t("targetForm.pinnedKey")} required />
              <TrustCertificate form={form} connector={target?.connectorId ?? ""} />
            </>
          ) : !unverified && (
            <>
              <BundleSelect form={form} />
              <Text form={form} name="spki" label={t("targetForm.spki")} />
            </>
          )}
        </>
      )}
      {proxies.length > 0 && (
        <Select form={form} name="proxy" label={t("targetForm.proxy")} options={proxies.map((p) => [String(p), t(`targetForm.proxies.${ProxyProtocol[p]}`)])}
          hint={route.spec.case === "tcpUdp" ? t("targetForm.proxyTCPOnly") : undefined} />
      )}
      <div className="grid grid-cols-2 gap-2">
        <Text form={form} name="weight" label={t("route.columns.weight")} required />
        <Text form={form} name="priority" label={t("targetForm.priority")} hint={t("targetForm.priorityHint")} required />
      </div>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" className="size-4 accent-primary" {...form.register("enabled")} />{t("targetForm.enabled")}</label>
      {other.map((m) => <Alert key={m}>{m}</Alert>)}
      <div className="flex gap-2">
        <Button type="submit" disabled={add.isPending || update.isPending}>{t(target ? "routeForm.save" : "targetForm.add")}</Button>
        <Button variant="outline" onClick={onCancel}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}

// TrustCertificate reads the certificate the target in the form presents, through its connector,
// shows it, and pins its key once the user trusts it (D82); the target need not be saved yet. A
// certificate shows only while the form still names the target it was read from, so that another
// target's key is never pinned.
function TrustCertificate({ form, connector }: { form: UseFormReturn<TargetValues>; connector: string }) {
  const { t } = useTranslation();
  const probe = useMutation(RouteService.method.probeTargetCertificate);
  const [shown, setShown] = useState<{ cert: TargetCertificate; of: string }>();
  const [error, setError] = useState<string>();
  const watched = useWatch({ control: form.control, name: ["connector", "address", "host", "port", "unixPath", "serverName"] });
  const of = [connector, ...watched.map((w) => String(w ?? "").trim())].join("\n");
  const cert = shown?.of === of ? shown.cert : undefined;
  const setCert = (c?: TargetCertificate) => setShown(c && { cert: c, of });
  async function read() {
    const v = form.getValues();
    setError(undefined);
    setCert(undefined);
    const hostPort = v.address === "hostPort";
    if (!(connector || v.connector) || (hostPort ? !v.host.trim() || Number.isNaN(whole(v.port)) : !v.unixPath.trim())) {
      setError(t("targetForm.trustNeeds"));
      return;
    }
    try {
      const res = await probe.mutateAsync({
        connectorId: connector || v.connector, serverName: v.serverName.trim(),
        address: hostPort ? { case: "hostPort", value: { host: v.host.trim(), port: whole(v.port) } } : { case: "unixPath", value: v.unixPath.trim() },
      });
      setCert(res.certificate);
    } catch (err) {
      setError(t("targetForm.trustFailed", { message: ConnectError.from(err).rawMessage }));
    }
  }
  return (
    <div className="grid gap-2">
      <Button variant="outline" className="justify-self-start" disabled={probe.isPending} onClick={() => void read()}>{t("targetForm.trust")}</Button>
      {error && <Alert>{error}</Alert>}
      {cert && (
        <section aria-label={t("targetForm.trustTitle")} className="grid gap-2 rounded-lg border border-border bg-card p-3 text-sm">
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
            <dt className="text-muted-foreground">{t("targetForm.certSubject")}</dt><dd className="break-all">{cert.subject}</dd>
            <dt className="text-muted-foreground">{t("targetForm.certNames")}</dt><dd className="break-all">{[...cert.dnsNames, ...cert.ipAddresses].join(", ") || "—"}</dd>
            <dt className="text-muted-foreground">{t("targetForm.certIssuer")}</dt>
            <dd className="break-all">{cert.selfSigned ? t("targetForm.certSelfSigned") : cert.issuer}</dd>
            <dt className="text-muted-foreground">{t("targetForm.certValid")}</dt><dd>{when(cert.notAfter)}</dd>
            <dt className="text-muted-foreground">{t("targetForm.certKey")}</dt><dd className="font-mono break-all">{cert.spkiSha256}</dd>
          </dl>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => { form.setValue("spki", cert.spkiSha256, { shouldDirty: true, shouldValidate: true }); setCert(undefined); }}>
              {t("targetForm.trustIt")}
            </Button>
            <Button size="sm" variant="outline" onClick={() => setCert(undefined)}>{t("stepUp.cancel")}</Button>
          </div>
        </section>
      )}
    </div>
  );
}

// BundleSelect chooses the CA bundle that a verified HTTPS target's certificate is checked with,
// among the org's, or none for the system's roots, and keeps the bundle's ID as the form's value. It
// is controlled, so that it shows the form's value while the bundles are read; a bundle the org does
// not list stays offered by its ID, so that the select never changes it unasked.
function BundleSelect({ form }: { form: UseFormReturn<TargetValues> }) {
  const { t } = useTranslation();
  const id = useId();
  const org = useOrg();
  const bundles = useCABundles(org?.orgId);
  const { field: { ref, ...field }, fieldState } = useController({ control: form.control, name: "caBundle" });
  const listed = bundles.data ?? [];
  const chosen = field.value.trim();
  const none = bundles.isSuccess && listed.length === 0;
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className={labelClass(false)}>{t("targetForm.caBundle")}</label>
      <SelectBox id={id} ref={ref} name={field.name} value={chosen} onChange={field.onChange} onBlur={field.onBlur}
        aria-invalid={fieldState.error ? true : undefined} aria-describedby={none ? `${id}-hint` : undefined}>
        <option value="">{t("targetForm.systemRoots")}</option>
        {listed.map((b) => <option key={b.id} value={b.id}>{t("targetForm.bundleOption", { name: b.name, id: b.id })}</option>)}
        {chosen !== "" && !listed.some((b) => b.id === chosen) && <option value={chosen}>{chosen}</option>}
      </SelectBox>
      {none && <p id={`${id}-hint`} className="text-xs text-muted-foreground">{t("targetForm.noBundles")}</p>}
      {fieldState.error && <p role="alert" className="text-sm text-destructive">{fieldState.error.message}</p>}
    </div>
  );
}

// Text and Select are a field of the target form; a required one's label ends in a red asterisk.
function Text({ form, name, label, hint, required }: {
  form: UseFormReturn<TargetValues>; name: Path<TargetValues>; label: string; hint?: string; required?: boolean;
}) {
  const id = useId();
  const error = form.formState.errors[name as keyof TargetValues]?.message;
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className={labelClass(required)}>{label}</label>
      <Input id={id} required={required} aria-invalid={error ? true : undefined} aria-describedby={hint ? `${id}-hint ${id}-error` : `${id}-error`} {...form.register(name)} />
      {hint && <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint}</p>}
      {error && <p id={`${id}-error`} role="alert" className="text-sm text-destructive">{error}</p>}
    </div>
  );
}

function Select({ form, name, label, options, disabled, required, describedBy, hint }: {
  form: UseFormReturn<TargetValues>; name: Path<TargetValues>; label: string; options: [string, string][]; disabled?: boolean; required?: boolean;
  describedBy?: string; hint?: string;
}) {
  const id = useId();
  const error = form.formState.errors[name as keyof TargetValues]?.message;
  const described = [describedBy, hint && `${id}-hint`].filter(Boolean).join(" ") || undefined;
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className={labelClass(required)}>{label}</label>
      <SelectBox id={id} disabled={disabled} required={required} aria-invalid={error ? true : undefined} aria-describedby={described} {...form.register(name)}>
        {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </SelectBox>
      {hint && <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint}</p>}
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    </div>
  );
}
