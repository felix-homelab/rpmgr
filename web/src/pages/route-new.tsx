// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { useForm, type Resolver } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { ApplyStatusView, useLiveApplyStatus } from "@/components/apply-status";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import type { Revision } from "@/gen/rpmgr/v1/common_pb";
import {
  CreateRouteRequestSchema, Port80Mode, RouteSchema, RouteService, TLSMode, type PreviewRouteResponse, type Route,
} from "@/gen/rpmgr/v1/route_pb";
import type { ApplyStatus } from "@/gen/rpmgr/v1/status_pb";
import { protoResolver, serverFieldErrors, type FieldOf } from "@/lib/proto-form";
import { numberProblems, routeFields, routeWith, valuesOf, type RouteValues } from "@/route-form/fields";
import { FormField } from "@/route-form/form-field";
import { PreviewPanel } from "@/route-form/preview";
import { routeTypes, useAgentNames, useGroupNames } from "@/routes-data";
import { useOrg } from "@/session";

type RouteType = (typeof routeTypes)[number];

// template is a new route of a type, with the defaults the form starts from: ACME certificates and a
// redirect on port 80 for HTTP; port 0, a free port of the pools, for TCP and UDP.
function template(type: RouteType): Route {
  const specs = {
    http: { case: "http" as const, value: { tlsMode: TLSMode.TLS_MODE_ACME, port80: Port80Mode.REDIRECT } },
    tcp: { case: "tcp" as const, value: {} },
    udp: { case: "udp" as const, value: {} },
    tlsPassthrough: { case: "tlsPassthrough" as const, value: {} },
  };
  return create(RouteSchema, { enabled: true, spec: specs[type] });
}

// RouteNew creates a route of a chosen type in a gateway group, previews it, and follows it to the
// agents (docs/09-web-ui.md, "Routes"); its targets are added on its page.
export function RouteNew() {
  const { t } = useTranslation();
  const [type, setType] = useState<RouteType>("http");
  return (
    <div className="grid max-w-2xl gap-6">
      <h1 className="text-2xl font-semibold">{t("routeNew.title")}</h1>
      <fieldset className="grid gap-1.5">
        <legend className="text-sm font-medium">{t("routes.type")}</legend>
        <div className="flex flex-wrap gap-4 text-sm">
          {routeTypes.map((rt) => (
            <label key={rt} className="flex items-center gap-1.5">
              <input type="radio" name="type" checked={type === rt} onChange={() => setType(rt)} />
              {t(`routeType.${rt}`)}
            </label>
          ))}
        </div>
      </fieldset>
      <NewRouteForm key={type} type={type} />
    </div>
  );
}

type NewValues = RouteValues & { group: string };

function NewRouteForm({ type }: { type: RouteType }) {
  const { t } = useTranslation();
  const org = useOrg();
  const groups = useGroupNames(org?.orgId);
  const names = useAgentNames(org?.orgId);
  const queryClient = useQueryClient();
  const createRoute = useMutation(RouteService.method.createRoute);
  const preview = useMutation(RouteService.method.previewRoute);
  const [requestId] = useState(() => crypto.randomUUID()); // one creation, however often it is retried
  const base = template(type);
  const fields = routeFields(base);
  const routeOf = (v: NewValues) => create(RouteSchema, { ...routeWith(base, v), gatewayGroupId: v.group });
  const request = (v: NewValues) => create(CreateRouteRequestSchema, { orgId: org?.orgId ?? "", route: routeOf(v), requestId });
  const fieldOf: FieldOf<NewValues> = (path) => {
    const p = path.replace(/^route\./, "");
    return p === "gateway_group_id" ? "group" : fields.find((f) => p === f.path || p.startsWith(`${f.path}[`) || p.startsWith(`${f.path}.`))?.key;
  };
  const checks = protoResolver(CreateRouteRequestSchema, request, fieldOf);
  const resolver: Resolver<NewValues> = (values, ctx, opts) => {
    const bad = numberProblems(base, values);
    if (bad.length > 0) {
      return { values: {}, errors: Object.fromEntries(bad.map((k) => [k, { type: "number", message: t("routeForm.number") }])) };
    }
    if (!values.group) {
      return { values: {}, errors: { group: { type: "required", message: t("routeNew.groupNeeded") } } };
    }
    return checks(values, ctx, opts);
  };
  const form = useForm<NewValues>({ defaultValues: { ...valuesOf(base), group: "" }, resolver });
  const [created, setCreated] = useState<{ route?: Route; revision?: Revision; status?: ApplyStatus }>();
  const [previewed, setPreviewed] = useState<PreviewRouteResponse>();
  const [other, setOther] = useState<string[]>([]);
  const live = useLiveApplyStatus(org?.orgId ?? "", created?.revision, created?.status);
  const name = (id: string) => names.data?.get(id) || id;

  function failed(err: unknown) {
    const e = ConnectError.from(err);
    if (e.code === Code.InvalidArgument) {
      const { fields: bad, other } = serverFieldErrors(err, CreateRouteRequestSchema, fieldOf);
      bad.forEach(([f, message]) => form.setError(f, { type: "server", message }));
      setOther(other.length > 0 || bad.length > 0 ? other : [e.rawMessage]);
    } else {
      setOther([e.code === Code.FailedPrecondition || e.code === Code.ResourceExhausted ? e.rawMessage : t("link.failed", { message: e.rawMessage })]);
    }
  }
  async function save(values: NewValues) {
    setOther([]);
    try {
      const res = await createRoute.mutateAsync(request(values));
      setCreated({ route: res.route, revision: res.revision, status: res.applyStatus });
      await queryClient.invalidateQueries();
    } catch (err) {
      failed(err);
    }
  }
  async function check(values: NewValues) {
    setOther([]);
    try {
      setPreviewed(await preview.mutateAsync({ orgId: org?.orgId ?? "", route: routeOf(values) }));
    } catch (err) {
      setPreviewed(undefined);
      failed(err);
    }
  }

  if (created?.route) {
    return (
      <div className="grid gap-3">
        {live && <ApplyStatusView status={live} revision={created.revision} name={name} />}
        <Link to="/routes/$routeId" params={{ routeId: created.route.id }} className="underline">{t("routeNew.open", { name: created.route.name })}</Link>
      </div>
    );
  }
  const groupError = form.formState.errors.group?.message;
  return (
    <form onSubmit={form.handleSubmit(save)} className="grid gap-4" noValidate>
      <div className="grid gap-1.5">
        <label htmlFor="route-group" className="text-sm font-medium">{t("routes.group")}</label>
        <select id="route-group" className="h-9 rounded-md border border-border bg-background px-2 text-sm" aria-invalid={groupError ? true : undefined}
          {...form.register("group")}>
          <option value="">{t("routeNew.chooseGroup")}</option>
          {[...(groups.data ?? new Map<string, string>())].map(([id, n]) => <option key={id} value={id}>{n}</option>)}
        </select>
        {groupError && <p role="alert" className="text-sm text-destructive">{groupError}</p>}
      </div>
      {fields.map((f) => <FormField key={f.key} field={f} form={form} />)}
      {other.map((m) => <Alert key={m}>{m}</Alert>)}
      {previewed && <PreviewPanel preview={previewed} name={name} />}
      <div className="flex gap-2">
        <Button type="submit" disabled={createRoute.isPending}>{t("routeNew.create")}</Button>
        <Button variant="outline" disabled={preview.isPending} onClick={() => void form.handleSubmit(check)()}>{t("preview.button")}</Button>
        <Button asChild variant="outline"><Link to="/routes" search={{}}>{t("stepUp.cancel")}</Link></Button>
      </div>
    </form>
  );
}
