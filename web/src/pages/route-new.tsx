// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ChevronLeft } from "lucide-react";
import { useEffect, useState } from "react";
import { useForm, type Resolver } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { ApplyStatusView, useLiveApplyStatus } from "@/components/apply-status";
import { labelClass } from "@/components/field";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import type { Revision } from "@/gen/rpmgr/v1/common_pb";
import {
  CreateRouteRequestSchema, Port80Mode, RouteSchema, RouteService, TLSMode, type PreviewRouteResponse, type Route,
} from "@/gen/rpmgr/v1/route_pb";
import { SettingsService } from "@/gen/rpmgr/v1/settings_pb";
import type { ApplyStatus } from "@/gen/rpmgr/v1/status_pb";
import { protoResolver, serverFieldErrors, type FieldOf } from "@/lib/proto-form";
import { fieldAt, fieldProblems, routeFields, routeWith, valuesOf, type RouteValues } from "@/route-form/fields";
import { FieldGrid, FormField } from "@/route-form/form-field";
import { PreviewPanel } from "@/route-form/preview";
import { routeTypes, useAgentNames, useGroupNames } from "@/routes-data";
import { useOrg } from "@/session";

type RouteType = (typeof routeTypes)[number];

// template is a new route of a type, with the defaults the form starts from: ACME certificates and a
// redirect on port 80 for HTTP; port 0, a free port of the pools, for routes on a port.
function template(type: RouteType): Route {
  const specs = {
    http: { case: "http" as const, value: { tlsMode: TLSMode.TLS_MODE_ACME, port80: Port80Mode.REDIRECT } },
    tcp: { case: "tcp" as const, value: {} },
    udp: { case: "udp" as const, value: {} },
    tcpUdp: { case: "tcpUdp" as const, value: {} },
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
    <div className="grid gap-6">
      <div className="grid gap-2">
        <Link to="/routes" search={{}} className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
          <ChevronLeft aria-hidden="true" className="size-4" />{t("route.back")}
        </Link>
        <PageHeader title={t("routeNew.title")} />
      </div>
      <Card>
        <fieldset className="grid gap-2">
          <legend className="mb-2 text-sm font-medium">{t("routes.type")}</legend>
          <div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-5">
            {routeTypes.map((rt) => (
              <label key={rt} className="flex cursor-pointer items-center gap-2 rounded-lg border border-border px-3 py-2.5 text-sm font-medium transition-colors hover:bg-muted has-checked:border-ring has-checked:bg-accent has-checked:text-accent-foreground has-focus-visible:outline-2 has-focus-visible:outline-ring">
                <input type="radio" name="type" className="accent-primary" checked={type === rt} onChange={() => setType(rt)} />
                {t(`routeType.${rt}`)}
              </label>
            ))}
          </div>
        </fieldset>
        <NewRouteForm key={type} type={type} />
      </Card>
    </div>
  );
}

type NewValues = RouteValues & { group: string };

function NewRouteForm({ type }: { type: RouteType }) {
  const { t } = useTranslation();
  const org = useOrg();
  const groups = useGroupNames(org?.orgId);
  const names = useAgentNames(org?.orgId);
  const settings = useQuery(SettingsService.method.getOrgSettings, { orgId: org?.orgId ?? "" }, { enabled: !!org });
  const queryClient = useQueryClient();
  const createRoute = useMutation(RouteService.method.createRoute);
  const preview = useMutation(RouteService.method.previewRoute);
  const [requestId] = useState(() => crypto.randomUUID()); // one creation, however often it is retried
  const base = template(type);
  const fields = routeFields(base);
  const routeOf = (v: NewValues) => create(RouteSchema, { ...routeWith(base, v), gatewayGroupId: v.group });
  const request = (v: NewValues) => create(CreateRouteRequestSchema, { orgId: org?.orgId ?? "", route: routeOf(v), requestId });
  const fieldOf: FieldOf<NewValues> = (path) => (path.replace(/^route\./, "") === "gateway_group_id" ? "group" : fieldAt(base, path));
  const checks = protoResolver(CreateRouteRequestSchema, request, fieldOf);
  const resolver: Resolver<NewValues> = (values, ctx, opts) => {
    const bad = Object.entries(fieldProblems(base, values));
    if (bad.length > 0) {
      return { values: {}, errors: Object.fromEntries(bad.map(([k, p]) => [k, { type: "format", message: t(`routeForm.${p.text}`, p.values) }])) };
    }
    if (!values.group) {
      return { values: {}, errors: { group: { type: "required", message: t("routeNew.groupNeeded") } } };
    }
    return checks(values, ctx, opts);
  };
  const form = useForm<NewValues>({ defaultValues: { ...valuesOf(base), group: "" }, resolver });
  // The org's default gateway group is preselected once it and the groups are read, unless a group
  // was chosen first; a default that names no group of the org is ignored. It is preselected once,
  // so the form never takes back a choice.
  const preset = settings.data?.settings?.defaultGatewayGroupId ?? "";
  const listed = !!preset && !!groups.data?.has(preset);
  useEffect(() => {
    if (listed && !form.getValues("group")) {
      form.resetField("group", { defaultValue: preset });
    }
  }, [listed, preset, form]);
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
        <Button asChild className="justify-self-start">
          <Link to="/routes/$routeId" params={{ routeId: created.route.id }}>{t("routeNew.open", { name: created.route.name })}</Link>
        </Button>
      </div>
    );
  }
  const groupError = form.formState.errors.group?.message;
  return (
    <form onSubmit={form.handleSubmit(save)} className="grid gap-4" noValidate>
      <FieldGrid>
        <div className="grid gap-1.5">
          <label htmlFor="route-group" className={labelClass(true)}>{t("routes.group")}</label>
          <Select id="route-group" required aria-invalid={groupError ? true : undefined} {...form.register("group")}>
            <option value="">{t("routeNew.chooseGroup")}</option>
            {[...(groups.data ?? new Map<string, string>())].map(([id, n]) => <option key={id} value={id}>{n}</option>)}
          </Select>
          {groupError && <p role="alert" className="text-sm text-destructive">{groupError}</p>}
        </div>
        {fields.map((f) => <FormField key={f.key} field={f} form={form} />)}
      </FieldGrid>
      {other.map((m) => <Alert key={m}>{m}</Alert>)}
      {previewed && <PreviewPanel preview={previewed} name={name} />}
      <div className="flex flex-wrap gap-2 border-t border-border pt-4">
        <Button type="submit" disabled={createRoute.isPending}>{t("routeNew.create")}</Button>
        <Button variant="outline" disabled={preview.isPending} onClick={() => void form.handleSubmit(check)()}>{t("preview.button")}</Button>
        <Button asChild variant="outline"><Link to="/routes" search={{}}>{t("stepUp.cancel")}</Link></Button>
      </div>
    </form>
  );
}
