// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { Code, ConnectError, createClient } from "@connectrpc/connect";
import { useMutation, useQuery, useTransport } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { useState } from "react";
import { useForm, type Resolver } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { ApplyStatusView, useLiveApplyStatus } from "@/components/apply-status";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import type { Revision } from "@/gen/rpmgr/v1/common_pb";
import { RouteService, UpdateRouteRequestSchema, type PreviewRouteResponse, type Route } from "@/gen/rpmgr/v1/route_pb";
import type { ApplyStatus } from "@/gen/rpmgr/v1/status_pb";
import { reasonOf } from "@/lib/errors";
import { protoResolver, serverFieldErrors, type FieldOf } from "@/lib/proto-form";
import { Conflict, onTop } from "@/route-form/conflict";
import { numberProblems, routeFields, routeWith, valuesOf, type RouteValues } from "@/route-form/fields";
import { FormField } from "@/route-form/form-field";
import { PreviewPanel } from "@/route-form/preview";
import { routeType, useAgentNames } from "@/routes-data";
import { useOrg } from "@/session";

const page = getRouteApi("/app/routes/$routeId/edit");

// RouteEdit edits a route: the form starts from the route as read and sends it whole, with the
// fields it shows changed, its update mask and the etag it read (docs/09-web-ui.md, U1, U6).
export function RouteEdit() {
  const { t } = useTranslation();
  const { routeId } = page.useParams();
  const got = useQuery(RouteService.method.getRoute, { routeId });
  const [restart, setRestart] = useState<{ base: Route; values?: RouteValues; n: number }>();
  const start = restart ?? (got.data?.route && { base: got.data.route, values: undefined, n: 0 });
  if (!start) {
    return <p>{got.isError ? t("route.notFound") : t("stepUp.loading")}</p>;
  }
  return (
    <RouteForm key={start.n} base={start.base} initial={start.values}
      onRestart={(base, values) => setRestart({ base, values, n: start.n + 1 })} />
  );
}

// updateRequest is the UpdateRoute request of the form's values.
export function updateRequest(base: Route, values: RouteValues) {
  return create(UpdateRouteRequestSchema, {
    route: routeWith(base, values),
    updateMask: { paths: routeFields(base).map((f) => f.path) },
    etag: base.etag,
  });
}

function RouteForm({ base, initial, onRestart }: { base: Route; initial?: RouteValues; onRestart: (base: Route, values?: RouteValues) => void }) {
  const { t } = useTranslation();
  const org = useOrg();
  const names = useAgentNames(org?.orgId);
  const queryClient = useQueryClient();
  const update = useMutation(RouteService.method.updateRoute);
  const preview = useMutation(RouteService.method.previewRoute);
  const [previewed, setPreviewed] = useState<PreviewRouteResponse>();
  const fields = routeFields(base);
  const fieldOf: FieldOf<RouteValues> = (path) => {
    const p = path.replace(/^route\./, "");
    return fields.find((f) => p === f.path || p.startsWith(`${f.path}[`) || p.startsWith(`${f.path}.`))?.key;
  };
  const checks = protoResolver(UpdateRouteRequestSchema, (v: RouteValues) => updateRequest(base, v), fieldOf);
  const resolver: Resolver<RouteValues> = (values, ctx, opts) => {
    const bad = numberProblems(base, values);
    if (bad.length > 0) {
      return { values: {}, errors: Object.fromEntries(bad.map((k) => [k, { type: "number", message: t("routeForm.number") }])) };
    }
    return checks(values, ctx, opts);
  };
  const form = useForm<RouteValues>({ defaultValues: initial ?? valuesOf(base), resolver });
  const transport = useTransport();
  const [conflict, setConflict] = useState<{ theirs: Route; mine: RouteValues }>();
  const [write, setWrite] = useState<{ revision?: Revision; status?: ApplyStatus }>();
  const [other, setOther] = useState<string[]>([]);
  const live = useLiveApplyStatus(org?.orgId ?? "", write?.revision, write?.status);

  // check previews the change as the save would make it, without saving.
  async function check(values: RouteValues) {
    setOther([]);
    try {
      const req = updateRequest(base, values);
      setPreviewed(await preview.mutateAsync({ orgId: org?.orgId ?? "", route: req.route, updateMask: req.updateMask, etag: req.etag }));
    } catch (err) {
      setPreviewed(undefined);
      setOther([ConnectError.from(err).rawMessage]);
    }
  }

  async function save(values: RouteValues) {
    setOther([]);
    try {
      const res = await update.mutateAsync(updateRequest(base, values));
      setWrite({ revision: res.revision, status: res.applyStatus });
      await queryClient.invalidateQueries();
    } catch (err) {
      const e = ConnectError.from(err);
      if (e.code === Code.InvalidArgument) {
        const { fields: bad, other } = serverFieldErrors(err, UpdateRouteRequestSchema, fieldOf);
        bad.forEach(([f, message]) => form.setError(f, { type: "server", message }));
        setOther(other.length > 0 || bad.length > 0 ? other : [e.rawMessage]);
      } else if (e.code === Code.FailedPrecondition && reasonOf(err) === "ETAG_MISMATCH") {
        const now = await createClient(RouteService, transport).getRoute({ routeId: base.id });
        if (now.route) {
          setConflict({ theirs: now.route, mine: values });
        }
      } else {
        setOther([t("link.failed", { message: e.rawMessage })]);
      }
    }
  }

  return (
    <div className="grid max-w-2xl gap-6">
      <h1 className="text-2xl font-semibold">{t("routeForm.title", { name: base.name, type: t(`routeType.${routeType(base) || "unknown"}`) })}</h1>
      {live ? (
        <>
          <ApplyStatusView status={live} revision={write?.revision} name={(id) => names.data?.get(id) || id} />
          <Link to="/routes/$routeId" params={{ routeId: base.id }} className="underline">{t("routeForm.back")}</Link>
        </>
      ) : (
        <form onSubmit={form.handleSubmit(save)} className="grid gap-4" noValidate>
          {conflict && (
            <Conflict base={base} mine={conflict.mine} theirs={conflict.theirs}
              onTop={() => onRestart(conflict.theirs, onTop(base, conflict.mine, conflict.theirs))} onDiscard={() => onRestart(conflict.theirs)} />
          )}
          {fields.map((f) => <FormField key={f.key} field={f} form={form} />)}
          {other.map((m) => <Alert key={m}>{m}</Alert>)}
          {previewed && <PreviewPanel preview={previewed} name={(id) => names.data?.get(id) || id} />}
          <div className="flex gap-2">
            <Button type="submit" disabled={update.isPending}>{t("routeForm.save")}</Button>
            <Button variant="outline" disabled={preview.isPending} onClick={() => void form.handleSubmit(check)()}>{t("preview.button")}</Button>
            <Button asChild variant="outline"><Link to="/routes/$routeId" params={{ routeId: base.id }}>{t("stepUp.cancel")}</Link></Button>
          </div>
        </form>
      )}
    </div>
  );
}
