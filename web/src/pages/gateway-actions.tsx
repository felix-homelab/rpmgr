// SPDX-License-Identifier: Apache-2.0

import { clone, create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { LinesField, trimmed } from "@/components/lines-field";
import { Command, OneTimeToken } from "@/components/one-time-token";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import type { Revision } from "@/gen/rpmgr/v1/common_pb";
import { AgentRole, EnrollmentService } from "@/gen/rpmgr/v1/enrollment_pb";
import { GatewaySchema, GatewayService, type Gateway } from "@/gen/rpmgr/v1/gateway_pb";
import type { ApplyStatus } from "@/gen/rpmgr/v1/status_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { useStepUp } from "@/step-up";

export type Written = { revision?: Revision; status?: ApplyStatus };

// The fields of a gateway the API changes (internal/apisvc gatewayFields).
const gatewayMask = ["name", "tunnel_endpoints", "enabled"];

function message(err: unknown, fallback: (m: string) => string): string {
  const e = ConnectError.from(err);
  return e.code === Code.InvalidArgument || e.code === Code.FailedPrecondition || e.code === Code.AlreadyExists ? e.rawMessage : fallback(e.rawMessage);
}

// GatewayForm adds a gateway to a group, or with gateway changes its name and tunnel endpoints: the
// gateway as read with those fields, its mask and etag (U1). A group has at most four gateways.
export function GatewayForm({ orgId, groupId, gateway, onDone, onCancel }: {
  orgId: string; groupId: string; gateway?: Gateway; onDone: (w: Written) => void; onCancel: () => void;
}) {
  const { t } = useTranslation();
  const add = useMutation(GatewayService.method.createGateway);
  const update = useMutation(GatewayService.method.updateGateway);
  const [requestId] = useState(() => crypto.randomUUID());
  const [name, setName] = useState(gateway?.name ?? "");
  const [endpoints, setEndpoints] = useState(gateway?.tunnelEndpoints ?? []);
  const [error, setError] = useState("");
  async function save(e: FormEvent) {
    e.preventDefault();
    setError("");
    const next = gateway ? clone(GatewaySchema, gateway) : create(GatewaySchema, { gatewayGroupId: groupId, enabled: true });
    next.name = name.trim();
    next.tunnelEndpoints = trimmed(endpoints);
    try {
      if (gateway) {
        const res = await update.mutateAsync({ gateway: next, updateMask: { paths: gatewayMask }, etag: gateway.etag });
        onDone({ revision: res.revision, status: res.applyStatus });
      } else {
        const res = await add.mutateAsync({ orgId, gateway: next, requestId });
        onDone({ revision: res.revision, status: res.applyStatus });
      }
    } catch (err) {
      setError(message(err, (m) => t("link.failed", { message: m })));
    }
  }
  return (
    <form onSubmit={save} aria-label={t(gateway ? "gwActions.editTitle" : "gwActions.addTitle")} className="grid max-w-xl gap-3 rounded-md border border-border p-3" noValidate>
      <Field label={t("routeForm.fields.name")} value={name} onChange={(e) => setName(e.target.value)} />
      <LinesField label={t("gateways.gw.endpoints")} hint={t("gwActions.endpointsHint")} value={endpoints} onChange={setEndpoints} />
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={add.isPending || update.isPending}>{t(gateway ? "routeForm.save" : "gwActions.add")}</Button>
        <Button variant="outline" onClick={onCancel}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}

// GatewayActions are a gateway's actions: edit, drain or resume (R22), decommission after a
// confirmation that names it (U7), and for one that has not enrolled its enrollment token.
export function GatewayActions({ orgId, gateway: g, onEdit, onDone }: { orgId: string; gateway: Gateway; onEdit: () => void; onDone: (w: Written) => void }) {
  const { t } = useTranslation();
  const update = useMutation(GatewayService.method.updateGateway);
  const decommission = useMutation(GatewayService.method.decommissionGateway);
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  const [enrolling, setEnrolling] = useState(false);
  const queryClient = useQueryClient();
  async function drain(enabled: boolean) {
    setError("");
    try {
      const res = await update.mutateAsync({ gateway: { ...clone(GatewaySchema, g), enabled }, updateMask: { paths: ["enabled"] }, etag: g.etag });
      onDone({ revision: res.revision, status: res.applyStatus });
    } catch (err) {
      setError(message(err, (m) => t("link.failed", { message: m })));
    }
  }
  async function retire() {
    try {
      const res = await decommission.mutateAsync({ gatewayId: g.id, etag: g.etag });
      onDone({ revision: res.revision, status: res.applyStatus });
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(message(err, (m) => t("link.failed", { message: m })));
    }
  }
  return (
    <div className="grid gap-2">
      {asking ? (
        <div className="grid gap-2">
          <Alert>{t("gwActions.decommissionWarning", { name: g.name })}</Alert>
          <div className="flex gap-2">
            <Button size="sm" variant="destructive" onClick={() => void retire()}>{t("connectors.decommissionNamed", { name: g.name })}</Button>
            <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" onClick={onEdit}>{t("targetForm.edit")}</Button>
          {g.enabled
            ? <Button size="sm" variant="outline" onClick={() => void drain(false)} title={t("gwActions.drainHint")}>{t("gwActions.drain")}</Button>
            : <Button size="sm" variant="outline" onClick={() => void drain(true)}>{t("gwActions.resume")}</Button>}
          {!g.status?.enrolled && <Button size="sm" variant="outline" onClick={() => setEnrolling(true)}>{t("gwActions.token")}</Button>}
          <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("connectors.decommission")}</Button>
        </div>
      )}
      {error && <Alert>{error}</Alert>}
      {enrolling && <GatewayToken orgId={orgId} gateway={g} onClose={() => setEnrolling(false)} />}
    </div>
  );
}

// GatewayToken mints the enrollment token bound to a gateway after a step-up, and shows the install
// command, which never holds the token, and the token once (docs/04-security.md, "Join command").
function GatewayToken({ orgId, gateway: g, onClose }: { orgId: string; gateway: Gateway; onClose: () => void }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const mint = useMutation(EnrollmentService.method.createGatewayEnrollmentToken);
  const command = useMutation(EnrollmentService.method.getInstallCommand);
  const [requestId] = useState(() => crypto.randomUUID());
  const [result, setResult] = useState<{ token: string; command: string }>();
  const [error, setError] = useState("");
  async function go() {
    setError("");
    try {
      const tok = await stepUp(() => mint.mutateAsync({ gatewayId: g.id, ttl: { seconds: 3600n }, requestId }));
      const cmd = await command.mutateAsync({ orgId, role: AgentRole.GATEWAY });
      setResult({ token: tok.token, command: cmd.command });
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(message(err, (m) => t("link.failed", { message: m })));
      }
    }
  }
  return (
    <div className="grid gap-2 rounded-md border border-border p-3 text-sm">
      {result ? (
        <>
          <p>{t("enroll.step1")}</p>
          <Command command={result.command} label={t("enroll.command")} />
          <p>{t("enroll.step2")}</p>
          <OneTimeToken token={result.token} label={t("enroll.token")} />
          <p className="text-muted-foreground">{t("enroll.note", { lifetime: t("enroll.lifetimes.3600") })}</p>
        </>
      ) : (
        <>
          <p>{t("gwActions.tokenIntro", { name: g.name })}</p>
          <Button size="sm" className="justify-self-start" disabled={mint.isPending} onClick={() => void go()}>{t("enroll.create")}</Button>
        </>
      )}
      {error && <Alert>{error}</Alert>}
      <Button size="sm" variant="outline" className="justify-self-start" onClick={onClose}>{t("enroll.close")}</Button>
    </div>
  );
}
