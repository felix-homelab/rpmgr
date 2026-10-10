// SPDX-License-Identifier: Apache-2.0

import { clone, create } from "@bufbuild/protobuf";
import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { GatewayService, PortPoolSchema, PortProtocol, type PortPool, type PortQuota } from "@/gen/rpmgr/v1/gateway_pb";

const protocols = [PortProtocol.TCP, PortProtocol.UDP];

// PortPools shows a group's port pools, from which TCP and UDP routes get their public ports, and
// the org's port quotas in the group; it adds, changes and removes them (docs/09-web-ui.md,
// "Gateways"). Without a quota, the pools alone limit the org.
export function PortPools({ orgId, groupId }: { orgId: string; groupId: string }) {
  const { t } = useTranslation();
  const pools = useQuery(GatewayService.method.listPortPools, { orgId, gatewayGroupId: groupId, pageSize: 500 });
  const quotas = useQuery(GatewayService.method.listPortQuotas, { orgId, gatewayGroupId: groupId, pageSize: 500 });
  const [adding, setAdding] = useState(false);
  return (
    <section aria-labelledby="pools-title" className="grid gap-3">
      <h2 id="pools-title" className="text-lg font-semibold">{t("pools.title")}</h2>
      <ul className="grid gap-2">
        {(pools.data?.portPools ?? []).map((p) => <PoolRow key={p.id} pool={p} />)}
      </ul>
      {pools.data?.portPools.length === 0 && <p className="text-sm">{t("pools.none")}</p>}
      {adding
        ? <PoolForm orgId={orgId} groupId={groupId} onDone={() => setAdding(false)} />
        : <Button size="sm" variant="outline" className="justify-self-start" onClick={() => setAdding(true)}>{t("pools.add")}</Button>}
      <h3 className="font-semibold">{t("pools.quotas")}</h3>
      <p className="text-sm text-muted-foreground">{t("pools.quotasIntro")}</p>
      {protocols.map((p) => {
        const quota = quotas.data?.portQuotas.find((q) => q.protocol === p);
        return <QuotaRow key={`${p}:${quota?.maxPorts ?? "-"}`} orgId={orgId} groupId={groupId} protocol={p} quota={quota} />;
      })}
    </section>
  );
}

// range reads a pool's first and last port, both 1 to 65535 and in order; undefined if they are not.
function range(from: string, to: string): [number, number] | undefined {
  const a = Number(from), b = Number(to);
  return Number.isInteger(a) && Number.isInteger(b) && a >= 1 && b <= 65535 && a <= b ? [a, b] : undefined;
}

function PoolForm({ orgId, groupId, pool, onDone }: { orgId: string; groupId: string; pool?: PortPool; onDone: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const add = useMutation(GatewayService.method.createPortPool);
  const update = useMutation(GatewayService.method.updatePortPool);
  const [requestId] = useState(() => crypto.randomUUID());
  const [form, setForm] = useState({ protocol: String(pool?.protocol ?? PortProtocol.TCP), from: String(pool?.portFrom ?? ""), to: String(pool?.portTo ?? "") });
  const [error, setError] = useState("");
  async function save(e: FormEvent) {
    e.preventDefault();
    const r = range(form.from, form.to);
    if (!r) {
      setError(t("pools.range"));
      return;
    }
    try {
      if (pool) {
        const next = clone(PortPoolSchema, pool);
        [next.portFrom, next.portTo] = r;
        await update.mutateAsync({ portPool: next, updateMask: { paths: ["port_from", "port_to"] }, etag: pool.etag });
      } else {
        await add.mutateAsync({ orgId, portPool: create(PortPoolSchema, { gatewayGroupId: groupId, protocol: Number(form.protocol), portFrom: r[0], portTo: r[1] }), requestId });
      }
      await queryClient.invalidateQueries();
      onDone();
    } catch (err) {
      setError(ConnectError.from(err).rawMessage);
    }
  }
  return (
    <form onSubmit={save} aria-label={t(pool ? "pools.editTitle" : "pools.addTitle")} className="flex flex-wrap items-end gap-2" noValidate>
      <label className="grid gap-1 text-sm">
        {t("pools.protocol")}
        <select disabled={!!pool} className="h-9 rounded-md border border-border bg-background px-2" value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })}>
          {protocols.map((p) => <option key={p} value={String(p)}>{PortProtocol[p]}</option>)}
        </select>
      </label>
      <label className="grid gap-1 text-sm">{t("pools.from")}<Input className="w-28" inputMode="numeric" value={form.from} onChange={(e) => setForm({ ...form, from: e.target.value })} /></label>
      <label className="grid gap-1 text-sm">{t("pools.to")}<Input className="w-28" inputMode="numeric" value={form.to} onChange={(e) => setForm({ ...form, to: e.target.value })} /></label>
      <Button type="submit" size="sm" disabled={add.isPending || update.isPending}>{t(pool ? "routeForm.save" : "pools.addSubmit")}</Button>
      <Button size="sm" variant="outline" onClick={onDone}>{t("stepUp.cancel")}</Button>
      {error && <div className="w-full"><Alert>{error}</Alert></div>}
    </form>
  );
}

function PoolRow({ pool: p }: { pool: PortPool }) {
  const { t } = useTranslation();
  const remove = useMutation(GatewayService.method.deletePortPool);
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<"show" | "edit" | "ask">("show");
  const [error, setError] = useState("");
  const name = `${PortProtocol[p.protocol]} ${p.portFrom}–${p.portTo}`;
  if (mode === "edit") {
    return <li><PoolForm orgId="" groupId={p.gatewayGroupId} pool={p} onDone={() => setMode("show")} /></li>;
  }
  return (
    <li className="flex flex-wrap items-center gap-2 text-sm">
      <span className="font-medium">{name}</span>
      {mode === "ask" ? (
        <>
          {t("pools.ask", { name })}
          <Button size="sm" variant="destructive"
            onClick={() => void remove.mutateAsync({ portPoolId: p.id, etag: p.etag }).then(() => queryClient.invalidateQueries(), (err: unknown) => setError(ConnectError.from(err).rawMessage))}>
            {t("targetForm.remove")}
          </Button>
          <Button size="sm" variant="outline" onClick={() => setMode("show")}>{t("stepUp.cancel")}</Button>
        </>
      ) : (
        <>
          <Button size="sm" variant="outline" onClick={() => setMode("edit")}>{t("targetForm.edit")}</Button>
          <Button size="sm" variant="outline" onClick={() => setMode("ask")}>{t("targetForm.removeAsk")}</Button>
        </>
      )}
      {error && <div className="w-full"><Alert>{error}</Alert></div>}
    </li>
  );
}

// QuotaRow sets or removes the org's quota of one protocol's ports in the group.
function QuotaRow({ orgId, groupId, protocol, quota }: { orgId: string; groupId: string; protocol: PortProtocol; quota?: PortQuota }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const set = useMutation(GatewayService.method.setPortQuota);
  const remove = useMutation(GatewayService.method.deletePortQuota);
  const [max, setMax] = useState(quota ? String(quota.maxPorts) : "");
  const [error, setError] = useState("");
  async function save(e: FormEvent) {
    e.preventDefault();
    setError("");
    const n = Number(max);
    try {
      if (max.trim() === "") {
        if (quota) {
          await remove.mutateAsync({ portQuotaId: quota.id });
        }
      } else if (Number.isInteger(n) && n >= 0 && n <= 65535) {
        await set.mutateAsync({ orgId, gatewayGroupId: groupId, protocol, maxPorts: n });
      } else {
        setError(t("pools.quotaRange"));
        return;
      }
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(ConnectError.from(err).rawMessage);
    }
  }
  return (
    <form onSubmit={save} aria-label={t("pools.quotaOf", { protocol: PortProtocol[protocol] })} className="flex flex-wrap items-end gap-2" noValidate>
      <label className="grid gap-1 text-sm">
        {t("pools.quotaLabel", { protocol: PortProtocol[protocol] })}
        <Input className="w-28" inputMode="numeric" placeholder={t("pools.noQuota")} value={max} onChange={(e) => setMax(e.target.value)} />
      </label>
      {quota && <span className="text-sm text-muted-foreground">{t("pools.allocated", { count: quota.allocatedPorts })}</span>}
      <Button type="submit" size="sm" variant="outline" disabled={set.isPending || remove.isPending}>{t("routeForm.save")}</Button>
      {error && <div className="w-full"><Alert>{error}</Alert></div>}
    </form>
  );
}
