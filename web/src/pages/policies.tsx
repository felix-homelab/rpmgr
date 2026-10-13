// SPDX-License-Identifier: Apache-2.0

import { clone, create } from "@bufbuild/protobuf";
import { ConnectError, createClient } from "@connectrpc/connect";
import { useMutation, useTransport } from "@connectrpc/connect-query";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { Plus, ShieldCheck } from "lucide-react";
import { ApplyStatusView, useLiveApplyStatus } from "@/components/apply-status";
import { EmptyState } from "@/components/empty-state";
import { Field } from "@/components/field";
import { LinesField, trimmed } from "@/components/lines-field";
import { ManifestButton } from "@/components/manifest";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { Row, RowList } from "@/components/row-list";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";
import type { Revision } from "@/gen/rpmgr/v1/common_pb";
import { AccessPolicySchema, AccessRuleSchema, PolicyService, type AccessPolicy, type AccessRule } from "@/gen/rpmgr/v1/policy_pb";
import type { ApplyStatus } from "@/gen/rpmgr/v1/status_pb";
import { largestPage, listAll } from "@/lib/list-all";
import { useAgentNames, useRoutes } from "@/routes-data";
import { useOrg } from "@/session";

type Kind = "ipAllow" | "ipDeny" | "basicAuth";

// A rule as the form edits it; a basic-auth user's empty password keeps the one the policy has.
interface RuleDraft {
  kind: Kind;
  cidrs: string[];
  users: { name: string; password: string }[];
}

function draftOf(r: AccessRule): RuleDraft {
  switch (r.rule.case) {
    case "ipAllow":
    case "ipDeny":
      return { kind: r.rule.case, cidrs: r.rule.value.cidrs, users: [] };
    case "basicAuth":
      return { kind: "basicAuth", cidrs: [], users: r.rule.value.users.map((u) => ({ name: u.name, password: "" })) };
    default:
      return { kind: "ipAllow", cidrs: [], users: [] };
  }
}

function ruleOf(d: RuleDraft): AccessRule {
  if (d.kind === "basicAuth") {
    return create(AccessRuleSchema, { rule: { case: "basicAuth", value: { users: d.users.map((u) => ({ name: u.name.trim(), password: u.password })) } } });
  }
  return create(AccessRuleSchema, { rule: { case: d.kind, value: { cidrs: trimmed(d.cidrs) } } });
}

export function usePolicies(orgId: string | undefined) {
  const transport = useTransport();
  return useQuery({
    queryKey: ["access-policies", orgId],
    enabled: !!orgId,
    queryFn: () => listAll(async (pageToken) => {
      const r = await createClient(PolicyService, transport).listAccessPolicies({ orgId, pageSize: largestPage, pageToken });
      return { items: r.accessPolicies, next: r.nextPageToken };
    }),
  });
}

// Policies lists the org's access policies with their rules and the routes that use them, and
// creates, changes and deletes them (docs/09-web-ui.md, "Information architecture"; docs/03, "Access
// policies"). Rules apply in order.
export function Policies() {
  const { t } = useTranslation();
  const org = useOrg();
  const list = usePolicies(org?.orgId);
  const routes = useRoutes(org?.orgId);
  const names = useAgentNames(org?.orgId);
  const [editing, setEditing] = useState<string>(); // a policy's ID, or "new"
  const [write, setWrite] = useState<{ revision?: Revision; status?: ApplyStatus }>();
  const live = useLiveApplyStatus(org?.orgId ?? "", write?.revision, write?.status);
  const routeName = (id: string) => routes.data?.find((r) => r.id === id)?.name ?? id;
  const add = (
    <Button size="sm" disabled={!org} onClick={() => setEditing("new")}><Plus aria-hidden="true" />{t("policies.add")}</Button>
  );
  return (
    <section aria-labelledby="policies-title" className="grid gap-6">
      <PageHeader id="policies-title" title={t("policies.title")} description={t("policies.intro")} actions={<>
        {org && <ManifestButton label={t("manifest.export")} title={t("manifest.ofKind", { what: t("policies.title") })} orgId={org.orgId} kinds={["AccessPolicy"]} file="access-policies" />}
        {add}
      </>} />
      {live && <ApplyStatusView status={live} revision={write?.revision} name={(id) => names.data?.get(id) || id} />}
      {editing && org && (
        <PolicyForm key={editing} orgId={org.orgId} policy={list.data?.find((p) => p.id === editing)}
          onDone={(w) => (setEditing(undefined), w && setWrite(w))} />
      )}
      {list.data?.length === 0 ? <EmptyState icon={ShieldCheck} action={!editing && add}>{t("policies.none")}</EmptyState> : (
        <RowList framed>
          {[...(list.data ?? [])].sort((a, b) => a.name.localeCompare(b.name)).map((p) => (
            <PolicyRow key={p.id} policy={p} routeName={routeName} onEdit={() => setEditing(p.id)} onDone={setWrite} />
          ))}
        </RowList>
      )}
    </section>
  );
}

function summary(t: TFunction, r: AccessRule): string {
  switch (r.rule.case) {
    case "ipAllow": return t("policies.summary.allow", { cidrs: r.rule.value.cidrs.join(", ") });
    case "ipDeny": return t("policies.summary.deny", { cidrs: r.rule.value.cidrs.join(", ") });
    case "basicAuth": return t("policies.summary.basicAuth", { users: r.rule.value.users.map((u) => u.name).join(", ") });
    default: return "";
  }
}

function PolicyRow({ policy: p, routeName, onEdit, onDone }: {
  policy: AccessPolicy; routeName: (id: string) => string; onEdit: () => void; onDone: (w: { revision?: Revision; status?: ApplyStatus }) => void;
}) {
  const { t } = useTranslation();
  const remove = useMutation(PolicyService.method.deleteAccessPolicy);
  const queryClient = useQueryClient();
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  return (
    <Row>
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
        <div className="grid gap-1">
          <span className="font-medium">{p.name}</span>
          {p.description && <span className="text-muted-foreground">{p.description}</span>}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="outline" onClick={onEdit}>{t("targetForm.edit")}</Button>
          {asking ? (
            <>
              <span>{t("policies.ask", { name: p.name })}</span>
              <Button size="sm" variant="destructive" onClick={() => void remove.mutateAsync({ accessPolicyId: p.id, etag: p.etag }).then(
                async (res) => (onDone({ revision: res.revision, status: res.applyStatus }), await queryClient.invalidateQueries()),
                (err: unknown) => setError(ConnectError.from(err).rawMessage))}>{t("targetForm.remove")}</Button>
              <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
            </>
          ) : (
            <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("targetForm.removeAsk")}</Button>
          )}
        </div>
      </div>
      <ol className="grid list-decimal gap-0.5 pl-5 marker:text-muted-foreground">{p.rules.map((r, i) => <li key={i}>{summary(t, r)}</li>)}</ol>
      <span className="text-muted-foreground">{p.routeIds.length ? t("policies.usedBy", { routes: p.routeIds.map(routeName).join(", ") }) : t("policies.unused")}</span>
      {error && <Alert>{error}</Alert>}
    </Row>
  );
}

// PolicyForm creates a policy, or with policy changes one: the policy as read with its name,
// description and rules, their mask and its etag (U1). Passwords are write-only.
function PolicyForm({ orgId, policy, onDone }: { orgId: string; policy?: AccessPolicy; onDone: (w?: { revision?: Revision; status?: ApplyStatus }) => void }) {
  const { t } = useTranslation();
  const add = useMutation(PolicyService.method.createAccessPolicy);
  const update = useMutation(PolicyService.method.updateAccessPolicy);
  const queryClient = useQueryClient();
  const [requestId] = useState(() => crypto.randomUUID());
  const [name, setName] = useState(policy?.name ?? "");
  const [description, setDescription] = useState(policy?.description ?? "");
  const [rules, setRules] = useState<RuleDraft[]>(policy?.rules.map(draftOf) ?? [{ kind: "ipAllow", cidrs: [], users: [] }]);
  const [error, setError] = useState("");
  const setRule = (i: number, r: Partial<RuleDraft>) => setRules(rules.map((x, j) => (j === i ? { ...x, ...r } : x)));
  const move = (i: number, by: number) => {
    const next = [...rules];
    [next[i], next[i + by]] = [next[i + by]!, next[i]!];
    setRules(next);
  };
  async function save(e: FormEvent) {
    e.preventDefault();
    setError("");
    const next = policy ? clone(AccessPolicySchema, policy) : create(AccessPolicySchema);
    Object.assign(next, { name: name.trim(), description, rules: rules.map(ruleOf) });
    try {
      const res = policy
        ? await update.mutateAsync({ accessPolicy: next, updateMask: { paths: ["name", "description", "rules"] }, etag: policy.etag })
        : await add.mutateAsync({ orgId, accessPolicy: next, requestId });
      await queryClient.invalidateQueries();
      onDone({ revision: res.revision, status: res.applyStatus });
    } catch (err) {
      setError(ConnectError.from(err).rawMessage);
    }
  }
  return (
    <form onSubmit={save} aria-label={t(policy ? "policies.editTitle" : "policies.addTitle")}
      className="grid gap-4 rounded-xl border border-border bg-card p-5 shadow-xs" noValidate>
      <h2 className="font-semibold">{t(policy ? "policies.editTitle" : "policies.addTitle")}</h2>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("routeForm.fields.name")} value={name} onChange={(e) => setName(e.target.value)} />
        <Field label={t("routeForm.fields.description")} value={description} onChange={(e) => setDescription(e.target.value)} />
      </div>
      <fieldset className="grid gap-3">
        <legend className="mb-1 text-sm font-medium">{t("policies.rules")}</legend>
        {rules.map((r, i) => (
          <div key={i} role="group" aria-label={t("policies.ruleN", { n: i + 1 })} className="grid gap-3 rounded-lg border border-border bg-muted/40 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span aria-hidden="true" className="grid size-6 place-items-center rounded-full bg-muted text-xs font-medium text-muted-foreground">{i + 1}</span>
              <Select aria-label={t("policies.kind")} className="w-56" value={r.kind} onChange={(e) => setRule(i, { kind: e.target.value as Kind })}>
                {(["ipAllow", "ipDeny", "basicAuth"] as Kind[]).map((k) => <option key={k} value={k}>{t(`policies.kinds.${k}`)}</option>)}
              </Select>
              <span className="ml-auto flex flex-wrap gap-1">
                <Button size="sm" variant="ghost" disabled={i === 0} onClick={() => move(i, -1)}>{t("policies.up")}</Button>
                <Button size="sm" variant="ghost" disabled={i === rules.length - 1} onClick={() => move(i, 1)}>{t("policies.down")}</Button>
                <Button size="sm" variant="ghost" onClick={() => setRules(rules.filter((_, j) => j !== i))}>{t("policies.removeRule")}</Button>
              </span>
            </div>
            {r.kind === "basicAuth" ? (
              <div className="grid gap-2">
                {r.users.map((u, k) => (
                  <div key={k} className="flex flex-wrap items-end gap-2">
                    <label className="grid gap-1.5 text-sm font-medium">{t("policies.user")}
                      <Input value={u.name} onChange={(e) => setRule(i, { users: r.users.map((x, m) => (m === k ? { ...x, name: e.target.value } : x)) })} />
                    </label>
                    <label className="grid gap-1.5 text-sm font-medium">{t("login.password")}
                      <Input type="password" autoComplete="new-password" placeholder={policy ? t("policies.keep") : ""} value={u.password}
                        onChange={(e) => setRule(i, { users: r.users.map((x, m) => (m === k ? { ...x, password: e.target.value } : x)) })} />
                    </label>
                    <Button size="sm" variant="outline" onClick={() => setRule(i, { users: r.users.filter((_, m) => m !== k) })}>{t("policies.removeUser")}</Button>
                  </div>
                ))}
                <Button size="sm" variant="outline" className="justify-self-start" onClick={() => setRule(i, { users: [...r.users, { name: "", password: "" }] })}>{t("policies.addUser")}</Button>
              </div>
            ) : (
              <LinesField label={t("policies.cidrs")} value={r.cidrs} onChange={(cidrs) => setRule(i, { cidrs })} />
            )}
          </div>
        ))}
        <Button size="sm" variant="outline" className="justify-self-start" onClick={() => setRules([...rules, { kind: "ipAllow", cidrs: [], users: [] }])}>{t("policies.addRule")}</Button>
      </fieldset>
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={add.isPending || update.isPending}>{t(policy ? "routeForm.save" : "policies.addSubmit")}</Button>
        <Button variant="outline" onClick={() => onDone()}>{t("stepUp.cancel")}</Button>
      </div>
    </form>
  );
}
