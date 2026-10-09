// SPDX-License-Identifier: Apache-2.0

import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Command } from "@/components/one-time-token";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { OrgService, type Member, type SuspendedAPIToken } from "@/gen/rpmgr/v1/org_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { useOrg } from "@/session";
import { useStepUp } from "@/step-up";

const roles = ["owner", "admin", "operator", "viewer"] as const;

// failure is what a member change's error says to the user; nothing for a cancelled step-up.
function failure(err: unknown, t: (k: string, o?: Record<string, string>) => string): string {
  if (reasonOf(err) === Reason.stepUpRequired) {
    return "";
  }
  const e = ConnectError.from(err);
  return [Code.InvalidArgument, Code.FailedPrecondition, Code.PermissionDenied].includes(e.code) ? e.rawMessage : t("link.failed", { message: e.rawMessage });
}

// OrgPage is the organisation (docs/09-web-ui.md, "Information architecture"): its name, its members
// and their roles, and invitations as one-time links (docs/04-security.md, "Roles").
export function OrgPage() {
  const { t } = useTranslation();
  const org = useOrg();
  const got = useQuery(OrgService.method.getOrg, { orgId: org?.orgId ?? "" }, { enabled: !!org });
  const members = useQuery(OrgService.method.listMembers, { orgId: org?.orgId ?? "" }, { enabled: !!org });
  if (!org) {
    return <p>{t("stepUp.loading")}</p>;
  }
  return (
    <div className="grid max-w-4xl gap-6">
      <h1 className="text-2xl font-semibold">{got.data?.org?.name ?? t("org.title")}</h1>
      {got.data?.org?.restoreReviewTime && (org.role === "owner" ? (
        <OwnerReview orgId={org.orgId} since={got.data.org.restoreReviewTime} />
      ) : (
        <p role="status" className="rounded-md border border-warn p-3 text-sm">
          {t("review.orgReadOnly", { since: when(got.data.org.restoreReviewTime) })}{" "}
          <code className="font-mono">rpmgr restore confirm --org {got.data.org.slug}</code>
        </p>
      ))}
      {got.data?.org && <OrgName key={got.data.org.name} orgId={org.orgId} name={got.data.org.name} />}
      <section aria-labelledby="members-title" className="grid gap-2">
        <h2 id="members-title" className="text-lg font-semibold">{t("org.members")}</h2>
        <table className="w-full text-left text-sm">
          <thead className="text-muted-foreground">
            <tr>{["name", "email", "role", "since", "actions"].map((c) => <th key={c} scope="col" className="py-1 font-medium">{t(`org.columns.${c}`)}</th>)}</tr>
          </thead>
          <tbody>{(members.data?.members ?? []).map((m) => <MemberRow key={m.userId} orgId={org.orgId} member={m} />)}</tbody>
        </table>
      </section>
      <Invite orgId={org.orgId} />
    </div>
  );
}

// OwnerReview is the Owner's restore review of their org (docs/10-operations.md, "Backup and
// restore"): the members and roles below to check, the API tokens the restore suspended to resume
// one by one, and the confirmation that ends the org's review. Each needs a step-up.
function OwnerReview({ orgId, since }: { orgId: string; since: Timestamp }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const tokens = useQuery(OrgService.method.listSuspendedAPITokens, { orgId });
  const confirm = useMutation(OrgService.method.confirmRestoreReview);
  const queryClient = useQueryClient();
  const [error, setError] = useState("");
  async function confirmed() {
    setError("");
    try {
      await stepUp(() => confirm.mutateAsync({ orgId }));
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(failure(err, t));
    }
  }
  const list = tokens.data?.apiTokens ?? [];
  return (
    <section aria-labelledby="review-title" className="grid gap-3 rounded-md border border-warn p-4">
      <h2 id="review-title" className="text-lg font-semibold">{t("review.orgTitle")}</h2>
      <p className="text-sm">{t("review.orgIntro", { since: when(since) })}</p>
      <h3 className="font-medium">{t("review.tokens")}</h3>
      {list.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("review.noTokens")}</p>
      ) : (
        <table className="w-full text-left text-sm">
          <thead className="text-muted-foreground">
            <tr>{["name", "owner", "scopes", "suspended", "actions"].map((c) => <th key={c} scope="col" className="py-1 font-medium">{t(`review.columns.${c}`)}</th>)}</tr>
          </thead>
          <tbody>{list.map((s) => <SuspendedToken key={s.apiToken?.id} orgId={orgId} token={s} />)}</tbody>
        </table>
      )}
      <div>
        <Button size="sm" onClick={() => void confirmed()} disabled={confirm.isPending}>{t("review.confirm")}</Button>
      </div>
      {error && <Alert>{error}</Alert>}
    </section>
  );
}

// SuspendedToken is an API token a restore suspended, which the Owner resumes after a step-up.
function SuspendedToken({ orgId, token: s }: { orgId: string; token: SuspendedAPIToken }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const resume = useMutation(OrgService.method.resumeAPIToken);
  const queryClient = useQueryClient();
  const [error, setError] = useState("");
  const tok = s.apiToken;
  async function resumed() {
    setError("");
    try {
      await stepUp(() => resume.mutateAsync({ orgId, tokenId: tok?.id ?? "" }));
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(failure(err, t));
    }
  }
  return (
    <tr className="border-t border-border align-top">
      <td className="py-2"><span className="font-medium">{tok?.name}</span> <code className="font-mono text-muted-foreground">{tok?.prefix}</code></td>
      <td className="py-2">{s.ownerEmail || s.ownerId}</td>
      <td className="py-2">{tok?.scopes.join(", ")}</td>
      <td className="py-2">{when(tok?.suspendTime)}</td>
      <td className="py-2">
        <Button size="sm" variant="outline" onClick={() => void resumed()} disabled={resume.isPending}
          aria-label={t("review.resumeOf", { name: tok?.name ?? "" })}>{t("review.resume")}</Button>
        {error && <Alert>{error}</Alert>}
      </td>
    </tr>
  );
}

// OrgName renames the org; the Owner only (org.write).
function OrgName({ orgId, name: was }: { orgId: string; name: string }) {
  const { t } = useTranslation();
  const update = useMutation(OrgService.method.updateOrg);
  const queryClient = useQueryClient();
  const [name, setName] = useState(was);
  const [message, setMessage] = useState<{ tone: "info" | "error"; text: string }>();
  async function save(e: FormEvent) {
    e.preventDefault();
    try {
      await update.mutateAsync({ orgId, name: name.trim() });
      setMessage({ tone: "info", text: t("account.saved") });
      await queryClient.invalidateQueries();
    } catch (err) {
      setMessage({ tone: "error", text: failure(err, t) });
    }
  }
  return (
    <form onSubmit={save} aria-label={t("org.nameTitle")} className="flex flex-wrap items-end gap-2" noValidate>
      <div className="w-72"><Field label={t("org.name")} value={name} onChange={(e) => setName(e.target.value)} /></div>
      <Button type="submit" size="sm" variant="outline" disabled={update.isPending || name.trim() === was}>{t("routeForm.save")}</Button>
      {message && <div className="w-full"><Alert tone={message.tone}>{message.text}</Alert></div>}
    </form>
  );
}

// MemberRow shows a member and changes their role or removes them, with a step-up where the server
// asks for one (granting Admin or Owner).
function MemberRow({ orgId, member: m }: { orgId: string; member: Member }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const update = useMutation(OrgService.method.updateMember);
  const remove = useMutation(OrgService.method.removeMember);
  const queryClient = useQueryClient();
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  async function act(run: () => Promise<unknown>) {
    setError("");
    try {
      await stepUp(run);
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(failure(err, t));
    }
  }
  const who = m.displayName || m.email;
  return (
    <tr className="border-t border-border align-top">
      <td className="py-2 font-medium">{m.displayName}</td>
      <td className="py-2">{m.email}</td>
      <td className="py-2">
        <select aria-label={t("org.roleOf", { name: who })} className="h-8 rounded-md border border-border bg-background px-2" value={m.role}
          onChange={(e) => {
            const role = e.target.value; // the select shows the stored role again until the change is saved
            void act(() => update.mutateAsync({ orgId, userId: m.userId, role }));
          }}>
          {roles.map((r) => <option key={r} value={r}>{t(`org.roles.${r}`)}</option>)}
        </select>
      </td>
      <td className="py-2">{when(m.createTime)}</td>
      <td className="py-2">
        {asking ? (
          <span className="flex flex-wrap items-center gap-2">
            {t("org.removeAsk", { name: who })}
            <Button size="sm" variant="destructive" onClick={() => void act(() => remove.mutateAsync({ orgId, userId: m.userId }))}>{t("targetForm.remove")}</Button>
            <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
          </span>
        ) : (
          <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("targetForm.removeAsk")}</Button>
        )}
        {error && <Alert>{error}</Alert>}
      </td>
    </tr>
  );
}

// Invite makes an invitation: a one-time link for an address and a role, also e-mailed when the
// controller can send mail (docs/04-security.md, "Password reset, invitations").
function Invite({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const invite = useMutation(OrgService.method.createInvitation);
  const [requestId, setRequestId] = useState(() => crypto.randomUUID());
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  const [result, setResult] = useState<{ url: string; mailed: boolean; until: string }>();
  const [error, setError] = useState("");
  async function save(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const r = await stepUp(() => invite.mutateAsync({ orgId, email: email.trim(), role, requestId }));
      setResult({ url: r.url, mailed: r.emailSent, until: when(r.expireTime) });
      setRequestId(crypto.randomUUID());
    } catch (err) {
      setError(failure(err, t));
    }
  }
  return (
    <section aria-labelledby="invite-title" className="grid gap-2">
      <h2 id="invite-title" className="text-lg font-semibold">{t("org.invite")}</h2>
      <form onSubmit={save} className="flex flex-wrap items-end gap-2" noValidate>
        <div className="w-72"><Field label={t("login.email")} type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></div>
        <label className="grid gap-1 text-sm font-medium">
          {t("org.columns.role")}
          <select className="h-9 rounded-md border border-border bg-background px-2 font-normal" value={role} onChange={(e) => setRole(e.target.value)}>
            {roles.map((r) => <option key={r} value={r}>{t(`org.roles.${r}`)}</option>)}
          </select>
        </label>
        <Button type="submit" size="sm" disabled={invite.isPending || !email}>{t("org.inviteSubmit")}</Button>
      </form>
      {error && <Alert>{error}</Alert>}
      {result && (
        <div className="grid gap-1 text-sm">
          <p role="status">{t(result.mailed ? "org.mailed" : "org.notMailed", { until: result.until })}</p>
          <Command command={result.url} label={t("org.link")} />
        </div>
      )}
    </section>
  );
}
