// SPDX-License-Identifier: Apache-2.0

import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Command } from "@/components/one-time-token";
import { RecoveryActions } from "@/components/recovery";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
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
    return <p className="text-sm text-muted-foreground">{t("stepUp.loading")}</p>;
  }
  return (
    <div className="grid gap-6">
      <PageHeader title={got.data?.org?.name ?? t("org.title")} description={t("org.intro")} />
      {got.data?.org?.restoreReviewTime && (org.role === "owner" ? (
        <OwnerReview orgId={org.orgId} since={got.data.org.restoreReviewTime} />
      ) : (
        <p role="status" className="rounded-xl border border-warn/40 bg-warn/10 p-4 text-sm">
          {t("review.orgReadOnly", { since: when(got.data.org.restoreReviewTime) })}{" "}
          <code className="font-mono">rpmgr restore confirm --org {got.data.org.slug}</code>
        </p>
      ))}
      {got.data?.org && <OrgName key={got.data.org.name} orgId={org.orgId} name={got.data.org.name} />}
      <Card title={t("org.members")}>
        <Table framed={false}>
          <THead>
            <tr>{["name", "email", "role", "since", "actions"].map((c) => <TH key={c}>{t(`org.columns.${c}`)}</TH>)}</tr>
          </THead>
          <tbody>{(members.data?.members ?? []).map((m) => <MemberRow key={m.userId} orgId={org.orgId} role={org.role} member={m} />)}</tbody>
        </Table>
      </Card>
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
    <Card title={t("review.orgTitle")} description={t("review.orgIntro", { since: when(since) })} className="border-warn/40">
      <h3 className="text-sm font-medium">{t("review.tokens")}</h3>
      {list.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("review.noTokens")}</p>
      ) : (
        <Table framed={false}>
          <THead>
            <tr>{["name", "owner", "scopes", "suspended", "actions"].map((c) => <TH key={c}>{t(`review.columns.${c}`)}</TH>)}</tr>
          </THead>
          <tbody>{list.map((s) => <SuspendedToken key={s.apiToken?.id} orgId={orgId} token={s} />)}</tbody>
        </Table>
      )}
      <div>
        <Button size="sm" onClick={() => void confirmed()} disabled={confirm.isPending}>{t("review.confirm")}</Button>
      </div>
      {error && <Alert>{error}</Alert>}
    </Card>
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
    <TR>
      <TD><span className="font-medium">{tok?.name}</span> <code className="font-mono text-muted-foreground">{tok?.prefix}</code></TD>
      <TD>{s.ownerEmail || s.ownerId}</TD>
      <TD>{tok?.scopes.join(", ")}</TD>
      <TD>{when(tok?.suspendTime)}</TD>
      <TD>
        <Button size="sm" variant="outline" onClick={() => void resumed()} disabled={resume.isPending}
          aria-label={t("review.resumeOf", { name: tok?.name ?? "" })}>{t("review.resume")}</Button>
        {error && <div className="mt-2"><Alert>{error}</Alert></div>}
      </TD>
    </TR>
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
    <Card title={t("org.nameTitle")}>
      <form onSubmit={save} aria-label={t("org.nameTitle")} className="flex flex-wrap items-end gap-2" noValidate>
        <div className="w-72"><Field label={t("org.name")} required value={name} onChange={(e) => setName(e.target.value)} /></div>
        <Button type="submit" variant="outline" disabled={update.isPending || name.trim() === was}>{t("routeForm.save")}</Button>
        {message && <div className="w-full"><Alert tone={message.tone}>{message.text}</Alert></div>}
      </form>
    </Card>
  );
}

// MemberRow shows a member and changes their role or removes them, with a step-up where the server
// asks for one (granting Admin or Owner). For the caller's role, it recovers another member's
// access: an Owner's or Admin's reset link, an Admin's not for an Owner, and an Owner's removal of
// the second factor (docs/04-security.md, "Account recovery").
function MemberRow({ orgId, role, member: m }: { orgId: string; role: string; member: Member }) {
  const { t } = useTranslation();
  const me = useQuery(AuthService.method.getSession, {}).data?.userId;
  const recover = m.userId !== me && (role === "owner" || (role === "admin" && m.role !== "owner"));
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
    <TR className="align-middle">
      <TD className="font-medium">{m.displayName}</TD>
      <TD>{m.email}</TD>
      <TD>
        <Select aria-label={t("org.roleOf", { name: who })} className="w-36" value={m.role}
          onChange={(e) => {
            const role = e.target.value; // the select shows the stored role again until the change is saved
            void act(() => update.mutateAsync({ orgId, userId: m.userId, role }));
          }}>
          {roles.map((r) => <option key={r} value={r}>{t(`org.roles.${r}`)}</option>)}
        </Select>
      </TD>
      <TD className="whitespace-nowrap">{when(m.createTime)}</TD>
      <TD>
        {asking ? (
          <span className="flex flex-wrap items-center gap-2">
            {t("org.removeAsk", { name: who })}
            <Button size="sm" variant="destructive" onClick={() => void act(() => remove.mutateAsync({ orgId, userId: m.userId }))}>{t("targetForm.remove")}</Button>
            <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
          </span>
        ) : (
          <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("targetForm.removeAsk")}</Button>
        )}
        {error && <div className="mt-2"><Alert>{error}</Alert></div>}
        {recover && <div className="mt-2"><RecoveryActions userId={m.userId} name={who} secondFactor={role === "owner"} /></div>}
      </TD>
    </TR>
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
    <Card title={t("org.invite")} description={t("org.inviteIntro")}>
      <form onSubmit={save} className="flex flex-wrap items-end gap-2" noValidate>
        <div className="w-72"><Field label={t("login.email")} type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></div>
        <label className="grid gap-1.5 text-sm font-medium">
          {t("org.columns.role")}
          <Select className="w-36 font-normal" value={role} onChange={(e) => setRole(e.target.value)}>
            {roles.map((r) => <option key={r} value={r}>{t(`org.roles.${r}`)}</option>)}
          </Select>
        </label>
        <Button type="submit" disabled={invite.isPending || !email}>{t("org.inviteSubmit")}</Button>
      </form>
      {error && <Alert>{error}</Alert>}
      {result && (
        <div className="grid gap-1 text-sm">
          <p role="status">{t(result.mailed ? "org.mailed" : "org.notMailed", { until: result.until })}</p>
          <Command command={result.url} label={t("org.link")} />
        </div>
      )}
    </Card>
  );
}
