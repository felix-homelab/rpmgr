// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Alert, PublicPage } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { OrgService } from "@/gen/rpmgr/v1/org_pb";
import { serverMessage, useLinkToken } from "@/lib/link-token";
import { passwordProblem } from "@/pages/reset";

// Invite uses an invitation link: a signed-in user joins with their account; without a session, an
// account is created for the invited address (docs/04-security.md, "Password reset, invitations").
export function Invite() {
  const { t } = useTranslation();
  const token = useLinkToken();
  const session = useQuery(AuthService.method.getSession, {}, { retry: false });
  const accept = useMutation(OrgService.method.acceptInvitation);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: "", password: "", confirm: "" });
  const [error, setError] = useState("");
  const [created, setCreated] = useState(false);
  async function join(e: FormEvent) {
    e.preventDefault();
    setError("");
    const signedIn = !!session.data;
    if (!signedIn) {
      const problem = passwordProblem(form.password, form.confirm);
      if (problem) {
        setError(t(problem));
        return;
      }
    }
    try {
      await accept.mutateAsync(signedIn ? { token } : { token, displayName: form.name.trim(), password: form.password });
      if (signedIn) {
        await queryClient.resetQueries();
        await navigate({ to: "/", replace: true });
      } else {
        setCreated(true);
      }
    } catch (err) {
      setError(serverMessage(ConnectError.from(err).rawMessage));
    }
  }
  if (!token) {
    return <PublicPage title={t("invite.title")}><Alert>{t("link.incomplete")}</Alert></PublicPage>;
  }
  if (created) {
    return (
      <PublicPage title={t("invite.title")}>
        <Alert tone="info">{t("invite.created")}</Alert>
        <Button asChild className="mt-4"><Link to="/login" search={{}}>{t("login.submit")}</Link></Button>
      </PublicPage>
    );
  }
  return (
    <PublicPage title={t("invite.title")}>
      <form onSubmit={join} className="grid gap-4" noValidate>
        {session.data ? (
          <p className="text-sm">{t("invite.asYou", { name: session.data.displayName || session.data.email })}</p>
        ) : (
          <>
            <p className="text-sm text-muted-foreground">{t("invite.newAccount")}</p>
            <Field label={t("setup.name")} autoComplete="name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <Field label={t("reset.password")} hint={t("reset.passwordHint")} type="password" autoComplete="new-password" value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })} />
            <Field label={t("reset.confirm")} type="password" autoComplete="new-password" value={form.confirm} onChange={(e) => setForm({ ...form, confirm: e.target.value })} />
          </>
        )}
        {error && <Alert>{error}</Alert>}
        <Button type="submit" disabled={accept.isPending || session.isPending}>{t("invite.join")}</Button>
      </form>
    </PublicPage>
  );
}
