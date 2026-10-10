// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Alert, PublicPage } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { retryAfter } from "@/lib/errors";

// Forgot asks for a reset link by e-mail. The answer is the same whether an account has the address
// or not, so that the page reveals no accounts.
export function Forgot() {
  const { t } = useTranslation();
  const request = useMutation(AuthService.method.requestPasswordReset);
  const [email, setEmail] = useState("");
  const [result, setResult] = useState<{ tone: "info" | "error"; text: string }>();

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      await request.mutateAsync({ email });
      setResult({ tone: "info", text: t("forgot.sent") });
    } catch (err) {
      const code = ConnectError.from(err).code;
      const text = code === Code.Unavailable ? t("forgot.noMail")
        : code === Code.ResourceExhausted ? t("login.tooMany", { count: retryAfter(err) ?? 60 })
        : t("link.failed", { message: ConnectError.from(err).rawMessage });
      setResult({ tone: "error", text });
    }
  }

  return (
    <PublicPage title={t("forgot.title")}>
      <form onSubmit={submit} className="grid gap-4" noValidate>
        <Field label={t("login.email")} type="email" autoComplete="username" required value={email}
          onChange={(e) => setEmail(e.target.value)} />
        {result && <Alert tone={result.tone}>{result.text}</Alert>}
        <Button type="submit" disabled={request.isPending}>{t("forgot.submit")}</Button>
      </form>
    </PublicPage>
  );
}
