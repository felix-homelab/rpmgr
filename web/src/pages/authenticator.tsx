// SPDX-License-Identifier: Apache-2.0

import { ConnectError, Code } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "@/components/field";
import { Alert } from "@/components/public-page";
import { QRCode } from "@/components/qr-code";
import { Button } from "@/components/ui/button";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { serverMessage } from "@/lib/link-token";
import { useStepUp } from "@/step-up";

// Authenticator sets up, renews the recovery codes of, and removes the user's authenticator (TOTP,
// docs/04-security.md, "Human authentication and sessions"). Every change needs a step-up and ends
// the user's other sessions; recovery codes are shown once.
export function Authenticator() {
  const { t } = useTranslation();
  const me = useQuery(UserService.method.getMe, {});
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const enroll = useMutation(UserService.method.enrollTOTP);
  const confirm = useMutation(UserService.method.confirmTOTP);
  const regenerate = useMutation(UserService.method.regenerateRecoveryCodes);
  const remove = useMutation(UserService.method.removeTOTP);
  const [setup, setSetup] = useState<{ secret: string; uri: string }>();
  const [codes, setCodes] = useState<string[]>();
  const [removing, setRemoving] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");

  // act runs a change with a step-up; a cancelled step-up shows nothing.
  async function act(change: () => Promise<void>) {
    setError("");
    try {
      await change();
      await queryClient.invalidateQueries();
    } catch (err) {
      const e = ConnectError.from(err);
      if (reasonOf(err) !== Reason.stepUpRequired) {
        setError(e.code === Code.InvalidArgument ? serverMessage(e.rawMessage) : t("link.failed", { message: e.rawMessage }));
      }
    }
  }
  const begin = () => act(async () => setSetup(await stepUp(() => enroll.mutateAsync({}))));
  const finish = (e: FormEvent) => {
    e.preventDefault();
    void act(async () => {
      const r = await stepUp(() => confirm.mutateAsync({ code }));
      setSetup(undefined);
      setCode("");
      setCodes(r.recoveryCodes);
    });
  };
  const renew = () => act(async () => setCodes((await stepUp(() => regenerate.mutateAsync({}))).recoveryCodes));
  const drop = () => act(async () => {
    await stepUp(() => remove.mutateAsync({}));
    setRemoving(false);
  });

  let body;
  if (codes) {
    body = (
      <>
        <p className="text-sm">{t("mfa.codesIntro")}</p>
        <ol aria-label={t("mfa.codes")} className="grid grid-cols-2 gap-1 font-mono text-sm">
          {codes.map((c) => <li key={c}>{c}</li>)}
        </ol>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => void navigator.clipboard?.writeText(codes.join("\n"))}>{t("mfa.copy")}</Button>
          <Button onClick={() => setCodes(undefined)}>{t("mfa.saved")}</Button>
        </div>
      </>
    );
  } else if (setup) {
    body = (
      <form onSubmit={finish} className="grid gap-4" noValidate>
        <p className="text-sm">{t("mfa.scan")}</p>
        <QRCode text={setup.uri} label={t("mfa.qr")} />
        <p className="text-sm">
          {t("mfa.manual")} <code className="font-mono">{setup.secret.match(/.{1,4}/g)?.join(" ")}</code>
        </p>
        <Field label={t("mfa.code")} autoComplete="one-time-code" inputMode="numeric" maxLength={6} required value={code}
          onChange={(e) => setCode(e.target.value.trim())} />
        <div className="flex gap-2">
          <Button type="submit" disabled={confirm.isPending}>{t("mfa.confirm")}</Button>
          <Button type="button" variant="outline" onClick={() => setSetup(undefined)}>{t("stepUp.cancel")}</Button>
        </div>
      </form>
    );
  } else if (me.data?.user?.mfa) {
    body = (
      <>
        <p className="text-sm">{t("mfa.active")}</p>
        {removing ? (
          <div className="grid gap-2">
            <Alert>{t("mfa.removeWarning")}</Alert>
            <div className="flex gap-2">
              <Button variant="destructive" onClick={() => void drop()}>{t("mfa.remove")}</Button>
              <Button variant="outline" onClick={() => setRemoving(false)}>{t("stepUp.cancel")}</Button>
            </div>
          </div>
        ) : (
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => void renew()}>{t("mfa.renew")}</Button>
            <Button variant="outline" onClick={() => setRemoving(true)}>{t("mfa.removeAsk")}</Button>
          </div>
        )}
      </>
    );
  } else {
    body = (
      <>
        <p className="text-sm">{t("mfa.none")}</p>
        <Button className="justify-self-start" onClick={() => void begin()} disabled={!me.data}>{t("mfa.setUp")}</Button>
      </>
    );
  }
  return (
    <section aria-labelledby="section-mfa" className="grid gap-4">
      <h2 id="section-mfa" className="text-lg font-semibold">{t("mfa.title")}</h2>
      {body}
      {error && <Alert>{error}</Alert>}
    </section>
  );
}
