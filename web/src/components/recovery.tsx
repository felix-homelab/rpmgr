// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Command } from "@/components/one-time-token";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { UserService } from "@/gen/rpmgr/v1/user_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { useStepUp } from "@/step-up";

// RecoveryActions recover another user's access after a step-up (docs/04-security.md, "Account
// recovery"): a one-time password-reset link to pass on, and, where secondFactor, the removal of
// their authenticator and recovery codes, which ends their sessions. The server decides who may;
// a user the caller may not recover is not found.
export function RecoveryActions({ userId, name, secondFactor }: { userId: string; name: string; secondFactor: boolean }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const link = useMutation(UserService.method.createPasswordResetLink);
  const remove = useMutation(UserService.method.removeUserTOTP);
  const queryClient = useQueryClient();
  const [asking, setAsking] = useState(false);
  const [result, setResult] = useState<{ url: string; until: string }>();
  const [done, setDone] = useState("");
  const [error, setError] = useState("");
  async function act(run: () => Promise<void>) {
    setError("");
    setDone("");
    try {
      await run();
    } catch (err) {
      setError(failure(err, t));
    }
  }
  return (
    <span className="flex flex-wrap items-center gap-2">
      <Button size="sm" variant="outline" disabled={link.isPending} onClick={() => void act(async () => {
        const r = await stepUp(() => link.mutateAsync({ userId }));
        setResult({ url: r.url, until: when(r.expireTime) });
      })}>{t("recovery.link")}</Button>
      {secondFactor && (asking ? (
        <span className="flex flex-wrap items-center gap-2">
          {t("recovery.removeAsk", { name })}
          <Button size="sm" variant="destructive" onClick={() => void act(async () => {
            await stepUp(() => remove.mutateAsync({ userId }));
            setAsking(false);
            setDone(t("recovery.removed", { name }));
            await queryClient.invalidateQueries();
          })}>{t("recovery.remove")}</Button>
          <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
        </span>
      ) : (
        <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("recovery.removeOpen")}</Button>
      ))}
      {result && (
        <span className="grid w-full gap-1 text-sm">
          <span role="status">{t("recovery.linkMade", { name, until: result.until })}</span>
          <Command command={result.url} label={t("recovery.linkLabel", { name })} />
        </span>
      )}
      {done && <span role="status" className="w-full text-sm">{done}</span>}
      {error && <span className="w-full"><Alert>{error}</Alert></span>}
    </span>
  );
}

// failure is what a recovery's error says; nothing for a cancelled step-up.
function failure(err: unknown, t: (k: string, o?: Record<string, string>) => string): string {
  if (reasonOf(err) === Reason.stepUpRequired) {
    return "";
  }
  const e = ConnectError.from(err);
  if (e.code === Code.NotFound) {
    return t("recovery.notYours");
  }
  return [Code.InvalidArgument, Code.FailedPrecondition, Code.PermissionDenied].includes(e.code) ? e.rawMessage : t("link.failed", { message: e.rawMessage });
}
