// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { AuthService, type Session } from "@/gen/rpmgr/v1/auth_pb";
import { when } from "@/lib/format";

// Sessions lists the user's live sessions, newest first, and ends any but the current one after a
// confirmation that names it (docs/09-web-ui.md, U7).
export function Sessions() {
  const { t } = useTranslation();
  const list = useQuery(AuthService.method.listSessions, {});
  return (
    <section aria-labelledby="section-sessions" className="grid gap-4">
      <h2 id="section-sessions" className="text-lg font-semibold">{t("sessions.title")}</h2>
      {list.data ? (
        <table className="w-full text-left text-sm">
          <thead className="text-muted-foreground">
            <tr>
              <th scope="col" className="py-1 font-medium">{t("sessions.browser")}</th>
              <th scope="col" className="py-1 font-medium">{t("sessions.address")}</th>
              <th scope="col" className="py-1 font-medium">{t("sessions.lastSeen")}</th>
              <th scope="col" className="py-1 font-medium"><span className="sr-only">{t("sessions.actions")}</span></th>
            </tr>
          </thead>
          <tbody>
            {list.data.sessions.map((s) => <Row key={s.id} session={s} />)}
          </tbody>
        </table>
      ) : (
        <p>{t("stepUp.loading")}</p>
      )}
    </section>
  );
}

function Row({ session }: { session: Session }) {
  const { t } = useTranslation();
  const revoke = useMutation(AuthService.method.revokeSession);
  const queryClient = useQueryClient();
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");

  async function end() {
    try {
      await revoke.mutateAsync({ sessionId: session.id });
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(t("link.failed", { message: ConnectError.from(err).rawMessage }));
    }
  }

  return (
    <tr className="border-t border-border align-top">
      <td className="max-w-64 truncate py-2" title={session.userAgent}>{session.userAgent || "—"}</td>
      <td className="py-2">{session.ip}</td>
      <td className="py-2">{when(session.lastSeenTime)}</td>
      <td className="py-2 text-right">
        {session.current ? (
          <span className="text-muted-foreground">{t("sessions.current")}</span>
        ) : asking ? (
          <span className="inline-flex items-center gap-2">
            {t("sessions.ask", { ip: session.ip })}
            <Button size="sm" variant="destructive" onClick={() => void end()} disabled={revoke.isPending}>{t("sessions.end")}</Button>
            <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
          </span>
        ) : (
          <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("sessions.endAsk")}</Button>
        )}
        {error && <Alert>{error}</Alert>}
      </td>
    </tr>
  );
}
