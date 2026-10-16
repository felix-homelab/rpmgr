// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError, createClient } from "@connectrpc/connect";
import { useMutation, useQuery as useConnectQuery, useTransport } from "@connectrpc/connect-query";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { RecoveryActions } from "@/components/recovery";
import { Status } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { AuthService } from "@/gen/rpmgr/v1/auth_pb";
import { UserService, type User } from "@/gen/rpmgr/v1/user_pb";
import { Reason, reasonOf } from "@/lib/errors";
import { when } from "@/lib/format";
import { largestPage, listAll } from "@/lib/list-all";
import { InstanceAdminPage } from "@/pages/settings";
import { useStepUp } from "@/step-up";

// Users shows the Instance Admin every account of the instance, and recovers or changes one after
// a step-up: a password-reset link, the removal of a lost second factor, and the Instance Admin
// role, which the last active Instance Admin keeps (docs/09-web-ui.md, "Settings"; docs/04-security.md,
// "Account recovery").
export function Users() {
  const { t } = useTranslation();
  return (
    <InstanceAdminPage title={t("users.title")}>
      <UserList />
    </InstanceAdminPage>
  );
}

function UserList() {
  const { t } = useTranslation();
  const transport = useTransport();
  const users = useQuery({
    queryKey: ["users"],
    queryFn: () => listAll(async (pageToken) => {
      const r = await createClient(UserService, transport).listUsers({ pageSize: largestPage, pageToken });
      return { items: r.users, next: r.nextPageToken };
    }),
  });
  const me = useConnectQuery(AuthService.method.getSession, {}).data?.userId;
  return (
    <Card title={t("users.title")} description={t("users.intro")}>
      {users.error && <Alert>{users.error.message}</Alert>}
      <Table framed={false}>
        <THead>
          <tr>{["name", "email", "roles", "mfa", "status", "lastLogin", "actions"].map((c) => <TH key={c}>{t(`users.columns.${c}`)}</TH>)}</tr>
        </THead>
        <tbody>{(users.data ?? []).map((u) => <UserRow key={u.id} user={u} me={u.id === me} />)}</tbody>
      </Table>
    </Card>
  );
}

function UserRow({ user: u, me }: { user: User; me: boolean }) {
  const { t } = useTranslation();
  const name = u.displayName || u.email;
  return (
    <TR className="align-top">
      <TD className="font-medium">{u.displayName}{me && <span className="text-muted-foreground"> ({t("users.you")})</span>}</TD>
      <TD className="wrap-anywhere">{u.email}</TD>
      <TD>{u.instanceAdmin ? <Status look="ok">{t("users.yes")}</Status> : t("users.no")}</TD>
      <TD>{u.mfa ? <Status look="ok">{t("users.yes")}</Status> : t("users.no")}</TD>
      <TD>{u.status === "disabled" ? <Status look="off">{t("users.statuses.disabled")}</Status> : t("users.statuses.active")}</TD>
      <TD className="whitespace-nowrap">{u.lastLoginTime ? when(u.lastLoginTime) : t("users.never")}</TD>
      <TD>
        <div className="grid gap-2">
          <InstanceAdminAction user={u} name={name} />
          {!me && <RecoveryActions userId={u.id} name={name} secondFactor={u.mfa} />}
        </div>
      </TD>
    </TR>
  );
}

// InstanceAdminAction grants or revokes the Instance Admin role after a confirmation and a step-up.
function InstanceAdminAction({ user: u, name }: { user: User; name: string }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  const set = useMutation(UserService.method.setInstanceAdmin);
  const queryClient = useQueryClient();
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  const grant = !u.instanceAdmin;
  async function confirm() {
    setError("");
    try {
      await stepUp(() => set.mutateAsync({ userId: u.id, instanceAdmin: grant }));
      setAsking(false);
      await queryClient.invalidateQueries();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) {
        const e = ConnectError.from(err);
        setError(e.code === Code.FailedPrecondition || e.code === Code.NotFound ? e.rawMessage : t("link.failed", { message: e.rawMessage }));
      }
    }
  }
  return (
    <span className="flex flex-wrap items-center gap-2">
      {asking ? (
        <>
          {t(grant ? "users.grantAsk" : "users.revokeAsk", { name })}
          <Button size="sm" variant={grant ? "default" : "destructive"} disabled={set.isPending} onClick={() => void confirm()}>{t("users.confirm")}</Button>
          <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
        </>
      ) : (
        <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t(grant ? "users.grant" : "users.revoke")}</Button>
      )}
      {error && <span className="w-full"><Alert>{error}</Alert></span>}
    </span>
  );
}
