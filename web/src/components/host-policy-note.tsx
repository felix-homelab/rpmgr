// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@connectrpc/connect-query";
import { useTranslation } from "react-i18next";
import { ReleaseService } from "@/gen/rpmgr/v1/release_pb";

// HostPolicyNote says what the controller's own host takes: the update_channel and auto_update of
// its local policy file, which the root updater obeys and this web UI never writes. The instance's
// release channel and the host's are two settings, so the note names the command that changes the
// host's (#1135; docs/10-operations.md, "Root updater"). It shows nothing until the controller has
// read the file, and for a controller that has no root updater.
export function HostPolicyNote() {
  const { t } = useTranslation();
  const status = useQuery(ReleaseService.method.getControllerUpdate, {}, { refetchInterval: 5000 });
  const d = status.data;
  if (!d || (!d.hostUpdateChannel && !d.hostPolicyError)) return null;
  const command = (c: string) => <code className="rounded bg-muted px-1 font-mono">{c}</code>;
  return (
    <div className="grid gap-1 text-xs text-muted-foreground" data-testid="host-policy">
      {d.hostPolicyError ? (
        <p>{t("updates.hostPolicy.error", { error: d.hostPolicyError })} {command("sudo rpmgr policy set-auto-update auto")}</p>
      ) : (
        <>
          <p>
            {d.hostUpdateChannel === "prerelease" ? t("updates.hostPolicy.prerelease") : t("updates.hostPolicy.stable")}
            {d.hostUpdateChannel !== "prerelease" && <> {command("sudo rpmgr policy set-update-channel prerelease")}</>}
          </p>
          {d.hostAutoUpdate && d.hostAutoUpdate !== "auto" && (
            <p>{t("updates.hostPolicy.autoOff", { value: d.hostAutoUpdate })} {command("sudo rpmgr policy set-auto-update auto")}</p>
          )}
        </>
      )}
    </div>
  );
}
