// SPDX-License-Identifier: Apache-2.0

import { ConnectError } from "@connectrpc/connect";
import { useMutation } from "@connectrpc/connect-query";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert } from "@/components/public-page";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import type { DrainingProcess } from "@/gen/rpmgr/v1/common_pb";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { when } from "@/lib/format";
import { Reason, reasonOf } from "@/lib/errors";
import { useOrg } from "@/session";
import { useConnectors, useGateways } from "@/routes-data";
import { useStepUp } from "@/step-up";

// How often the dashboard reads the agents again while it may show a draining old process.
const refreshMs = 5000;

// canEndDrain tells whether the user may end an old process's drain: an Owner or Admin of the org
// (infrastructure.write, connectors.write), and for the all-in-one's own agents the Instance Admin.
// The API decides; this only hides a button that would be refused.
function canEndDrain(org: { role: string; instanceAdmin: boolean } | undefined, builtIn: boolean): boolean {
  if (!org) return false;
  return builtIn ? org.instanceAdmin : org.role === "owner" || org.role === "admin";
}

// DrainingLine shows the old process a hand-off left draining, and lets an admin end it: what it
// still holds, since when it drains and when it ends at the latest (docs/09-web-ui.md,
// "Restarting"; D160). It shows nothing without an old process.
export function DrainingLine({ kind, id, name, builtIn, draining }: {
  kind: "gateway" | "connector"; id: string; name: string; builtIn: boolean; draining?: DrainingProcess;
}) {
  const { t } = useTranslation();
  const org = useOrg();
  const stepUp = useStepUp();
  const queryClient = useQueryClient();
  const endGateway = useMutation(GatewayService.method.endGatewayDrain);
  const endConnector = useMutation(ConnectorService.method.endConnectorDrain);
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  if (!draining) return null;
  const open = draining.connections + draining.flows;
  async function end() {
    setError("");
    try {
      await stepUp(async () => { await (kind === "gateway" ? endGateway.mutateAsync({ gatewayId: id }) : endConnector.mutateAsync({ connectorId: id })); });
      setAsking(false);
      await queryClient.invalidateQueries();
    } catch (err) {
      if (reasonOf(err) !== Reason.stepUpRequired) setError(ConnectError.from(err).rawMessage);
    }
  }
  return (
    <div className="grid gap-2 text-sm">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="font-medium">{name}</span>
        <span className="text-muted-foreground">
          {t(`draining.${kind}Counts`, { connections: Number(draining.connections), flows: Number(draining.flows), sessions: Number(draining.sessions) })}
        </span>
        <span className="text-muted-foreground">{t("draining.times", { since: when(draining.since), ends: when(draining.ends) })}</span>
        {canEndDrain(org, builtIn) && !asking && (
          <Button size="sm" variant="outline" onClick={() => setAsking(true)}>{t("draining.end")}</Button>
        )}
      </div>
      {asking && (
        <div role="alertdialog" aria-label={t("draining.confirmTitle", { name })} className="grid gap-2">
          <Alert>{t("draining.confirm", { name, count: Number(open) })}</Alert>
          <div className="flex gap-2">
            <Button size="sm" variant="destructive" disabled={endGateway.isPending || endConnector.isPending} onClick={() => void end()}>
              {t("draining.endNamed", { name })}
            </Button>
            <Button size="sm" variant="outline" onClick={() => setAsking(false)}>{t("stepUp.cancel")}</Button>
          </div>
        </div>
      )}
      {error && <Alert>{error}</Alert>}
    </div>
  );
}

// Restarting is the dashboard card of the old processes that still drain after a socket hand-off,
// one line per agent; it is not shown when none does (docs/09-web-ui.md, "Restarting"; D160).
export function Restarting({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const gateways = useGateways(orgId, refreshMs).data;
  const connectors = useConnectors(orgId, refreshMs).data;
  const lines = [
    ...(gateways ?? []).filter((g) => g.status?.draining).map((g) => ({ kind: "gateway" as const, id: g.id, name: g.name, builtIn: g.builtIn, draining: g.status?.draining })),
    ...(connectors ?? []).filter((c) => c.session?.draining).map((c) => ({ kind: "connector" as const, id: c.id, name: c.name, builtIn: c.builtIn, draining: c.session?.draining })),
  ];
  if (lines.length === 0) return null;
  return (
    <Card title={t("draining.title")} description={t("draining.description")}>
      <ul className="grid divide-y divide-border">
        {lines.map((l) => <li key={`${l.kind}-${l.id}`} className="py-2 first:pt-0 last:pb-0"><DrainingLine {...l} /></li>)}
      </ul>
    </Card>
  );
}
