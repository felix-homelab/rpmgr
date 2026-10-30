// SPDX-License-Identifier: Apache-2.0

import { useTranslation } from "react-i18next";
import { Status, type Look } from "@/components/status";
import { FirewallState, type FirewallStatus, type Gateway } from "@/gen/rpmgr/v1/gateway_pb";

// The look of each state the gateway reports of its host's firewall (docs/09-web-ui.md, U8).
const looks: Record<FirewallState, [Look, string]> = {
  [FirewallState.UNSPECIFIED]: ["unknown", "unknown"],
  [FirewallState.OFF]: ["off", "off"],
  [FirewallState.APPLIED]: ["ok", "applied"],
  [FirewallState.FAILED]: ["failed", "failed"],
};

// FirewallChip shows the state of a gateway host's firewall management as the gateway last reported
// it: off, applied, or failed with the reason and the ports the helper refused (D152). A gateway
// that reports nothing is off, as one that does not manage its firewall is; an offline one is a dash.
export function FirewallChip({ gateway: g }: { gateway: Gateway }) {
  const { t } = useTranslation();
  const f = g.status?.firewall;
  if (!f) {
    return g.status?.connected ? <Status look="off">{t("firewall.off")}</Status> : <span aria-label={t("firewall.unknown")}>—</span>;
  }
  const [look, key] = looks[f.state] ?? looks[FirewallState.UNSPECIFIED];
  return (
    <span className="grid gap-1">
      <span><Status look={look}>{t(`firewall.${key}`)}</Status></span>
      {f.state === FirewallState.APPLIED && f.rules.length > 0 && (
        <span className="text-xs text-muted-foreground" title={f.rules.join(", ")}>{t("firewall.rules", { count: f.rules.length })}</span>
      )}
      {f.reason && <span className="max-w-72 text-xs text-muted-foreground">{f.reason}</span>}
      {f.refused.length > 0 && <span className="text-xs text-muted-foreground">{t("firewall.refused", { ports: f.refused.join(", ") })}</span>}
    </span>
  );
}

// covers tells whether the rules the helper holds, as ufw names them ("80/tcp", "20000:20099/udp"),
// open every port from..to of protocol: the helper merges the ranges of its pools, so a pool is
// open when the rules together cover it, not when one rule names it.
export function covers(rules: readonly string[], protocol: "tcp" | "udp", from: number, to: number): boolean {
  const spans: [number, number][] = [];
  for (const r of rules) {
    const m = /^(\d+)(?::(\d+))?\/(tcp|udp)$/.exec(r);
    if (m && m[3] === protocol) spans.push([Number(m[1]), Number(m[2] ?? m[1])]);
  }
  spans.sort((a, b) => a[0] - b[0]);
  let next = from;
  for (const [a, b] of spans) {
    if (a > next) break;
    next = Math.max(next, b + 1);
    if (next > to) return true;
  }
  return next > to;
}

// managing returns the gateways that report their firewall as applied or failed: those that hand
// their ufw to rpmgr and have heard of the helper.
export function managing(gateways: readonly Gateway[]): Gateway[] {
  return gateways.filter((g) => g.status?.firewall && g.status.firewall.state !== FirewallState.OFF && g.status.firewall.state !== FirewallState.UNSPECIFIED);
}

// PoolFirewall says on how many of a group's gateways that manage their firewall a pool's range is
// open now; nothing if none does.
export function PoolFirewall({ protocol, from, to, gateways }: { protocol: "tcp" | "udp"; from: number; to: number; gateways: readonly Gateway[] }) {
  const { t } = useTranslation();
  const managed = managing(gateways);
  if (managed.length === 0) return null;
  const open = managed.filter((g) => covers((g.status?.firewall as FirewallStatus).rules, protocol, from, to)).length;
  return (
    <span className="text-xs text-muted-foreground">
      {t("firewall.poolOpen", { open, count: managed.length })}
    </span>
  );
}
