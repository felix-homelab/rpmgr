// SPDX-License-Identifier: Apache-2.0

import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Status, type Look } from "@/components/status";
import type { HostnameDnsStatus } from "@/gen/rpmgr/v1/route_pb";

// The dns_status of a hostname and how it looks (docs/15-dns.md, "Publication rules"). A status this
// UI does not know is shown as it is, as unknown.
const looks: Record<string, Look> = {
  not_managed: "off", pending: "pending", published: "ok", conflict: "alert", ambiguous: "alert", held: "warn", error: "failed", rate_limited: "warn",
};

// problem says whether a status is one that someone has to act on, and so is listed as needing attention.
export const problem = (status: string) => ["conflict", "ambiguous", "error", "rate_limited"].includes(status);

// hintKey is the key of what to do about a hostname (U4): its status, or for a name that is not
// managed the reason it publishes nothing.
export function hintKey(s: Pick<HostnameDnsStatus, "status" | "reason">): string | undefined {
  if (s.status === "not_managed") {
    return ["no_target", "reserved", "not_verified"].includes(s.reason) ? `dnsStatus.reason.${s.reason}` : undefined;
  }
  return ["pending", "conflict", "ambiguous", "held", "error", "rate_limited"].includes(s.status) ? `dnsStatus.hint.${s.status}` : undefined;
}

// DnsHint is what to do about a hostname's DNS status, with a link to where to do it; nothing for a
// name that is published or deliberately not managed.
export function DnsHint({ status: s }: { status: Pick<HostnameDnsStatus, "status" | "reason"> }) {
  const { t } = useTranslation();
  const key = hintKey(s);
  if (!key) {
    return null;
  }
  const names = s.status === "ambiguous";
  return (
    <span className="text-muted-foreground">
      {t(key, { reason: s.reason })}{" "}
      {(s.status === "conflict" || s.status === "held" || s.status === "error") && <Link to="/dns" className="underline">{t("dnsStatus.zones")}</Link>}
      {names && <Link to="/dns-names" className="underline">{t("dnsStatus.names")}</Link>}
      {s.reason === "no_target" && s.status === "not_managed" && <Link to="/gateways" className="underline">{t("dnsStatus.groups")}</Link>}
    </span>
  );
}

// DnsLine is the DNS line of a route's hostname: its status, the records published for it and what
// to do about it. The status never changes the route's own (docs/15-dns.md).
export function DnsLine({ status: s }: { status: HostnameDnsStatus }) {
  const { t } = useTranslation();
  return (
    <li className="grid gap-1">
      <span className="flex flex-wrap items-center gap-2">
        <span className="font-mono">{s.hostname}</span>
        <Status look={looks[s.status] ?? "unknown"}>{t(`dnsStatus.label.${s.status}`, { defaultValue: s.status })}</Status>
        {s.records.length > 0 && <span className="font-mono text-muted-foreground">{s.records.join(", ")}</span>}
      </span>
      {s.status === "error" && s.reason && <span className="text-destructive">{s.reason}</span>}
      <DnsHint status={s} />
    </li>
  );
}
