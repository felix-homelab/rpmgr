// SPDX-License-Identifier: Apache-2.0

import { createClient } from "@connectrpc/connect";
import { useTransport } from "@connectrpc/connect-query";
import { useQueries, useQuery } from "@tanstack/react-query";
import { problem } from "@/components/dns-status";
import { DnsRecordState, DnsZoneService, ZoneProviderStatus, ZoneSyncState } from "@/gen/rpmgr/v1/dns_pb";
import { largestPage, listAll } from "@/lib/list-all";
import { useRoutes } from "@/routes-data";

// A DnsProblem is one thing about DNS that needs attention: its kind, which decides the hint of U4
// (dnsStatus.hint.<kind>, or dnsProblem.<kind>), where it is, and what it is about.
export interface DnsProblem {
  key: string;
  kind: "conflict" | "ambiguous" | "error" | "rate_limited" | "drifted" | "held" | "permission_denied";
  subject: string;
  // Where its page is: a route or a zone.
  route?: string;
  zone?: string;
  reason?: string;
}

// useDnsProblems collects what needs attention in DNS: hostnames of routes whose DNS status is
// conflict, ambiguous, error or rate limited, which any member sees on the routes; and, for an
// Owner or Admin, who may read the zones, held zones, zones whose provider rate-limits or refuses
// the token, and the records that drifted (docs/09-web-ui.md, "Overview"; docs/15-dns.md). The
// zone queries do not retry: an instance that does not serve DNS answers them as unimplemented, and
// that is no problem to list.
export function useDnsProblems(orgId: string, admin: boolean): DnsProblem[] {
  const transport = useTransport();
  const routes = useRoutes(orgId).data ?? [];
  const zones = useQuery({
    queryKey: ["dns-zones", orgId],
    enabled: admin,
    retry: false,
    queryFn: () => listAll(async (pageToken) => {
      const r = await createClient(DnsZoneService, transport).listZones({ orgId, pageSize: largestPage, pageToken });
      return { items: r.dnsZones, next: r.nextPageToken };
    }),
  }).data ?? [];
  const records = useQueries({
    queries: zones.map((z) => ({
      queryKey: ["dns-zone-records", z.id],
      retry: false,
      queryFn: async () => (await createClient(DnsZoneService, transport).listZoneRecords({ dnsZoneId: z.id })).records,
    })),
  });
  const out: DnsProblem[] = [];
  for (const r of routes) {
    for (const s of r.dnsStatus) {
      if (problem(s.status)) {
        out.push({ key: `${r.id}/${s.hostname}`, kind: s.status as DnsProblem["kind"], subject: s.hostname, route: r.id, reason: s.reason });
      }
    }
  }
  zones.forEach((z, i) => {
    if (z.syncState === ZoneSyncState.HELD) {
      out.push({ key: `${z.id}/held`, kind: "held", subject: z.name, zone: z.id });
    }
    if (z.providerStatus === ZoneProviderStatus.RATE_LIMITED) {
      out.push({ key: `${z.id}/rate`, kind: "rate_limited", subject: z.name, zone: z.id });
    }
    if (z.providerStatus === ZoneProviderStatus.PERMISSION_DENIED) {
      out.push({ key: `${z.id}/denied`, kind: "permission_denied", subject: z.name, zone: z.id });
    }
    for (const rec of records[i]?.data ?? []) {
      if (rec.state === DnsRecordState.DRIFTED) {
        out.push({ key: `${z.id}/${rec.id}`, kind: "drifted", subject: rec.name, zone: z.id, reason: rec.reason });
      }
    }
  });
  return out;
}
