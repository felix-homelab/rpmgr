// SPDX-License-Identifier: Apache-2.0

import { createClient } from "@connectrpc/connect";
import { useTransport } from "@connectrpc/connect-query";
import { useQuery } from "@tanstack/react-query";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService } from "@/gen/rpmgr/v1/gateway_pb";
import { RouteService, type Route } from "@/gen/rpmgr/v1/route_pb";
import { largestPage, listAll } from "@/lib/list-all";

// useRoutes reads all routes of the org.
export function useRoutes(orgId: string | undefined) {
  const transport = useTransport();
  return useQuery({
    queryKey: ["routes", orgId],
    enabled: !!orgId,
    queryFn: () => {
      const api = createClient(RouteService, transport);
      return listAll(async (pageToken) => {
        const r = await api.listRoutes({ orgId, pageSize: largestPage, pageToken });
        return { items: r.routes, next: r.nextPageToken };
      });
    },
  });
}

// useGroupNames maps the org's gateway group IDs to their names.
export function useGroupNames(orgId: string | undefined) {
  const transport = useTransport();
  return useQuery({
    queryKey: ["gateway-group-names", orgId],
    enabled: !!orgId,
    queryFn: async () => {
      const api = createClient(GatewayService, transport);
      const groups = await listAll(async (pageToken) => {
        const r = await api.listGatewayGroups({ orgId, pageSize: largestPage, pageToken });
        return { items: r.gatewayGroups, next: r.nextPageToken };
      });
      return new Map(groups.map((g) => [g.id, g.name]));
    },
  });
}

// The route types, by the case of Route.spec.
export const routeTypes = ["http", "tcp", "udp", "tlsPassthrough"] as const;

// routeType names a route's type; "" for a route without a spec.
export function routeType(r: Route): string {
  return r.spec.case ?? "";
}

// routeAddress is where a route is reached: its hostnames, or its public port.
export function routeAddress(r: Route): string[] {
  switch (r.spec.case) {
    case "http": {
      const { hostnames, pathPrefix } = r.spec.value;
      return hostnames.map((h) => h + pathPrefix);
    }
    case "tlsPassthrough":
      return r.spec.value.hostnames;
    case "tcp":
    case "udp":
      return r.spec.value.port ? [`:${r.spec.value.port}`] : [];
    default:
      return [];
  }
}

// blockedTargets counts the targets that a connector's local policy blocks.
export function blockedTargets(r: Route): number {
  return r.status?.notServing.filter((n) => n.reason === "BLOCKED_BY_LOCAL_POLICY").length ?? 0;
}

// useAgentNames maps the org's connector and gateway IDs to their names.
export function useAgentNames(orgId: string | undefined) {
  const transport = useTransport();
  return useQuery({
    queryKey: ["agent-names", orgId],
    enabled: !!orgId,
    queryFn: async () => {
      const connectors = createClient(ConnectorService, transport);
      const gateways = createClient(GatewayService, transport);
      const [cs, gs] = await Promise.all([
        listAll(async (pageToken) => {
          const r = await connectors.listConnectors({ orgId, pageSize: largestPage, pageToken });
          return { items: r.connectors, next: r.nextPageToken };
        }),
        listAll(async (pageToken) => {
          const r = await gateways.listGateways({ orgId, pageSize: largestPage, pageToken });
          return { items: r.gateways, next: r.nextPageToken };
        }),
      ]);
      return new Map([...cs, ...gs].map((a) => [a.id, a.name]));
    },
  });
}

// shellArg quotes a value for a POSIX shell, unless it needs no quotes.
export function shellArg(s: string): string {
  return /^[A-Za-z0-9_.:/@%+=,[\]-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

// allowCommand is the command that lets a connector's local policy reach a target it blocks
// (docs/04-security.md, "Connector-local policy"; docs/09-web-ui.md, U4).
export function allowCommand(target: string): string {
  return `sudo rpmgr policy allow-target ${shellArg(target)}`;
}

// useConnectors reads all connectors of the org in service.
export function useConnectors(orgId: string | undefined) {
  const transport = useTransport();
  return useQuery({
    queryKey: ["connectors", orgId],
    enabled: !!orgId,
    queryFn: () => {
      const api = createClient(ConnectorService, transport);
      return listAll(async (pageToken) => {
        const r = await api.listConnectors({ orgId, pageSize: largestPage, pageToken });
        return { items: r.connectors, next: r.nextPageToken };
      });
    },
  });
}
