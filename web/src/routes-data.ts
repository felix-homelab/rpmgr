// SPDX-License-Identifier: Apache-2.0

import { createClient } from "@connectrpc/connect";
import { useTransport } from "@connectrpc/connect-query";
import { useQuery } from "@tanstack/react-query";
import { ConnectorService } from "@/gen/rpmgr/v1/connector_pb";
import { GatewayService, type GatewayGroup } from "@/gen/rpmgr/v1/gateway_pb";
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
  return useGroupsAs(orgId, (gs) => new Map(gs.map((g) => [g.id, g.name])));
}

// useGroupHostnames maps the org's gateway group IDs to their public hostnames.
export function useGroupHostnames(orgId: string | undefined) {
  return useGroupsAs(orgId, (gs) => new Map(gs.map((g) => [g.id, g.publicHostnames])));
}

// The route types, by the case of Route.spec.
export const routeTypes = ["http", "tcp", "udp", "tcpUdp", "tlsPassthrough"] as const;

// routeType names a route's type; "" for a route without a spec.
export function routeType(r: Route): string {
  return r.spec.case ?? "";
}

// hostPort joins a host and a port, an IPv6 address in brackets.
export const hostPort = (host: string, port: number) => (host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`);

// routeAddress is where a route is reached: its hostnames, or its public port at each public
// hostname of its gateway group, given as groupHosts; only the port while the group has none (D79).
// A hostname the group lists twice gives one address.
export function routeAddress(r: Route, groupHosts: readonly string[] = []): string[] {
  switch (r.spec.case) {
    case "http": {
      const { hostnames, pathPrefix } = r.spec.value;
      return hostnames.map((h) => h + pathPrefix);
    }
    case "tlsPassthrough":
      return r.spec.value.hostnames;
    case "tcp":
    case "udp":
    case "tcpUdp": {
      const { port } = r.spec.value;
      if (!port) {
        return [];
      }
      return groupHosts.length > 0 ? [...new Set(groupHosts)].map((h) => hostPort(h, port)) : [`:${port}`];
    }
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

// shellArg quotes a value for a POSIX shell, unless it needs no quotes; brackets are quoted, as
// zsh and bash would take [fd00::1]:443 as a pattern.
export function shellArg(s: string): string {
  return /^[A-Za-z0-9_.:/@%+=,-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

// ownPort ends the readiness detail of a target that is one of rpmgr's own ports, which the
// all-in-one's connector never dials (ADR-0019; internal/policy OwnPort).
export const ownPort = " is one of rpmgr's own ports";

// policyCommand is the command that lets a connector's local policy reach a target it blocks
// (docs/04-security.md, "Connector-local policy"; docs/09-web-ui.md, U4), from the readiness
// detail: allow-target for a target nothing allows, remove-deny-target for the entry of
// deny_targets that refuses it, which the detail names after " denied by " (D84). No command lets
// the all-in-one's connector reach one of rpmgr's own ports: undefined.
export function policyCommand(detail: string): string | undefined {
  if (detail.endsWith(ownPort)) return undefined;
  const at = detail.lastIndexOf(" denied by ");
  return at < 0 ? `sudo rpmgr policy allow-target ${shellArg(detail)}`
    : `sudo rpmgr policy remove-deny-target ${shellArg(detail.slice(at + " denied by ".length))}`;
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

// useGateways reads all gateways of the org in service.
export function useGateways(orgId: string | undefined) {
  const transport = useTransport();
  return useQuery({
    queryKey: ["gateways", orgId],
    enabled: !!orgId,
    queryFn: () => {
      const api = createClient(GatewayService, transport);
      return listAll(async (pageToken) => {
        const r = await api.listGateways({ orgId, pageSize: largestPage, pageToken });
        return { items: r.gateways, next: r.nextPageToken };
      });
    },
  });
}

// useGroups reads all gateway groups of the org.
export function useGroups(orgId: string | undefined) {
  return useGroupsAs(orgId, (gs) => gs);
}

// useGroupsAs reads all gateway groups of the org, in one request that useGroups, useGroupNames and
// useGroupHostnames share, and gives them as select makes them.
function useGroupsAs<T>(orgId: string | undefined, select: (groups: GatewayGroup[]) => T) {
  const transport = useTransport();
  return useQuery({
    queryKey: ["gateway-groups", orgId],
    enabled: !!orgId,
    queryFn: () => {
      const api = createClient(GatewayService, transport);
      return listAll(async (pageToken) => {
        const r = await api.listGatewayGroups({ orgId, pageSize: largestPage, pageToken });
        return { items: r.gatewayGroups, next: r.nextPageToken };
      });
    },
    select,
  });
}
