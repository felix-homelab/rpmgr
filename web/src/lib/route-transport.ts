// SPDX-License-Identifier: Apache-2.0

import type { TFunction } from "i18next";
import { DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import { TransportPin, type Route, type TargetTransport } from "@/gen/rpmgr/v1/route_pb";

// The transport each target of a route is served over, as the route's status reports it per
// gateway (docs/03-connections.md, "Transport selection"). Nothing is derived here.

// TransportKey names a transport; "unknown" is a gateway that does not report it, as one of an
// earlier release does not.
export type TransportKey = "quic" | "h2" | "wss" | "inProcess" | "unknown";

const keys: Partial<Record<DataTransport, TransportKey>> = {
  [DataTransport.QUIC]: "quic",
  [DataTransport.H2]: "h2",
  [DataTransport.WSS]: "wss",
  [DataTransport.IN_PROCESS]: "inProcess",
};

export const transportKeys: TransportKey[] = ["quic", "h2", "wss", "inProcess", "unknown"];

// TransportGroup is the gateways a target is served over one transport through.
export interface TransportGroup {
  key: TransportKey;
  gateways: string[];
}

// targetGroups groups a target's gateways by transport, in the order QUIC, HTTP/2, WSS, in process, unknown.
// None: the target does not serve, or its connector is offline.
export function targetGroups(tt?: TargetTransport): TransportGroup[] {
  const out: TransportGroup[] = [];
  for (const k of transportKeys) {
    const gateways = (tt?.gateways ?? []).filter((g) => (keys[g.transport] ?? "unknown") === k).map((g) => g.gatewayId);
    if (gateways.length > 0) {
      out.push({ key: k, gateways });
    }
  }
  return out;
}

// routeTransports counts the route's targets per transport; a target served over two counts under
// each. Entries with no count are left out.
export function routeTransports(r: Route): { key: TransportKey; count: number }[] {
  const count = new Map<TransportKey, number>();
  for (const tt of r.status?.targetTransports ?? []) {
    for (const g of targetGroups(tt)) {
      count.set(g.key, (count.get(g.key) ?? 0) + 1);
    }
  }
  return transportKeys.filter((k) => count.has(k)).map((key) => ({ key, count: count.get(key)! }));
}

// summary is "QUIC 1 · HTTP/2 1", or "" while no target is served.
export function transportSummary(r: Route, t: TFunction): string {
  return routeTransports(r).map((e) => `${t(`transport.name.${e.key}`)} ${e.count}`).join(" · ");
}

const pinKeys: Record<TransportPin, string> = {
  [TransportPin.UNSPECIFIED]: "",
  [TransportPin.ROUTE]: "route",
  [TransportPin.CONNECTOR]: "connector",
  [TransportPin.INSTANCE]: "instance",
};

// groupLabel names a transport as the target takes it: pinned, with where the pin is set, or on
// auto the winner, which names QUIC alone and says the others are fallbacks.
export function groupLabel(key: TransportKey, pin: TransportPin, t: TFunction): string {
  const name = t(`transport.name.${key}`);
  if (key === "unknown") {
    return name;
  }
  // The built-in connector reaches its own gateway in memory, whatever any pin says.
  if (key === "inProcess") {
    return t("transport.inProcess");
  }
  if (pin !== TransportPin.UNSPECIFIED) {
    return t("transport.pinned", { name, where: t(`transport.pin.${pinKeys[pin]}`) });
  }
  return key === "quic" ? name : t(`transport.fallback.${key}`, { name });
}

// pinnedName names the transport the target's pin sets, "QUIC", "HTTP/2" or "WSS"; "" on auto.
export function pinnedName(tt: TargetTransport | undefined, t: TFunction): string {
  const key = keys[tt?.pinnedTransport ?? DataTransport.UNSPECIFIED];
  return key === undefined || key === "inProcess" ? "" : t(`transport.name.${key}`);
}

// inProcessNote explains a target served by the all-in-one's built-in connector, which no
// transport setting applies to; "" for any other target. The setting is named where there is one.
export function inProcessNote(tt: TargetTransport | undefined, t: TFunction): string {
  if (!targetGroups(tt).some((g) => g.key === "inProcess")) {
    return "";
  }
  const pin = pinnedName(tt, t);
  return pin === "" ? t("transport.inProcessNote") : t("transport.inProcessPinnedNote", { pin });
}

// routeInProcessNote is the note of a route with a transport setting and built-in targets.
export function routeInProcessNote(r: Route, t: TFunction): string {
  const targets = r.status?.targetTransports ?? [];
  const pinned = targets.some((tt) => pinnedName(tt, t) !== "");
  return pinned && targets.some((tt) => targetGroups(tt).some((g) => g.key === "inProcess")) ? t("transport.inProcessRouteNote") : "";
}
