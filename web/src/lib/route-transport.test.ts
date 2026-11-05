// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import type { TFunction } from "i18next";
import { describe, expect, it } from "vitest";
import { DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import { RouteSchema, TargetTransportSchema, TransportPin } from "@/gen/rpmgr/v1/route_pb";
import { groupLabel, inProcessNote, routeInProcessNote, routeTransports, targetGroups } from "@/lib/route-transport";

describe("route transports", () => {
  it("groups a target's gateways by transport, QUIC first, and leaves a target without gateways out", () => {
    const tt = create(TargetTransportSchema, { targetId: "t", pinnedBy: TransportPin.UNSPECIFIED, gateways: [
      { gatewayId: "g3", transport: DataTransport.H2 }, { gatewayId: "g1", transport: DataTransport.QUIC }, { gatewayId: "g2" },
      { gatewayId: "g4", transport: DataTransport.QUIC }] });
    expect(targetGroups(tt)).toEqual([{ key: "quic", gateways: ["g1", "g4"] }, { key: "h2", gateways: ["g3"] }, { key: "unknown", gateways: ["g2"] }]);
    expect(targetGroups(create(TargetTransportSchema, { targetId: "t" }))).toEqual([]);
    expect(targetGroups(undefined)).toEqual([]);
  });

  it("counts a target under every transport it is served over, and nothing for a route without a status", () => {
    const r = create(RouteSchema, { status: { targetTransports: [
      { targetId: "a", gateways: [{ gatewayId: "g1", transport: DataTransport.QUIC }, { gatewayId: "g2", transport: DataTransport.H2 }] },
      { targetId: "b", gateways: [{ gatewayId: "g1", transport: DataTransport.H2 }] }] } });
    expect(routeTransports(r)).toEqual([{ key: "quic", count: 1 }, { key: "h2", count: 2 }]);
    expect(routeTransports(create(RouteSchema, {}))).toEqual([]);
  });

  it("names the built-in connector's in-memory session as such, never as pinned", () => {
    const tt = create(TargetTransportSchema, { targetId: "t", pinnedBy: TransportPin.ROUTE, gateways: [
      { gatewayId: "g1", transport: DataTransport.IN_PROCESS }] });
    expect(targetGroups(tt)).toEqual([{ key: "inProcess", gateways: ["g1"] }]);
    expect(routeTransports(create(RouteSchema, { status: { targetTransports: [tt] } }))).toEqual([{ key: "inProcess", count: 1 }]);
    const t = ((k: string) => k) as TFunction;
    expect(groupLabel("inProcess", TransportPin.ROUTE, t)).toBe("transport.inProcess");
    expect(groupLabel("quic", TransportPin.ROUTE, t)).toBe("transport.pinned");
  });

  it("explains a built-in target, naming the setting that does not apply to it, and says it once on the route", () => {
    const t = ((k: string, o?: { pin?: string }) => `${k}${o?.pin ? `:${o.pin}` : ""}`) as TFunction;
    const builtIn = (pinned: DataTransport) => create(TargetTransportSchema, { targetId: "t", pinnedTransport: pinned,
      pinnedBy: pinned === DataTransport.UNSPECIFIED ? TransportPin.UNSPECIFIED : TransportPin.ROUTE,
      gateways: [{ gatewayId: "g1", transport: DataTransport.IN_PROCESS }] });
    expect(inProcessNote(builtIn(DataTransport.QUIC), t)).toBe("transport.inProcessPinnedNote:transport.name.quic");
    expect(inProcessNote(builtIn(DataTransport.UNSPECIFIED), t)).toBe("transport.inProcessNote");
    const external = create(TargetTransportSchema, { targetId: "e", pinnedTransport: DataTransport.QUIC, pinnedBy: TransportPin.ROUTE,
      gateways: [{ gatewayId: "g1", transport: DataTransport.QUIC }] });
    expect(inProcessNote(external, t)).toBe("");
    expect(inProcessNote(undefined, t)).toBe("");
    const route = (...targets: ReturnType<typeof builtIn>[]) => create(RouteSchema, { status: { targetTransports: targets } });
    expect(routeInProcessNote(route(builtIn(DataTransport.QUIC), external), t)).toBe("transport.inProcessRouteNote");
    expect(routeInProcessNote(route(builtIn(DataTransport.UNSPECIFIED)), t)).toBe("");
    expect(routeInProcessNote(route(external), t)).toBe("");
  });
});
