// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";
import { DataTransport } from "@/gen/rpmgr/v1/connector_pb";
import { RouteSchema, TargetTransportSchema, TransportPin } from "@/gen/rpmgr/v1/route_pb";
import { routeTransports, targetGroups } from "@/lib/route-transport";

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
});
