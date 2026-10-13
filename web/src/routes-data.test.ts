// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";
import { RouteSchema } from "@/gen/rpmgr/v1/route_pb";
import { hostPort, routeAddress } from "@/routes-data";

const tcp = (port: number) => create(RouteSchema, { spec: { case: "tcp", value: { port } } });

describe("routeAddress", () => {
  it("gives a TCP or UDP route's port at each public hostname of its gateway group (D79)", () => {
    expect(routeAddress(tcp(25432), ["edge.example.com", "203.0.113.7"])).toEqual(["edge.example.com:25432", "203.0.113.7:25432"]);
    expect(routeAddress(create(RouteSchema, { spec: { case: "udp", value: { port: 53 } } }), ["dns.example.com"])).toEqual(["dns.example.com:53"]);
  });

  it("gives a hostname the group lists twice once", () => {
    expect(routeAddress(tcp(25432), ["edge.example.com", "edge.example.com"])).toEqual(["edge.example.com:25432"]);
  });

  it("puts an IPv6 address in brackets", () => {
    expect(routeAddress(tcp(25432), ["2001:db8::7"])).toEqual(["[2001:db8::7]:25432"]);
  });

  it("gives only the port while the group has no public hostname", () => {
    expect(routeAddress(tcp(25432), [])).toEqual([":25432"]);
    expect(routeAddress(tcp(25432))).toEqual([":25432"]);
  });

  it("gives nothing for a route without a public port", () => {
    expect(routeAddress(tcp(0), ["edge.example.com"])).toEqual([]);
  });

  it("keeps an HTTP or TLS passthrough route's own hostnames, whatever the group's", () => {
    const http = create(RouteSchema, { spec: { case: "http", value: { hostnames: ["app.example.com"], pathPrefix: "/api" } } });
    expect(routeAddress(http, ["edge.example.com"])).toEqual(["app.example.com/api"]);
    const tls = create(RouteSchema, { spec: { case: "tlsPassthrough", value: { hostnames: ["db.example.com"] } } });
    expect(routeAddress(tls, ["edge.example.com"])).toEqual(["db.example.com"]);
  });

  it("gives nothing for a route without a spec", () => {
    expect(routeAddress(create(RouteSchema), ["edge.example.com"])).toEqual([]);
  });
});

describe("hostPort", () => {
  it("joins a name or an IPv4 address with the port, and brackets an IPv6 address", () => {
    expect(hostPort("edge.example.com", 443)).toBe("edge.example.com:443");
    expect(hostPort("203.0.113.7", 443)).toBe("203.0.113.7:443");
    expect(hostPort("::1", 443)).toBe("[::1]:443");
  });
});
