// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";
import { CertificateSchema, CertificateSource } from "@/gen/rpmgr/v1/certificate_pb";
import { covers, fitting } from "@/route-form/certificate-select";

describe("covers", () => {
  it.each([
    ["wiki.example.com", "wiki.example.com", true],
    ["*.example.com", "wiki.example.com", true],
    ["*.example.com", "example.com", false], // not the wildcard's parent
    ["*.example.com", "a.b.example.com", false], // one label only
    ["*.example.com", ".example.com", false], // an empty label
    ["*.example.com", "*.example.com", true],
    ["*.example.com", "*.a.example.com", false], // a wildcard hostname by the same wildcard only
    ["wiki.example.com", "*.example.com", false],
    ["wiki.example.com", "docs.example.com", false],
  ])("%s covers %s: %s", (san, name, want) => {
    expect(covers(san, name)).toBe(want);
  });
});

describe("fitting", () => {
  const cert = (id: string, sans: string[], source = CertificateSource.UPLOADED) => create(CertificateSchema, { id, sans, source });
  const certs = [cert("crt_idn", ["xn--bcher-kva.example"]), cert("crt_wild", ["*.example.com"]), cert("crt_acme", ["*.example.com"], CertificateSource.ACME)];

  it.each([
    ["", ["crt_idn", "crt_wild"]], // no hostname yet: every uploaded one
    ["\n  \n", ["crt_idn", "crt_wild"]],
    ["Bücher.example.", ["crt_idn"]], // an international name in its ASCII form, without the trailing dot
    ["WIKI.example.com\ndocs.example.com", ["crt_wild"]],
    ["wiki.example.com\nbücher.example", []],
    ["not a name/", []],
  ])("for %j: %j", (hostnames, want) => {
    expect(fitting(certs, hostnames).map((c) => c.id)).toEqual(want);
  });
});
