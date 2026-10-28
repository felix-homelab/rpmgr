// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { FieldDescriptorProto_Type } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import type { TFunction } from "i18next";
import { describe, expect, it } from "vitest";
import { ViolationsSchema } from "@/gen/buf/validate/validate_pb";
import { CreateAccessPolicyRequestSchema } from "@/gen/rpmgr/v1/policy_pb";
import en from "@/locales/en.json";
import { apiError, checkRequest, serverProblems } from "@/lib/api-error";

// A stand-in for t that reads the English locale, with i18next's default value.
const t = ((key: string, o?: { defaultValue?: string }) =>
  key.split(".").reduce<unknown>((n, k) => (n as Record<string, unknown> | undefined)?.[k], en) ?? o?.defaultValue ?? key) as TFunction;

const rule = "use 1 to 63 lowercase letters, digits and hyphens, starting and ending with a letter or digit";
const pattern = "value does not match regex pattern `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`";

function invalid(...violations: { path: string[]; message: string }[]) {
  const field = (n: string) => ({ fieldName: n, fieldNumber: 1, fieldType: FieldDescriptorProto_Type.STRING });
  const value = create(ViolationsSchema, { violations: violations.map((v) => ({ field: { elements: v.path.map(field) }, message: v.message })) });
  return new ConnectError("api: the request is not valid", Code.InvalidArgument, undefined, [{ desc: ViolationsSchema, value }]);
}

describe("apiError", () => {
  it("names each field the API found wrong, and says the name rule in words", () => {
    const err = invalid({ path: ["access_policy", "name"], message: pattern }, { path: ["access_policy", "display_name"], message: "too long" });
    expect(apiError(t, err)).toBe(`Name: ${rule}; Display name: too long`);
  });

  it("leaves out the fields the form shows itself, and is empty when none is left", () => {
    const err = invalid({ path: ["name"], message: pattern }, { path: ["region"], message: "too long" });
    expect(apiError(t, err, ["name"])).toBe("Region: too long");
    expect(apiError(t, invalid({ path: ["name"], message: pattern }), ["name"])).toBe("");
  });

  it("is the message of an error without violations", () => {
    expect(apiError(t, new ConnectError("api: the request is not valid", Code.InvalidArgument))).toBe("api: the request is not valid");
    expect(apiError(t, new Error("boom"))).toBe("boom");
  });
});

describe("serverProblems", () => {
  it("maps the last name of a violation's path to its text, the first of a field", () => {
    const err = invalid({ path: ["a", "name"], message: pattern }, { path: ["name"], message: "again" });
    expect(serverProblems(t, err)).toEqual({ name: rule });
    expect(serverProblems(t, new ConnectError("x", Code.Internal))).toEqual({});
  });
});

describe("checkRequest", () => {
  const check = (name: string, shown = ["name"]) => checkRequest(t, CreateAccessPolicyRequestSchema, { orgId: "org_1", accessPolicy: { name } }, shown);
  it("reports the rule of a resource name, for the shown fields only", () => {
    expect(check("Lab")).toEqual({ name: rule });
    expect(check("-lab")).toEqual({ name: rule });
    expect(check("lab_1")).toEqual({ name: rule });
    expect(check("a".repeat(64))).toEqual({ name: rule });
    expect(check("a".repeat(63))).toEqual({});
    expect(check("a")).toEqual({});
    expect(check("lab-1")).toEqual({});
    expect(check("Lab", ["description"])).toEqual({});
  });
});
