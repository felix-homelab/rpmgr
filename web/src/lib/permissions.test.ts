// SPDX-License-Identifier: Apache-2.0

import { getOption, type DescFile } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";
import { authz } from "@/gen/rpmgr/v1/options_pb";
import { instancePermission, orgPermissions } from "@/lib/permissions";

// The generated files of the public API.
const files = Object.values(import.meta.glob<Record<string, unknown>>("../gen/rpmgr/v1/*_pb.ts", { eager: true }))
  .flatMap((m) => Object.values(m))
  .filter((v): v is DescFile => typeof v === "object" && v !== null && (v as DescFile).kind === "file");

describe("permissions", () => {
  it("are the permissions the API's methods name", () => {
    const named = new Set<string>();
    for (const file of files) {
      for (const service of file.services) {
        for (const method of service.methods) {
          named.add(getOption(method, authz).permission);
        }
      }
    }
    expect(files.length).toBeGreaterThan(10);
    named.delete("public");
    named.delete("authenticated");
    expect([...named].sort()).toEqual([...orgPermissions, instancePermission].sort());
  });
});
