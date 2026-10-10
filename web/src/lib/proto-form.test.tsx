// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { FieldDescriptorProto_Type } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useForm } from "react-hook-form";
import { afterEach, describe, expect, it } from "vitest";
import { ViolationsSchema } from "@/gen/buf/validate/validate_pb";
import { UpdateRouteRequestSchema } from "@/gen/rpmgr/v1/route_pb";
import { protoResolver, serverFieldErrors, type FieldOf } from "@/lib/proto-form";

afterEach(cleanup);

interface Values {
  name: string;
  hostnames: string;
}

// The form edits a route's name and HTTP hostnames, one per line.
const toMessage = (v: Values) =>
  create(UpdateRouteRequestSchema, {
    route: { id: "rte_1", name: v.name, spec: { case: "http", value: { hostnames: v.hostnames.split("\n").filter(Boolean) } } },
  });
const fieldOf: FieldOf<Values> = (path) =>
  path === "route.name" ? "name" : path.startsWith("route.http.hostnames") ? "hostnames" : undefined;
const resolve = protoResolver(UpdateRouteRequestSchema, toMessage, fieldOf);

async function check(values: Values) {
  const r = await resolve(values, undefined, { fields: {}, shouldUseNativeValidation: false });
  return Object.fromEntries(Object.entries(r.errors).map(([k, e]) => [k, (e as { type: string }).type]));
}

describe("protoResolver", () => {
  it("checks the message's protovalidate rules and shows them on the fields", async () => {
    expect(await check({ name: "wiki", hostnames: "wiki.example.com" })).toEqual({});
    expect(await check({ name: "Bad_Name", hostnames: "" })).toEqual({ name: "string.pattern", hostnames: "repeated.min_items" });
    expect(await check({ name: "wiki", hostnames: "a.example\na.example" })).toEqual({ hostnames: "repeated.unique" });
  });

  it("leaves a violation no field edits to the server", async () => {
    const resolveName = protoResolver(UpdateRouteRequestSchema, toMessage, (p) => (p === "route.name" ? "name" : undefined));
    const r = await resolveName({ name: "wiki", hostnames: "" }, undefined, { fields: {}, shouldUseNativeValidation: false });
    expect(r.errors).toEqual({});
  });

  it("works as the resolver of a form", async () => {
    function Form() {
      const { register, handleSubmit, formState } = useForm<Values>({ resolver: resolve, defaultValues: { name: "", hostnames: "" } });
      return (
        <form onSubmit={handleSubmit(() => {})}>
          <input aria-label="name" {...register("name")} />
          <p>{formState.errors.name?.message}</p>
          <button type="submit">Save</button>
        </form>
      );
    }
    render(<Form />);
    fireEvent.change(screen.getByLabelText("name"), { target: { value: "UPPER" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/does not match regex pattern/)).toBeTruthy();
  });
});

describe("serverFieldErrors", () => {
  it("maps the server's violations of the request onto the fields", () => {
    const field = (name: string, number: number, type: FieldDescriptorProto_Type) => ({ fieldName: name, fieldNumber: number, fieldType: type });
    const violations = create(ViolationsSchema, {
      violations: [
        { field: { elements: [field("route", 1, FieldDescriptorProto_Type.MESSAGE), field("name", 2, FieldDescriptorProto_Type.STRING)] }, ruleId: "string.pattern", message: "bad name" },
        { field: { elements: [field("route", 1, FieldDescriptorProto_Type.MESSAGE), field("description", 6, FieldDescriptorProto_Type.STRING)] }, message: "too long" },
        { message: "no field" },
      ],
    });
    const err = new ConnectError("invalid", Code.InvalidArgument, undefined, [{ desc: ViolationsSchema, value: violations }]);
    expect(serverFieldErrors(err, UpdateRouteRequestSchema, fieldOf)).toEqual({ fields: [["name", "bad name"]], other: ["too long", "no field"] });
  });
});
