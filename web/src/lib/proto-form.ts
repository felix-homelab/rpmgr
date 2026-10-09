// SPDX-License-Identifier: Apache-2.0

import { type DescMessage, type MessageShape } from "@bufbuild/protobuf";
import { pathToString } from "@bufbuild/protobuf/reflect";
import { ConnectError } from "@connectrpc/connect";
import { createValidator, pathFromViolationProto } from "@bufbuild/protovalidate";
import type { FieldErrors, FieldValues, Path, Resolver } from "react-hook-form";
import { ViolationsSchema } from "@/gen/buf/validate/validate_pb";

const validator = createValidator();

// FieldOf names the form field that shows a violation of the message's field at a path, such as
// "route.http.hostnames[1]"; undefined for a path that no field of the form edits.
export type FieldOf<F extends FieldValues> = (path: string) => Path<F> | undefined;

// protoResolver validates a form with the protovalidate rules of the message it becomes, so that the
// form checks the same rules as the server (docs/09-web-ui.md, "Frontend architecture"). It is for
// quick feedback only: the server's result is authoritative, and a rule the browser cannot compile
// passes here. A violation of a field the form does not edit passes too, for the server to report.
export function protoResolver<F extends FieldValues, D extends DescMessage>(
  schema: D,
  toMessage: (values: F) => MessageShape<D>,
  fieldOf: FieldOf<F>,
): Resolver<F> {
  return (values) => {
    const result = validator.validate(schema, toMessage(values));
    const errors: Record<string, { type: string; message: string }> = {};
    if (result.kind === "invalid") {
      for (const v of result.violations) {
        const field = fieldOf(pathToString(v.field));
        if (field && !errors[field]) {
          errors[field] = { type: v.ruleId, message: v.message };
        }
      }
    }
    return Object.keys(errors).length > 0
      ? { values: {}, errors: errors as FieldErrors<F> }
      : { values, errors: {} };
  };
}

// serverFieldErrors maps the field violations of an INVALID_ARGUMENT answer, which come as
// buf.validate.Violations of the request (docs/07-api.md, "Errors"), onto the form's fields; the
// violations no field shows are returned apart.
export function serverFieldErrors<F extends FieldValues>(err: unknown, request: DescMessage, fieldOf: FieldOf<F>) {
  const fields: [Path<F>, string][] = [];
  const other: string[] = [];
  for (const vs of ConnectError.from(err).findDetails(ViolationsSchema)) {
    for (const v of vs.violations) {
      let field: Path<F> | undefined;
      try {
        field = v.field ? fieldOf(pathToString(pathFromViolationProto(request, v.field))) : undefined;
      } catch {
        field = undefined; // a path of another version of the schema
      }
      if (field) {
        fields.push([field, v.message]);
      } else {
        other.push(v.message);
      }
    }
  }
  return { fields, other };
}
