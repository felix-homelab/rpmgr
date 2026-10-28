// SPDX-License-Identifier: Apache-2.0

import type { DescMessage, MessageInitShape } from "@bufbuild/protobuf";
import { create } from "@bufbuild/protobuf";
import { pathToString } from "@bufbuild/protobuf/reflect";
import { ConnectError } from "@connectrpc/connect";
import { createValidator } from "@bufbuild/protovalidate";
import type { TFunction } from "i18next";
import { ViolationsSchema } from "@/gen/buf/validate/validate_pb";

const validator = createValidator();

// namePattern is the rule of every resource name (docs/07-api.md, "Resource names").
const namePattern = "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$";

// snake turns a field's name into its proto spelling, "displayName" into "display_name".
const snake = (s: string) => s.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);

// readable says what a protovalidate violation means for a person; the rule of a resource name
// is named in words, any other message is the validator's own.
function readable(t: TFunction, message: string): string {
  return message.includes(namePattern) ? t("violations.name") : message;
}

// fieldLabel names the field a violation is about by the last name of its path.
function fieldLabel(t: TFunction, field: string): string {
  const words = field.replaceAll("_", " ");
  return t(`violations.fields.${field}`, { defaultValue: words.charAt(0).toUpperCase() + words.slice(1) });
}

// A Problems maps a field, by its proto name ("name", "display_name"), to what is wrong with it.
export type Problems = Record<string, string>;

// checkRequest validates the request a form is about to send with the protovalidate rules of the
// server, so that a wrong value is shown before anything is sent. It reports only the fields
// listed in shown: a violation of any other field, or of a rule the browser cannot compile,
// passes here for the server to report.
export function checkRequest<D extends DescMessage>(t: TFunction, schema: D, init: MessageInitShape<D>, shown: string[]): Problems {
  const result = validator.validate(schema, create(schema, init));
  const problems: Problems = {};
  if (result.kind === "invalid") {
    for (const v of result.violations) {
      const field = snake(pathToString(v.field).split(".").pop()?.replace(/\[.*$/, "") ?? "");
      if (shown.includes(field) && !problems[field]) {
        problems[field] = readable(t, v.message);
      }
    }
  }
  return problems;
}

// violationsOf reads the field violations of an INVALID_ARGUMENT answer, which come as
// buf.validate.Violations (docs/07-api.md, "Errors"), as the last name of each path and its text.
function violationsOf(t: TFunction, err: unknown): [string, string][] {
  return ConnectError.from(err)
    .findDetails(ViolationsSchema)
    .flatMap((vs) => vs.violations.map((v): [string, string] => [v.field?.elements.at(-1)?.fieldName ?? "", readable(t, v.message)]));
}

// serverProblems maps the violations the API reported to the fields they are about.
export function serverProblems(t: TFunction, err: unknown): Problems {
  const problems: Problems = {};
  for (const [field, message] of violationsOf(t, err)) {
    if (field && !problems[field]) {
      problems[field] = message;
    }
  }
  return problems;
}

// apiError is the text of an API error for a form's alert. An answer with field violations says
// which field is wrong, "Name: use 1 to 63 lowercase letters, ...", instead of the generic
// message; the fields a form shows itself, named in shown, are left out, and the text is empty
// when no other violation is left. Any other error is its message.
export function apiError(t: TFunction, err: unknown, shown: string[] = []): string {
  const violations = violationsOf(t, err);
  if (violations.length === 0) {
    return ConnectError.from(err).rawMessage;
  }
  return violations
    .filter(([field]) => !shown.includes(field))
    .map(([field, message]) => (field ? `${fieldLabel(t, field)}: ${message}` : message))
    .join("; ");
}
