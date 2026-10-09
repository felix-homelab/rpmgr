// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { ErrorInfoSchema, RetryInfoSchema } from "@/gen/google/rpc/error_details_pb";

// The reasons of the API's errors (docs/07-api.md, "Errors").
export const Reason = {
  mfaRequired: "MFA_REQUIRED",
  stepUpRequired: "STEP_UP_REQUIRED",
  permissionMissing: "PERMISSION_MISSING",
  restoreReview: "RESTORE_REVIEW",
} as const;

// reasonOf returns the reason of an API error, from its google.rpc.ErrorInfo of domain rpmgr.v1.
export function reasonOf(err: unknown): string | undefined {
  return ConnectError.from(err)
    .findDetails(ErrorInfoSchema)
    .find((d) => d.domain === "rpmgr.v1")?.reason;
}

// refusedInReview reports whether the API refused a change because its org or the instance is in
// restore review (docs/10-operations.md, "Backup and restore").
export function refusedInReview(err: unknown): boolean {
  return ConnectError.from(err).code === Code.FailedPrecondition && reasonOf(err) === Reason.restoreReview;
}

// retryAfter returns in how many seconds a rate-limited call may be retried, from its
// google.rpc.RetryInfo, rounded up.
export function retryAfter(err: unknown): number | undefined {
  const delay = ConnectError.from(err).findDetails(RetryInfoSchema)[0]?.retryDelay;
  return delay ? Math.ceil(Number(delay.seconds) + delay.nanos / 1e9) : undefined;
}
