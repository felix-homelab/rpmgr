// SPDX-License-Identifier: Apache-2.0

import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { i18n } from "@/i18n";

// when formats a time of the API for the user's language; "" if it is not set.
export function when(ts: Timestamp | undefined): string {
  return ts ? new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium", timeStyle: "short" }).format(timestampDate(ts)) : "";
}
