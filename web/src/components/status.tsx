// SPDX-License-Identifier: Apache-2.0

import { CircleCheck, CircleHelp, CircleOff, CircleX, Hourglass, TriangleAlert, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Badge, type Tone } from "@/components/ui/badge";

// The looks of a state: an icon and a tone, always next to the state's name, so that no state is
// told by colour alone (docs/09-web-ui.md, U8).
const looks = {
  ok: [CircleCheck, "ok"],
  pending: [Hourglass, "neutral"],
  off: [CircleOff, "neutral"],
  warn: [TriangleAlert, "warn"],
  alert: [TriangleAlert, "danger"],
  failed: [CircleX, "danger"],
  unknown: [CircleHelp, "neutral"],
} as const satisfies Record<string, readonly [LucideIcon, Tone]>;

export type Look = keyof typeof looks;

// Status is a state as a badge: its icon, hidden from screen readers, and its name.
export function Status({ look, children }: { look: Look; children: ReactNode }) {
  const [Icon, tone] = looks[look];
  return (
    <Badge tone={tone}>
      <Icon aria-hidden="true" />
      {children}
    </Badge>
  );
}
