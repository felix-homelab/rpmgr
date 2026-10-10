// SPDX-License-Identifier: Apache-2.0

import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

// cn joins class names, the later Tailwind class winning over a conflicting earlier one.
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
