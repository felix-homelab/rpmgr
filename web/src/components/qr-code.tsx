// SPDX-License-Identifier: Apache-2.0

import { encode } from "uqr";

// QRCode draws text as a QR code in SVG: one path, so nothing is injected that the CSP refuses.
export function QRCode({ text, label }: { text: string; label: string }) {
  const { data, size } = encode(text, { ecc: "M", border: 2 });
  let d = "";
  data.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) {
        d += `M${x} ${y}h1v1h-1z`;
      }
    }),
  );
  return (
    <svg role="img" aria-label={label} viewBox={`0 0 ${size} ${size}`} className="h-48 w-48 bg-white" shapeRendering="crispEdges">
      <path d={d} fill="#000" />
    </svg>
  );
}
