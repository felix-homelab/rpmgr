// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { bytes, dayMs, filled, hourMs, totals, TotalsLine, TrafficChart } from "@/components/traffic";
import { TrafficBucketSchema } from "@/gen/rpmgr/v1/metrics_pb";

afterEach(cleanup);

const bucket = (iso: string, bytesIn: bigint, bytesOut: bigint, connections = 1n, errors = 0n) =>
  create(TrafficBucketSchema, { start: timestampFromDate(new Date(iso)), bytesIn, bytesOut, connections, errors });

// open opens a chart's table, as a click on its summary does in a browser.
function open() {
  const details = screen.getByText("Show the values as a table").closest("details")!;
  details.open = true;
  fireEvent(details, new Event("toggle"));
}

describe("bytes", () => {
  it("counts in decimal units, with one decimal below 100", () => {
    expect([0, 999, 1000, 1234, 99_949, 150_000, 1_234_567, 2_500_000_000, 10n ** 18n].map((n) => bytes(n))).toEqual([
      "0 B", "999 B", "1 kB", "1.2 kB", "99.9 kB", "150 kB", "1.2 MB", "2.5 GB", "1,000 PB",
    ]);
  });
});

describe("totals", () => {
  it("adds buckets up, beyond what a JavaScript number holds exactly", () => {
    const big = 2n ** 60n;
    expect(totals([bucket("2026-10-09T10:00:00Z", big, 1n, 2n, 1n), bucket("2026-10-09T11:00:00Z", big, 2n, 3n, 0n)]))
      .toEqual({ in: 2n * big, out: 3n, connections: 5n, errors: 1n });
    expect(totals([])).toEqual({ in: 0n, out: 0n, connections: 0n, errors: 0n });
  });
});

describe("TrafficChart", () => {
  it("has a table of every bucket, made when it is opened", () => {
    render(<TrafficChart buckets={[bucket("2026-10-09T10:00:00Z", 1500n, 20n, 3n, 1n), bucket("2026-10-09T11:00:00Z", 0n, 0n, 0n)]} />);
    expect(screen.queryByRole("table")).toBeNull();
    open();
    const rows = within(screen.getByRole("table")).getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell").slice(1).map((c) => c.textContent));
    expect(rows).toEqual([["1.5 kB", "20 B", "3", "1"], ["0 B", "0 B", "0", "0"]]);
  });

  it("says when there was no traffic instead of drawing nothing", () => {
    render(<TrafficChart buckets={[]} />);
    expect(screen.getByText("No traffic in this period.")).toBeTruthy();
    expect(screen.queryByText("Show the values as a table")).toBeNull();
  });
});

describe("TotalsLine", () => {
  it("counts connections and errors in the singular and the plural", () => {
    render(<TotalsLine t={{ in: 1n, out: 2_000n, connections: 1n, errors: 12_345n }} />);
    expect(screen.getByText("In 1 B · out 2 kB · 1 connection · 12,345 errors")).toBeTruthy();
  });
});

describe("filled", () => {
  const ms = (iso: string) => new Date(iso).getTime();
  const starts = (bs: { start?: { seconds: bigint } }[]) => bs.map((b) => new Date(Number(b.start!.seconds) * 1000).toISOString());

  it("puts empty buckets where the API sent none, from the step that holds from", () => {
    const sent = [bucket("2026-10-09T11:00:00Z", 7n, 0n)];
    const out = filled(sent, ms("2026-10-09T09:30:00Z"), ms("2026-10-09T12:00:00Z"), hourMs);
    expect(starts(out)).toEqual(["2026-10-09T09:00:00.000Z", "2026-10-09T10:00:00.000Z", "2026-10-09T11:00:00.000Z"]);
    expect(out.map((b) => b.bytesIn)).toEqual([0n, 0n, 7n]);
    expect(out[2]).toBe(sent[0]);
  });

  it("counts days in UTC and ends before end", () => {
    const out = filled([], ms("2026-10-07T23:59:59Z"), ms("2026-10-09T00:00:00Z"), dayMs);
    expect(starts(out)).toEqual(["2026-10-07T00:00:00.000Z", "2026-10-08T00:00:00.000Z"]);
    expect(filled([], ms("2026-10-09T10:00:00Z"), ms("2026-10-09T10:00:00Z"), hourMs)).toEqual([]);
  });
});
