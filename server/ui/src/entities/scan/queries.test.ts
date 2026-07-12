import { describe, expect, it } from "vitest";
import type { Scan } from "./model";
import { hasActiveScan } from "./queries";

function scan(status: Scan["status"]): Scan {
  return {
    id: `scan-${status}`,
    collector: "mcp",
    status,
    started_at: "2026-07-11T00:00:00Z",
    submitted: { nodes: 0, edges: 0 },
    write_rows: { nodes: 0, edges: 0 },
    graph_totals: { before: null, after: null },
  };
}

describe("hasActiveScan", () => {
  it("polls only while a scan is pending or running", () => {
    expect(hasActiveScan([scan("completed"), scan("failed")])).toBe(false);
    expect(hasActiveScan([scan("running")])).toBe(true);
    expect(hasActiveScan([scan("pending")])).toBe(true);
  });
});
