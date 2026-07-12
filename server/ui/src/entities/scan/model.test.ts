import { describe, expect, it } from "vitest";
import {
  comparablePublishedNodeDelta,
  comparablePublishedScans,
  latestCompletedScan,
  latestPublishedScan,
  type Scan,
} from "./model";

function scan(overrides: Partial<Scan>): Scan {
  return {
    id: "scan",
    collector: "scan",
    status: "completed",
    started_at: "2026-07-11T00:00:00Z",
    submitted: { nodes: 1000, edges: 1000 },
    write_rows: { nodes: 1000, edges: 1000 },
    graph_totals: { before: null, after: null },
    ...overrides,
  };
}

describe("published graph comparability", () => {
  it("excludes write rows and mismatched comparison keys", () => {
    const scans = [
      scan({
        id: "current",
        publication_status: "published",
        published_revision: 3,
        comparison_key: "key-a",
        graph_totals: {
          before: null,
          after: { total_nodes: 12, total_edges: 8 },
        },
        comparable_to_scan_id: "previous",
      }),
      scan({
        id: "different-scope",
        publication_status: "superseded",
        published_revision: 2,
        comparison_key: "key-b",
        graph_totals: {
          before: null,
          after: { total_nodes: 500, total_edges: 400 },
        },
      }),
      scan({
        id: "previous",
        publication_status: "superseded",
        published_revision: 1,
        comparison_key: "key-a",
        graph_totals: {
          before: null,
          after: { total_nodes: 10, total_edges: 7 },
        },
      }),
      scan({ id: "partial", status: "completed_with_errors" }),
    ];

    expect(comparablePublishedScans(scans).map((item) => item.id)).toEqual([
      "current",
      "previous",
    ]);
    expect(comparablePublishedNodeDelta(scans)).toBe(2);
  });

  it("withholds a delta without an explicit comparable link", () => {
    expect(
      comparablePublishedNodeDelta([
        scan({
          publication_status: "published",
          published_revision: 1,
          comparison_key: "key-a",
          graph_totals: {
            before: null,
            after: { total_nodes: 12, total_edges: 8 },
          },
        }),
      ]),
    ).toBeNull();
  });
});

describe("scan freshness selection", () => {
  it("selects completion and publication timestamps, not start order", () => {
    const firstByStart = scan({
      id: "started-later",
      started_at: "2026-07-11T11:00:00Z",
      completed_at: "2026-07-11T11:05:00Z",
      publication_status: "published",
      published_at: "2026-07-11T11:06:00Z",
    });
    const completedLater = scan({
      id: "completed-later",
      started_at: "2026-07-11T10:00:00Z",
      completed_at: "2026-07-11T12:00:00Z",
    });
    const publishedLater = scan({
      id: "published-later",
      started_at: "2026-07-11T09:00:00Z",
      completed_at: "2026-07-11T10:00:00Z",
      publication_status: "published",
      published_at: "2026-07-11T12:30:00Z",
    });
    const scans = [firstByStart, completedLater, publishedLater];

    const completed = latestCompletedScan(scans);
    const published = latestPublishedScan(scans);
    expect(completed?.id).toBe("completed-later");
    expect(published?.id).toBe("published-later");
  });
});
