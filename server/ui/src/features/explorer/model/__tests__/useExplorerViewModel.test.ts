import { renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ExplorerRawData } from "../useExplorerGraph";

const mocks = vi.hoisted(() => ({
  useExplorerGraph: vi.fn(),
  useBlastRadius: vi.fn(() => ({
    data: undefined,
    error: null,
    isLoading: false,
  })),
}));

vi.mock("../useExplorerGraph", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../useExplorerGraph")>();
  return { ...actual, useExplorerGraph: mocks.useExplorerGraph };
});

vi.mock("../useBlastRadius", () => ({
  useBlastRadius: mocks.useBlastRadius,
}));

import { useExplorerViewModel } from "../useExplorerViewModel";

const cachedData: ExplorerRawData = {
  nodes: [],
  edges: [],
  findings: [],
  publication: { scanId: "scan-1", revision: 1 },
  findingScope: {
    mode: "published",
    scanId: "scan-1",
    revision: 1,
    publishedAt: "2026-07-11T00:00:00Z",
    projectionStatus: "complete",
    snapshotStatus: "complete",
    available: true,
    stale: false,
  },
  projectionState: {
    status: "complete",
    scan_id: "scan-1",
    dirty_coverage: [],
    updated_at: "2026-07-11T00:00:00Z",
    published_scan_id: "scan-1",
    published_revision: 1,
  },
  collection: {
    complete: true,
    revision: "graph-revision",
    nodeTotal: 0,
    edgeTotal: 0,
  },
};

describe("useExplorerViewModel publication gating", () => {
  it("does not render cached graph data after publication verification fails", () => {
    mocks.useExplorerGraph.mockReturnValue({
      data: cachedData,
      error: new Error("mixed publication"),
      isLoading: false,
    });

    const { result } = renderHook(() => useExplorerViewModel());

    expect(result.current.data).toBeUndefined();
    expect(result.current.render).toBeNull();
    expect(result.current.lensMetrics).toBeNull();
    expect(result.current.error?.message).toBe("mixed publication");
  });
});
