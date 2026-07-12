import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  fetchNodes: vi.fn(),
  fetchEdges: vi.fn(),
  fetchFindings: vi.fn(),
  fetchProjectionState: vi.fn(),
}));

vi.mock("@entities/node/api", () => ({
  fetchNodeCollection: mocks.fetchNodes,
}));

vi.mock("@entities/edge/api", () => ({
  fetchEdgeCollection: mocks.fetchEdges,
}));

vi.mock("@entities/finding/api", () => ({
  fetchAllFindings: mocks.fetchFindings,
}));

vi.mock("@entities/posture/api", () => ({
  fetchProjectionState: mocks.fetchProjectionState,
}));

import {
  ExplorerPublicationError,
  fetchExplorerGraph,
} from "../useExplorerGraph";

function findingScope(scanId = "scan-1", revision = 1) {
  return {
    mode: "published" as const,
    scanId,
    revision,
    publishedAt: "2026-07-11T00:00:00Z",
    projectionStatus: "complete",
    snapshotStatus: "complete",
    available: true,
    stale: false,
  };
}

function projectionState(scanId = "scan-1", revision = 1) {
  return {
    status: "complete" as const,
    scan_id: scanId,
    dirty_coverage: [],
    updated_at: "2026-07-11T00:00:00Z",
    published_scan_id: scanId,
    published_revision: revision,
    published_at: "2026-07-11T00:00:00Z",
  };
}

describe("fetchExplorerGraph publication coherence", () => {
  beforeEach(() => {
    mocks.fetchNodes.mockReset().mockResolvedValue({
      items: [],
      total: 0,
      complete: true,
      revision: "graph-revision",
      projection: { scanId: "scan-1", revision: 1 },
    });
    mocks.fetchEdges.mockReset().mockResolvedValue({
      items: [],
      total: 0,
      complete: true,
      revision: "graph-revision",
      projection: { scanId: "scan-1", revision: 1 },
    });
    mocks.fetchFindings.mockReset().mockResolvedValue({
      findings: [],
      scope: findingScope(),
    });
    mocks.fetchProjectionState.mockReset().mockResolvedValue(
      projectionState(),
    );
  });

  it("returns graph data only when all four sources share one publication", async () => {
    await expect(fetchExplorerGraph()).resolves.toMatchObject({
      publication: { scanId: "scan-1", revision: 1 },
      findingScope: { scanId: "scan-1", revision: 1 },
      projectionState: {
        published_scan_id: "scan-1",
        published_revision: 1,
      },
      collection: { complete: true, revision: "graph-revision" },
    });
  });

  it.each([
    {
      source: "edges",
      mutate: () =>
        mocks.fetchEdges.mockResolvedValue({
          items: [],
          total: 0,
          complete: true,
          revision: "graph-revision",
          projection: { scanId: "scan-2", revision: 2 },
        }),
    },
    {
      source: "findings",
      mutate: () =>
        mocks.fetchFindings.mockResolvedValue({
          findings: [],
          scope: findingScope("scan-2", 2),
        }),
    },
    {
      source: "projection state",
      mutate: () =>
        mocks.fetchProjectionState.mockResolvedValue(
          projectionState("scan-2", 2),
        ),
    },
  ])("rejects a mixed publication from $source", async ({ mutate }) => {
    mutate();

    await expect(fetchExplorerGraph()).rejects.toBeInstanceOf(
      ExplorerPublicationError,
    );
  });

  it("rejects matching identities when the finding snapshot is stale", async () => {
    mocks.fetchFindings.mockResolvedValue({
      findings: [],
      scope: { ...findingScope(), stale: true },
    });

    await expect(fetchExplorerGraph()).rejects.toThrow(
      "finding snapshot is unavailable, stale, or incomplete",
    );
  });
});
