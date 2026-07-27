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

vi.mock("@entities/posture/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@entities/posture/api")>();
  return {
    ...actual,
    fetchProjectionState: mocks.fetchProjectionState,
  };
});

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
    coverageLimited: false,
    activeCoverageLimitations: [],
  };
}

function projectionState(scanId = "scan-1", revision = 1) {
  return {
    status: "complete" as const,
    scan_id: scanId,
    dirty_coverage: [],
    active_coverage_roots: [],
    active_coverage_limitations: [],
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
      projection: {
        scanId: "scan-1",
        revision: 1,
        coverageLimited: false,
        coverageLimitationCount: 0,
      },
    });
    mocks.fetchEdges.mockReset().mockResolvedValue({
      items: [],
      total: 0,
      complete: true,
      revision: "graph-revision",
      projection: {
        scanId: "scan-1",
        revision: 1,
        coverageLimited: false,
        coverageLimitationCount: 0,
      },
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
      publication: {
        scanId: "scan-1",
        revision: 1,
        coverageLimited: false,
        coverageLimitationCount: 0,
      },
      findingScope: { scanId: "scan-1", revision: 1 },
      projectionState: {
        published_scan_id: "scan-1",
        published_revision: 1,
      },
      collection: {
        complete: true,
        coverageLimited: false,
        revision: "graph-revision",
      },
    });
  });

  it("keeps a limited graph usable while withholding absence verdicts", async () => {
    const limitation = {
      coverageKey: "mcp:target:sha256:limited",
      state: "partial" as const,
      scanId: "scan-1",
      observedAt: "2026-07-11T00:00:00Z",
    };
    const limitedProjection = {
      scanId: "scan-1",
      revision: 1,
      coverageLimited: true,
      coverageLimitationCount: 1,
    };
    mocks.fetchNodes.mockResolvedValue({
      items: [],
      total: 0,
      complete: true,
      revision: "graph-revision",
      projection: limitedProjection,
    });
    mocks.fetchEdges.mockResolvedValue({
      items: [],
      total: 0,
      complete: true,
      revision: "graph-revision",
      projection: limitedProjection,
    });
    mocks.fetchFindings.mockResolvedValue({
      findings: [],
      scope: {
        ...findingScope(),
        coverageLimited: true,
        activeCoverageLimitations: [limitation],
      },
    });
    mocks.fetchProjectionState.mockResolvedValue({
      ...projectionState(),
      active_coverage_limitations: [
        {
          coverage_key: limitation.coverageKey,
          state: limitation.state,
          scan_id: limitation.scanId,
          observed_at: limitation.observedAt,
        },
      ],
    });

    await expect(fetchExplorerGraph()).resolves.toMatchObject({
      nodes: [],
      edges: [],
      collection: {
        complete: false,
        coverageLimited: true,
        incompleteReason: expect.stringContaining(
          "absence-based conclusions are withheld",
        ),
      },
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
          projection: {
            scanId: "scan-2",
            revision: 2,
            coverageLimited: false,
            coverageLimitationCount: 0,
          },
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
