import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectionConflictError } from "@shared/api/conflicts";
import { fetchEdgeCollection } from "./api";

const getMock = vi.hoisted(() => vi.fn());

vi.mock("@shared/api/client", () => ({
  api: { get: getMock },
}));

function pageResponse({
  offset,
  total,
  hasMore,
  revision = "rev-1",
  projectionScanId = "scan-1",
  projectionRevision = 1,
}: {
  offset: number;
  total: number;
  hasMore: boolean;
  revision?: string;
  projectionScanId?: string;
  projectionRevision?: number;
}): Response {
  return new Response(
    JSON.stringify({
      edges: [
        {
          source: `source-${offset}`,
          target: `target-${offset}`,
          kind: "PROVIDES_TOOL",
          properties: {},
        },
      ],
      page: {
        offset,
        limit: 1,
        total,
        has_more: hasMore,
        complete: !hasMore,
        revision,
        projection: {
          scan_id: projectionScanId,
          revision: projectionRevision,
        },
      },
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    },
  );
}

function conflictResponse(code: "REVISION_CONFLICT" | "PROJECTION_CONFLICT") {
  return new Response(
    JSON.stringify({
      error: {
        code,
        message:
          code === "PROJECTION_CONFLICT"
            ? "stable published projection unavailable"
            : "page revision changed",
        details:
          code === "PROJECTION_CONFLICT"
            ? { actual_revision: 2 }
            : { actual_revision: "rev-2" },
      },
    }),
    {
      status: 409,
      headers: { "Content-Type": "application/json" },
    },
  );
}

describe("fetchEdgeCollection", () => {
  beforeEach(() => {
    getMock.mockReset();
  });

  it("preserves one publication identity across stable pages", async () => {
    getMock
      .mockResolvedValueOnce(
        pageResponse({ offset: 0, total: 2, hasMore: true }),
      )
      .mockResolvedValueOnce(
        pageResponse({ offset: 1, total: 2, hasMore: false }),
      );

    await expect(fetchEdgeCollection(undefined, 1)).resolves.toMatchObject({
      complete: true,
      revision: "rev-1",
      projection: { scanId: "scan-1", revision: 1 },
    });
    expect(getMock.mock.calls[1]?.[1]?.searchParams).toMatchObject({
      offset: "1",
      revision: "rev-1",
    });
  });

  it("withholds a collection whose publication changes between pages", async () => {
    getMock
      .mockResolvedValueOnce(
        pageResponse({ offset: 0, total: 2, hasMore: true }),
      )
      .mockResolvedValueOnce(
        pageResponse({
          offset: 1,
          total: 2,
          hasMore: false,
          projectionScanId: "scan-2",
          projectionRevision: 2,
        }),
      );

    await expect(fetchEdgeCollection(undefined, 1)).resolves.toMatchObject({
      complete: false,
      incompleteReason: "projection-changed",
      projection: { scanId: "scan-1", revision: 1 },
    });
  });

  it("distinguishes projection conflicts from graph-page revision conflicts", async () => {
    getMock.mockResolvedValueOnce(conflictResponse("PROJECTION_CONFLICT"));
    await expect(fetchEdgeCollection()).rejects.toBeInstanceOf(
      ProjectionConflictError,
    );

    getMock.mockResolvedValueOnce(conflictResponse("REVISION_CONFLICT"));
    await expect(fetchEdgeCollection()).resolves.toMatchObject({
      complete: false,
      incompleteReason: "revision-changed",
      revision: "rev-2",
      projection: null,
    });
  });
});
