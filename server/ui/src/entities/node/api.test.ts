import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectionConflictError } from "@shared/api/conflicts";
import { fetchNodeCollection } from "./api";

const getMock = vi.hoisted(() => vi.fn());

vi.mock("@shared/api/client", () => ({
  api: { get: getMock },
}));

function pageResponse(
  body: unknown,
  {
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
  },
): Response {
  return new Response(JSON.stringify({
    nodes: body,
    page: {
      offset,
      limit: 2,
      total,
      has_more: hasMore,
      complete: !hasMore,
      revision,
      projection: {
        scan_id: projectionScanId,
        revision: projectionRevision,
      },
    },
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
    },
  });
}

function node(id: string) {
  return { id, kinds: ["MCPServer"], properties: { name: id } };
}

describe("fetchNodeCollection", () => {
  beforeEach(() => {
    getMock.mockReset();
  });

  it("iterates every stable page and forwards the revision token", async () => {
    getMock
      .mockResolvedValueOnce(
        pageResponse([node("a"), node("b")], {
          offset: 0,
          total: 3,
          hasMore: true,
        }),
      )
      .mockResolvedValueOnce(
        pageResponse([node("c")], {
          offset: 2,
          total: 3,
          hasMore: false,
        }),
      );

    const result = await fetchNodeCollection(undefined, 2);

    expect(result.complete).toBe(true);
    expect(result.items.map((item) => item.id)).toEqual(["a", "b", "c"]);
    expect(result.projection).toEqual({ scanId: "scan-1", revision: 1 });
    expect(getMock).toHaveBeenCalledTimes(2);
    expect(getMock.mock.calls[1]?.[1]?.searchParams).toMatchObject({
      offset: "2",
      revision: "rev-1",
    });
  });

  it("rejects malformed non-array responses instead of treating them as empty", async () => {
    getMock.mockResolvedValueOnce(
      pageResponse({}, { offset: 0, total: 0, hasMore: false }),
    );

    await expect(fetchNodeCollection()).rejects.toThrow(/must be an array/);
  });

  it("aborts a paginated collection when publication identity changes", async () => {
    getMock
      .mockResolvedValueOnce(
        pageResponse([node("a"), node("b")], {
          offset: 0,
          total: 3,
          hasMore: true,
          projectionScanId: "scan-1",
          projectionRevision: 1,
        }),
      )
      .mockResolvedValueOnce(
        pageResponse([node("c")], {
          offset: 2,
          total: 3,
          hasMore: false,
          projectionScanId: "scan-2",
          projectionRevision: 2,
        }),
      );

    await expect(fetchNodeCollection(undefined, 2)).resolves.toMatchObject({
      complete: false,
      incompleteReason: "projection-changed",
      projection: { scanId: "scan-1", revision: 1 },
    });
  });

  it("does not decode a projection conflict as a graph-page conflict", async () => {
    getMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: {
            code: "PROJECTION_CONFLICT",
            message: "stable published projection unavailable",
            details: { actual_revision: 2 },
          },
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );

    await expect(fetchNodeCollection()).rejects.toBeInstanceOf(
      ProjectionConflictError,
    );
  });
});
