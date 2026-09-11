import { beforeEach, describe, expect, it, vi } from "vitest";
import { fetchGraphStats } from "./api";

const getMock = vi.hoisted(() => vi.fn());

vi.mock("@shared/api/client", () => ({
  api: { get: getMock },
}));

function response(body: unknown) {
  return { ok: true, status: 200, json: vi.fn().mockResolvedValue(body) };
}

describe("fetchGraphStats", () => {
  beforeEach(() => {
    getMock.mockReset();
  });

  it("preserves absent publication without inventing empty statistics", async () => {
    getMock.mockReturnValue({ status: 409, ok: false, json: async () => ({
      error: { code: "PROJECTION_CONFLICT", details: { reason: "absent" } },
    }) });
    await expect(fetchGraphStats()).rejects.toMatchObject({ code: "PROJECTION_CONFLICT", reason: "absent" });
  });

  it("decodes the publication identity", async () => {
    getMock.mockReturnValue(
      response({
        node_counts: { MCPServer: 1 },
        edge_counts: {},
        total_nodes: 1,
        total_edges: 0,
        projection: {
          scan_id: "scan-4",
          revision: 4,
          coverage_limited: true,
          coverage_limitation_count: 2,
        },
      }),
    );

    await expect(fetchGraphStats()).resolves.toMatchObject({
      total_nodes: 1,
      projection: {
        scanId: "scan-4",
        revision: 4,
        coverageLimited: true,
        coverageLimitationCount: 2,
      },
    });
  });

  it("rejects missing publication identity", async () => {
    getMock.mockReturnValue(
      response({
        node_counts: {},
        edge_counts: {},
        total_nodes: 0,
        total_edges: 0,
      }),
    );

    await expect(fetchGraphStats()).rejects.toThrow(
      /graph stats.projection must be an object/,
    );
  });
});
