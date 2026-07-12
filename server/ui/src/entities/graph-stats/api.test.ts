import { beforeEach, describe, expect, it, vi } from "vitest";
import { fetchGraphStats } from "./api";

const getMock = vi.hoisted(() => vi.fn());

vi.mock("@shared/api/client", () => ({
  api: { get: getMock },
}));

function response(body: unknown) {
  return { json: vi.fn().mockResolvedValue(body) };
}

describe("fetchGraphStats", () => {
  beforeEach(() => {
    getMock.mockReset();
  });

  it("decodes the publication identity", async () => {
    getMock.mockReturnValue(
      response({
        node_counts: { MCPServer: 1 },
        edge_counts: {},
        total_nodes: 1,
        total_edges: 0,
        projection: { scan_id: "scan-4", revision: 4 },
      }),
    );

    await expect(fetchGraphStats()).resolves.toMatchObject({
      total_nodes: 1,
      projection: { scanId: "scan-4", revision: 4 },
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
