import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  deleteScan,
  fetchLatestCompletedScan,
  fetchLatestPublishedScan,
  fetchScan,
  IngestRequestError,
  ScanDeleteError,
  uploadScan,
} from "./api";

const getMock = vi.hoisted(() => vi.fn());
const postMock = vi.hoisted(() => vi.fn());
const deleteMock = vi.hoisted(() => vi.fn());

vi.mock("@shared/api/client", () => ({
  api: { delete: deleteMock, get: getMock, post: postMock },
}));

describe("uploadScan", () => {
  beforeEach(() => {
    getMock.mockReset();
    postMock.mockReset();
  });

  it("preserves failed-stage details from a partial ingest response", async () => {
    postMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          error: {
            code: "INGEST_FAILED",
            message: "Ingest failed after partial graph mutation.",
            details: {
              scan_id: "partial",
              outcome: "failed",
              projection_status: "incomplete",
              nodes_written: 1000,
              edges_written: 0,
              stages: [
                {
                  name: "write_edges",
                  state: "failed",
                  required: true,
                  duration: 1,
                  error: "neo4j failed",
                },
              ],
            },
          },
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );

    const file = new File(["{}"], "scan.json", {
      type: "application/json",
    });
    let thrown: unknown;
    try {
      await uploadScan(file);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(IngestRequestError);
    expect((thrown as IngestRequestError).result).toMatchObject({
      scan_id: "partial",
      nodes_written: 1000,
      stages: [
        {
          name: "write_edges",
          state: "failed",
          error: "neo4j failed",
        },
      ],
    });
  });
});

describe("deleteScan", () => {
  beforeEach(() => {
    deleteMock.mockReset();
  });

  it("preserves a 409 active-coverage-head rejection", async () => {
    deleteMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          error: {
            code: "SCAN_DELETE_CONFLICT",
            message: "scan owns an active coverage head",
          },
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );

    let thrown: unknown;
    try {
      await deleteScan("scan/coverage-head");
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(ScanDeleteError);
    expect(thrown).toMatchObject({
      name: "ScanDeleteError",
      status: 409,
      code: "SCAN_DELETE_CONFLICT",
      message: "scan owns an active coverage head",
    });
    expect(deleteMock).toHaveBeenCalledWith("scans/scan%2Fcoverage-head", {
      throwHttpErrors: false,
    });
  });
});

describe("fetchScan", () => {
  beforeEach(() => {
    getMock.mockReset();
  });

  it("fetches a selected scan directly by encoded ID", async () => {
    getMock.mockReturnValue({
      json: vi.fn().mockResolvedValue({
        id: "older/scan",
        collector: "mcp",
        status: "completed",
        started_at: "2026-07-10T00:00:00Z",
        node_count: 1,
        edge_count: 1,
      }),
    });

    await expect(fetchScan("older/scan")).resolves.toMatchObject({
      id: "older/scan",
    });
    expect(getMock).toHaveBeenCalledWith("scans/older%2Fscan");
  });
});

describe("scan freshness queries", () => {
  beforeEach(() => {
    getMock.mockReset();
  });

  it("requests the latest completion from the backend", async () => {
    getMock.mockResolvedValue(
      new Response(
        JSON.stringify([
          {
            id: "completed",
            collector: "mcp",
            status: "completed",
            started_at: "2026-07-11T00:00:00Z",
            completed_at: "2026-07-11T01:00:00Z",
            node_count: 1,
            edge_count: 1,
          },
        ]),
      ),
    );

    await expect(fetchLatestCompletedScan()).resolves.toMatchObject({
      id: "completed",
    });
    expect(getMock).toHaveBeenCalledWith(
      "scans",
      expect.objectContaining({
        searchParams: {
          limit: "1",
          offset: "0",
          order: "completed",
        },
      }),
    );
  });

  it("requests the latest publication from the backend", async () => {
    getMock.mockResolvedValue(
      new Response(
        JSON.stringify([
          {
            id: "published",
            collector: "mcp",
            status: "completed",
            started_at: "2026-07-11T00:00:00Z",
            completed_at: "2026-07-11T01:00:00Z",
            publication_status: "published",
            published_at: "2026-07-11T01:01:00Z",
            node_count: 1,
            edge_count: 1,
          },
        ]),
      ),
    );

    await expect(fetchLatestPublishedScan()).resolves.toMatchObject({
      id: "published",
    });
    expect(getMock).toHaveBeenCalledWith(
      "scans",
      expect.objectContaining({
        searchParams: {
          limit: "1",
          offset: "0",
          order: "published",
        },
      }),
    );
  });
});
