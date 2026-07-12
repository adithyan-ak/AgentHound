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

function scan(overrides: Record<string, unknown>) {
  return {
    id: "scan",
    collector: "mcp",
    status: "completed",
    started_at: "2026-07-11T00:00:00Z",
    submitted: { nodes: 1, edges: 1 },
    write_rows: { nodes: 1, edges: 1 },
    graph_totals: { before: null, after: null },
    ...overrides,
  };
}

function scanPage(scans: unknown[]) {
  return {
    scans,
    page: {
      offset: 0,
      limit: 1,
      total: scans.length,
      has_more: false,
      complete: true,
      revision: "scan-rev",
    },
  };
}

function ingestCollection(suffix = "c") {
  const coverageKey = `mcp:target:sha256:${suffix.repeat(64)}`;
  return {
    state: "complete",
    coverage_keys: [coverageKey],
    outcomes: [
      {
        collector: "mcp",
        coverage_key: coverageKey,
        target: "https://mcp.example",
        method: "initialize",
        state: "complete",
      },
    ],
  };
}

describe("uploadScan", () => {
  beforeEach(() => {
    getMock.mockReset();
    postMock.mockReset();
  });

  it("decodes the server-emitted collection report", async () => {
    const coverageKey = `mcp:target:sha256:${"a".repeat(64)}`;
    postMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          scan_id: "complete",
          outcome: "complete",
          projection_status: "complete",
          submitted: { nodes: 1, edges: 0 },
          write_rows: { nodes: 1, edges: 0 },
          graph_totals: { before: null, after: null },
          collection: {
            state: "complete",
            coverage_keys: [coverageKey],
            outcomes: [
              {
                collector: "mcp",
                coverage_key: coverageKey,
                target: "https://mcp.example",
                method: "initialize",
                state: "complete",
                items: 1,
              },
            ],
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const result = await uploadScan(
      new File(["{}"], "scan.json", { type: "application/json" }),
    );

    expect(result.collection).toEqual({
      state: "complete",
      coverage_keys: [coverageKey],
      outcomes: [
        {
          collector: "mcp",
          coverage_key: coverageKey,
          target: "https://mcp.example",
          method: "initialize",
          state: "complete",
          items: 1,
        },
      ],
    });
  });

  it("rejects unknown fields in a collection report", async () => {
    const coverageKey = `mcp:target:sha256:${"b".repeat(64)}`;
    postMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          scan_id: "invalid-collection",
          outcome: "complete",
          projection_status: "complete",
          submitted: { nodes: 0, edges: 0 },
          write_rows: { nodes: 0, edges: 0 },
          graph_totals: { before: null, after: null },
          collection: {
            state: "complete",
            coverage_keys: [coverageKey],
            outcomes: [
              {
                collector: "mcp",
                coverage_key: coverageKey,
                target: "https://mcp.example",
                method: "initialize",
                state: "complete",
              },
            ],
            legacy_scope: "mcp.example",
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await expect(
      uploadScan(
        new File(["{}"], "scan.json", { type: "application/json" }),
      ),
    ).rejects.toThrow("ingest result.collection.legacy_scope is not allowed");
  });

  it("requires collection in a successful ingest result", async () => {
    postMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          scan_id: "missing-collection",
          outcome: "complete",
          projection_status: "complete",
          submitted: { nodes: 0, edges: 0 },
          write_rows: { nodes: 0, edges: 0 },
          graph_totals: { before: null, after: null },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await expect(
      uploadScan(
        new File(["{}"], "scan.json", { type: "application/json" }),
      ),
    ).rejects.toThrow("ingest result.collection must be an object");
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
              submitted: { nodes: 1000, edges: 0 },
              write_rows: { nodes: 1000, edges: 0 },
              graph_totals: { before: null, after: null },
              collection: ingestCollection("d"),
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
      write_rows: { nodes: 1000, edges: 0 },
      stages: [
        {
          name: "write_edges",
          state: "failed",
          error: "neo4j failed",
        },
      ],
    });
  });

  it("requires collection in ingest error details", async () => {
    postMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          error: {
            code: "INGEST_FAILED",
            message: "Ingest failed after partial graph mutation.",
            details: {
              scan_id: "partial-without-collection",
              outcome: "failed",
              projection_status: "incomplete",
              submitted: { nodes: 1, edges: 0 },
              write_rows: { nodes: 1, edges: 0 },
              graph_totals: { before: null, after: null },
            },
          },
        }),
        { status: 500, headers: { "Content-Type": "application/json" } },
      ),
    );

    await expect(
      uploadScan(
        new File(["{}"], "scan.json", { type: "application/json" }),
      ),
    ).rejects.toThrow("ingest error.details.collection must be an object");
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
      json: vi.fn().mockResolvedValue(scan({
        id: "older/scan",
        started_at: "2026-07-10T00:00:00Z",
      })),
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
        JSON.stringify(scanPage([
          scan({
            id: "completed",
            started_at: "2026-07-11T00:00:00Z",
            completed_at: "2026-07-11T01:00:00Z",
          }),
        ])),
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
        JSON.stringify(scanPage([
          scan({
            id: "published",
            started_at: "2026-07-11T00:00:00Z",
            completed_at: "2026-07-11T01:00:00Z",
            publication_status: "published",
            published_at: "2026-07-11T01:01:00Z",
          }),
        ])),
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
