import { beforeEach, describe, expect, it, vi } from "vitest";
import { runPreBuiltQuery } from "./api";

const getMock = vi.hoisted(() => vi.fn());

vi.mock("@shared/api/client", () => ({
  api: { get: getMock },
}));

const query = {
  id: "shortest-to-database",
  name: "Shortest Path to Database",
  description: "test",
  category: "Critical Paths",
  severity: "critical",
};

const metadata = {
  scope: "security",
  direction: "out",
  relationship_kinds: ["TRUSTS_SERVER"],
  max_hops: 10,
  algorithm: "bounded-min-weight",
  complete: false,
  truncated: true,
  expansion_limit: 100,
  expansions: 101,
  incomplete_reason: "expansion limit reached",
};

function response(body: unknown) {
  return {
    json: vi.fn().mockResolvedValue(body),
  };
}

describe("runPreBuiltQuery", () => {
  beforeEach(() => {
    getMock.mockReset();
  });

  it("strictly decodes traversal and projection metadata", async () => {
    getMock.mockReturnValue(
      response({
        query,
        rows: [],
        metadata,
        projection: { scan_id: "scan-7", revision: 7 },
      }),
    );

    await expect(runPreBuiltQuery("shortest-to-database")).resolves.toMatchObject({
      metadata: {
        complete: false,
        truncated: true,
        expansionLimit: 100,
        incompleteReason: "expansion limit reached",
      },
      projection: { scanId: "scan-7", revision: 7 },
    });
  });

  it("rejects missing traversal metadata for traversal-backed queries", async () => {
    getMock.mockReturnValue(
      response({
        query,
        rows: [],
        projection: { scan_id: "scan-7", revision: 7 },
      }),
    );

    await expect(runPreBuiltQuery("shortest-to-database")).rejects.toThrow(
      /metadata is required/,
    );
  });

  it("rejects malformed traversal metadata instead of assuming completeness", async () => {
    getMock.mockReturnValue(
      response({
        query,
        rows: [],
        metadata: { ...metadata, complete: "yes" },
        projection: { scan_id: "scan-7", revision: 7 },
      }),
    );

    await expect(runPreBuiltQuery("shortest-to-database")).rejects.toThrow(
      /metadata.complete must be a boolean/,
    );
  });

  it("rejects missing projection metadata", async () => {
    getMock.mockReturnValue(
      response({
        query: { ...query, id: "no-auth-servers" },
        rows: [],
      }),
    );

    await expect(runPreBuiltQuery("no-auth-servers")).rejects.toThrow(
      /prebuilt result.projection must be an object/,
    );
  });
});
