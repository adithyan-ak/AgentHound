import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  get: vi.fn(),
  json: vi.fn(),
  headerGet: vi.fn(),
}));

vi.mock("@shared/api/client", () => ({
  api: {
    get: mocks.get,
  },
}));

import { fetchFindingDetail, fetchFindings } from "./api";

describe("published finding scope", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.get.mockReturnValue({
      json: mocks.json,
      headers: { get: mocks.headerGet },
    });
    mocks.json.mockResolvedValue([]);
    mocks.headerGet.mockImplementation((name: string) => {
      const headers: Record<string, string> = {
        "X-Finding-Scope": "published",
        "X-Snapshot-Scan-ID": "scan-1",
        "X-Published-Revision": "7",
        "X-Published-At": "2026-07-11T00:00:00Z",
        "X-Projection-Status": "complete",
        "X-Snapshot-Status": "complete",
        "X-Snapshot-Available": "true",
        "X-Snapshot-Stale": "false",
      };
      return headers[name] ?? null;
    });
  });

  it("requests the exact published snapshot for lists", async () => {
    const result = await fetchFindings("high", true);

    expect(mocks.get).toHaveBeenCalledWith("analysis/findings", {
      searchParams: {
        scope: "published",
        severity: "high",
        include_suppressed: "true",
      },
    });
    expect(result.scope).toMatchObject({
      mode: "published",
      scanId: "scan-1",
      revision: 7,
      available: true,
      stale: false,
    });
  });

  it("requests detail from the same published scope", async () => {
    mocks.json.mockResolvedValue({
      finding: {},
      attack_path: null,
      remediation: [],
      impact: null,
    });
    await fetchFindingDetail("aaaaaaaaaaaaaaaa");

    expect(mocks.get).toHaveBeenCalledWith(
      "analysis/findings/aaaaaaaaaaaaaaaa",
      { searchParams: { scope: "published" } },
    );
  });

  it("normalizes nullish detail collections without hiding malformed arrays", async () => {
    mocks.json.mockResolvedValue({
      finding: { owasp_map: null, atlas_map: null, evidence: { channels: null } },
      attack_path: {
        nodes: null,
        edges: null,
        shape: "nodes_only",
        continuity: {
          state: "not_applicable",
          component_count: 0,
          missing_node_ids: null,
        },
        direction: "not_applicable",
        completeness: { state: "complete", reasons: null },
        cost: {
          state: "not_applicable",
          value: null,
          reasons: null,
          missing_weight_edge_indexes: null,
        },
        total_risk_weight: null,
      },
      remediation: null,
      impact: null,
    });
    const detail = await fetchFindingDetail("aaaaaaaaaaaaaaaa");
    expect(detail.finding.owasp_map).toEqual([]);
    expect(detail.finding.evidence?.channels).toEqual([]);
    expect(detail.attack_path?.nodes).toEqual([]);
    expect(detail.attack_path?.continuity.missing_node_ids).toEqual([]);
    expect(detail.remediation).toEqual([]);

    mocks.json.mockResolvedValue({
      finding: {},
      attack_path: null,
      remediation: "not-an-array",
      impact: null,
    });
    await expect(fetchFindingDetail("aaaaaaaaaaaaaaaa")).rejects.toThrow(
      "finding detail.remediation must be an array",
    );
  });
});
