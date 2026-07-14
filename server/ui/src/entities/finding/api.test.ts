import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  get: vi.fn(),
  json: vi.fn(),
}));

vi.mock("@shared/api/client", () => ({
  api: {
    get: mocks.get,
  },
}));

import { fetchAllFindings, fetchFindingDetail, fetchFindings } from "./api";

function finding() {
  return {
    id: "aaaaaaaaaaaaaaaa",
    severity: "high",
    category: "Transitive Access",
    title: "Published finding",
    description: "Published detector result",
    edge_kind: "CAN_REACH",
    source_id: "source",
    source_name: "source",
    source_kind: "AgentInstance",
    target_id: "target",
    target_name: "target",
    target_kind: "MCPResource",
    confidence: 0.9,
    variant: "default",
    owasp_map: [],
    atlas_map: [],
    evidence: { state: "inferred", channels: [] },
  };
}

function verifiedFinding() {
  return {
    ...finding(),
    evidence: {
      state: "verified",
      channels: [],
      verification: {
        scenario_id: "cred-reach",
        scenario_version: 1,
        campaign_run_id: "run-ui",
        verified_at: "2026-07-13T12:00:00Z",
        oracle_type: "differential_credential_reach",
        outcome: "credential_gated_reach_verified",
        control_stage: "initialize",
        control_status: "denied",
        control_resource_addressed: false,
        authed_stage: "resource_read",
        authed_status: "allowed",
        authed_resource_addressed: true,
        cleanup_status: "not_applicable",
      },
    },
  };
}

function exactFindingDetail({
  nodes = [],
  edges = [],
  remediation = [],
}: {
  nodes?: unknown[];
  edges?: unknown[];
  remediation?: unknown[];
} = {}) {
  return {
    finding: finding(),
    attack_path: {
      nodes,
      edges,
      shape: "linear",
      continuity: {
        state: "continuous",
        component_count: 1,
        missing_node_ids: [],
      },
      direction: "forward",
      completeness: { state: "complete", reasons: [] },
      cost: {
        state: "complete",
        value: 0,
        reasons: [],
        missing_weight_edge_indexes: [],
      },
      total_risk_weight: 0,
    },
    remediation,
    impact: null,
    snapshot: {
      scope: "published",
      scan_id: "scan-1",
      revision: 7,
      published_at: "2026-07-11T00:00:00Z",
      projection_status: "complete",
      snapshot_status: "complete",
      available: true,
      stale: false,
      evidence_state: "persisted_exact_evidence",
    },
  };
}

describe("published finding scope", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.get.mockReturnValue({
      json: mocks.json,
    });
    mocks.json.mockResolvedValue({
      findings: [],
      scope: {
        mode: "published",
        scan_id: "scan-1",
        revision: 7,
        published_at: "2026-07-11T00:00:00Z",
        projection_status: "complete",
        snapshot_status: "complete",
        available: true,
        stale: false,
      },
    });
  });

  it("requests the exact published snapshot for lists", async () => {
    const result = await fetchFindings("high", true);

    expect(mocks.get).toHaveBeenCalledWith("analysis/findings", {
      searchParams: {
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

  it("preserves publication scope for complete Explorer reads", async () => {
    const result = await fetchAllFindings();

    expect(result).toMatchObject({
      findings: [],
      scope: {
        scanId: "scan-1",
        revision: 7,
        available: true,
        stale: false,
      },
    });
  });

  it("decodes verified finding evidence and structured metadata", async () => {
    mocks.json.mockResolvedValue({
      findings: [verifiedFinding()],
      scope: {
        mode: "published",
        scan_id: "scan-1",
        revision: 7,
        published_at: "2026-07-11T00:00:00Z",
        projection_status: "complete",
        snapshot_status: "complete",
        available: true,
        stale: false,
      },
    });
    const result = await fetchFindings();
    expect(result.findings[0]?.evidence).toMatchObject({
      state: "verified",
      verification: {
        campaign_run_id: "run-ui",
        control_stage: "initialize",
        control_resource_addressed: false,
        authed_stage: "resource_read",
        authed_resource_addressed: true,
        cleanup_status: "not_applicable",
      },
    });
  });

  it("rejects verified evidence without its verification contract", async () => {
    mocks.json.mockResolvedValue({
      findings: [{ ...finding(), evidence: { state: "verified", channels: [] } }],
      scope: {
        mode: "published",
        scan_id: "scan-1",
        revision: 7,
        published_at: "2026-07-11T00:00:00Z",
        projection_status: "complete",
        snapshot_status: "complete",
        available: true,
        stale: false,
      },
    });
    await expect(fetchFindings()).rejects.toThrow(
      "findings[0].evidence.verification is required",
    );
  });

  it("requests detail from the same published scope", async () => {
    mocks.json.mockResolvedValue({
      finding: finding(),
      attack_path: null,
      remediation: [],
      impact: null,
      snapshot: {
        scope: "published",
        scan_id: "scan-1",
        revision: 7,
        published_at: "2026-07-11T00:00:00Z",
        projection_status: "complete",
        snapshot_status: "complete",
        available: true,
        stale: false,
        evidence_state: "unavailable",
      },
    });
    await fetchFindingDetail("aaaaaaaaaaaaaaaa");

    expect(mocks.get).toHaveBeenCalledWith("analysis/findings/aaaaaaaaaaaaaaaa");
  });

  it("accepts canonical detail collections and rejects null fallbacks", async () => {
    mocks.json.mockResolvedValue({
      finding: finding(),
      attack_path: {
        nodes: [],
        edges: [],
        shape: "nodes_only",
        continuity: {
          state: "not_applicable",
          component_count: 0,
          missing_node_ids: [],
        },
        direction: "not_applicable",
        completeness: { state: "complete", reasons: [] },
        cost: {
          state: "not_applicable",
          value: null,
          reasons: [],
          missing_weight_edge_indexes: [],
        },
        total_risk_weight: null,
      },
      remediation: [],
      impact: null,
      snapshot: {
        scope: "published",
        scan_id: "scan-1",
        revision: 7,
        published_at: "2026-07-11T00:00:00Z",
        projection_status: "complete",
        snapshot_status: "complete",
        available: true,
        stale: false,
        evidence_state: "persisted_exact_evidence",
      },
    });
    const detail = await fetchFindingDetail("aaaaaaaaaaaaaaaa");
    expect(detail.finding.owasp_map).toEqual([]);
    expect(detail.finding.evidence.channels).toEqual([]);
    expect(detail.attack_path?.nodes).toEqual([]);
    expect(detail.attack_path?.continuity.missing_node_ids).toEqual([]);
    expect(detail.remediation).toEqual([]);

    mocks.json.mockResolvedValue({
      finding: finding(),
      attack_path: null,
      remediation: null,
      impact: null,
      snapshot: {
        scope: "published",
        scan_id: "scan-1",
        revision: 7,
        published_at: "2026-07-11T00:00:00Z",
        projection_status: "complete",
        snapshot_status: "complete",
        available: true,
        stale: false,
        evidence_state: "unavailable",
      },
    });
    await expect(fetchFindingDetail("aaaaaaaaaaaaaaaa")).rejects.toThrow(
      "finding detail.remediation must be an array",
    );
  });

  it("requires exact-evidence node kinds arrays, including empty arrays", async () => {
    mocks.json.mockResolvedValue(
      exactFindingDetail({
        nodes: [{ id: "untyped", kinds: [], properties: {} }],
      }),
    );
    const detail = await fetchFindingDetail("aaaaaaaaaaaaaaaa");
    expect(detail.attack_path?.nodes[0]?.kinds).toEqual([]);

    mocks.json.mockResolvedValue(
      exactFindingDetail({
        nodes: [{ id: "untyped", kinds: null, properties: {} }],
      }),
    );
    await expect(fetchFindingDetail("aaaaaaaaaaaaaaaa")).rejects.toThrow(
      "finding detail.attack_path.nodes[0].kinds must be an array",
    );
  });

  it("decodes ordinary remediation steps emitted by the handler", async () => {
    mocks.json.mockResolvedValue(
      exactFindingDetail({
        nodes: [
          { id: "server", kinds: ["MCPServer"], properties: {} },
          { id: "tool", kinds: ["MCPTool"], properties: {} },
          { id: "resource", kinds: ["MCPResource"], properties: {} },
        ],
        edges: [
          {
            source: "server",
            target: "tool",
            kind: "PROVIDES_TOOL",
            properties: {},
            synthetic: false,
          },
          {
            source: "tool",
            target: "resource",
            kind: "HAS_ACCESS_TO",
            properties: {},
            synthetic: false,
          },
        ],
        remediation: [
          {
            step: 1,
            title: "Review tool exposure",
            description: "Review exposure.",
            edge_kind: "PROVIDES_TOOL",
            source: { id: "server", name: "server", kind: "MCPServer" },
            target: { id: "tool", name: "tool", kind: "MCPTool" },
            channels: [],
            commands: [],
          },
          {
            step: 2,
            title: "Restrict inferred resource access",
            description: "Restrict access.",
            edge_kind: "HAS_ACCESS_TO",
            source: { id: "tool", name: "tool", kind: "MCPTool" },
            target: {
              id: "resource",
              name: "resource",
              kind: "MCPResource",
            },
            channels: [],
            commands: [],
          },
        ],
      }),
    );

    const detail = await fetchFindingDetail("aaaaaaaaaaaaaaaa");

    expect(
      detail.remediation.map(({ edge_kind, channels, commands }) => ({
        edge_kind,
        channels,
        commands,
      })),
    ).toEqual([
      { edge_kind: "PROVIDES_TOOL", channels: [], commands: [] },
      { edge_kind: "HAS_ACCESS_TO", channels: [], commands: [] },
    ]);
  });

  it.each([
    {
      evidence: "node",
      nodes: [
        { id: "server", kinds: ["MCPServer"], properties: null },
      ],
      edges: [],
      error: "finding detail.attack_path.nodes[0].properties must be an object",
    },
    {
      evidence: "edge",
      nodes: [
        { id: "server", kinds: ["MCPServer"], properties: {} },
        { id: "tool", kinds: ["MCPTool"], properties: {} },
      ],
      edges: [
        {
          source: "server",
          target: "tool",
          kind: "PROVIDES_TOOL",
          properties: null,
          synthetic: false,
        },
      ],
      error: "finding detail.attack_path.edges[0].properties must be an object",
    },
  ])("rejects null $evidence evidence properties", async ({ nodes, edges, error }) => {
    mocks.json.mockResolvedValue(exactFindingDetail({ nodes, edges }));

    await expect(fetchFindingDetail("aaaaaaaaaaaaaaaa")).rejects.toThrow(error);
  });
});
