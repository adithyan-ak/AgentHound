import { describe, it, expect } from "vitest";
import {
  buildExplorerGraph,
  buildFindingIndex,
  isCrossProtocolEdge,
  severityRank,
} from "../graph";
import { getLens } from "../lens-config";
import type { APIEdge, APINode, EdgeKind } from "@entities/graph/dto";
import type { Finding } from "@entities/finding/model";

function n(id: string, kind: string, extra: Record<string, unknown> = {}): APINode {
  return {
    id,
    kinds: [kind],
    properties: { name: id, ...extra },
  };
}

function e(
  source: string,
  target: string,
  kind: EdgeKind,
  props: Record<string, unknown> = {},
): APIEdge {
  return { source, target, kind, properties: props };
}

const FIXTURE_NODES: APINode[] = [
  n("agent-1", "AgentInstance"),
  n("server-1", "MCPServer", { auth_method: "none", is_pinned: false }),
  n("tool-1", "MCPTool", { has_injection_patterns: true }),
  n("resource-1", "MCPResource", { sensitivity: "critical" }),
  n("a2a-1", "A2AAgent"),
  n("a2a-2", "A2AAgent"),
  n("host-1", "Host"),
  n("cred-1", "Credential", {
    merge_key: "value_hash",
    identity_basis: "value_hash",
    material_status: "observed",
    exposure_status: "exposed",
  }),
  n("identity-1", "Identity"),
  n("litellm-1", "LiteLLMGateway"),
  n("ollama-1", "OllamaInstance"),
  n("model-1", "AIModel"),
  n("signal-1", "ExtractedTrainingSignal"),
];

const FIXTURE_EDGES: APIEdge[] = [
  e("agent-1", "server-1", "TRUSTS_SERVER"),
  e("server-1", "tool-1", "PROVIDES_TOOL"),
  e("server-1", "resource-1", "PROVIDES_RESOURCE"),
  e("tool-1", "resource-1", "HAS_ACCESS_TO", { is_composite: true, confidence: 0.9 }),
  e("agent-1", "resource-1", "CAN_REACH", {
    is_composite: true,
    confidence: 0.95,
    hops: 3,
  }),
  e("agent-1", "tool-1", "CAN_EXFILTRATE_VIA", {
    is_composite: true,
    confidence: 0.8,
  }),
  e("tool-1", "tool-1", "POISONED_DESCRIPTION", { is_composite: true }),
  e("server-1", "host-1", "RUNS_ON"),
  e("a2a-1", "host-1", "RUNS_ON"),
  e("server-1", "identity-1", "AUTHENTICATES_WITH"),
  e("identity-1", "cred-1", "USES_CREDENTIAL"),
  e("server-1", "cred-1", "HAS_ENV_VAR"),
  e("litellm-1", "cred-1", "EXPOSES_CREDENTIAL"),
  e("a2a-1", "a2a-2", "DELEGATES_TO"),
  e("a2a-1", "a2a-2", "SAME_AUTH_DOMAIN"),
  e("a2a-1", "a2a-2", "CAN_IMPERSONATE"),
  e("litellm-1", "ollama-1", "EXPOSES"),
  e("ollama-1", "model-1", "PROVIDES_MODEL"),
  e("model-1", "signal-1", "EXTRACTED_FROM"),
];

const FIXTURE_FINDINGS: Finding[] = [
  {
    id: "f1",
    severity: "critical",
    category: "Transitive Access",
    title: "Agent reaches critical resource",
    description: "",
    edge_kind: "CAN_REACH",
    source_id: "agent-1",
    source_name: "agent-1",
    source_kind: "AgentInstance",
    target_id: "resource-1",
    target_name: "resource-1",
    target_kind: "MCPResource",
    confidence: 0.95,
    variant: "default",
    evidence: { state: "inferred" },
    owasp_map: ["MCP04"],
    atlas_map: [],
  },
  {
    id: "f2",
    severity: "critical",
    category: "Data Exfiltration",
    title: "Can exfiltrate via tool",
    description: "",
    edge_kind: "CAN_EXFILTRATE_VIA",
    source_id: "agent-1",
    source_name: "agent-1",
    source_kind: "AgentInstance",
    target_id: "tool-1",
    target_name: "tool-1",
    target_kind: "MCPTool",
    confidence: 0.8,
    variant: "default",
    evidence: { state: "inferred" },
    owasp_map: [],
    atlas_map: [],
  },
  {
    id: "f3",
    severity: "high",
    category: "Poisoning",
    title: "Tool poisoned",
    description: "",
    edge_kind: "POISONED_DESCRIPTION",
    source_id: "tool-1",
    source_name: "tool-1",
    source_kind: "MCPTool",
    target_id: "tool-1",
    target_name: "tool-1",
    target_kind: "MCPTool",
    confidence: 1.0,
    variant: "default",
    evidence: { state: "observed_signal" },
    owasp_map: [],
    atlas_map: [],
  },
];

describe("severityRank", () => {
  it("orders critical < high < medium < low < info < null", () => {
    expect(severityRank("critical")).toBeLessThan(severityRank("high"));
    expect(severityRank("high")).toBeLessThan(severityRank("medium"));
    expect(severityRank("medium")).toBeLessThan(severityRank("low"));
    expect(severityRank("low")).toBeLessThan(severityRank("info"));
    expect(severityRank(null)).toBeGreaterThan(severityRank("info"));
  });
});

describe("buildFindingIndex", () => {
  it("indexes findings by source|target|kind", () => {
    const idx = buildFindingIndex(FIXTURE_FINDINGS);
    expect(idx.get("agent-1|resource-1|CAN_REACH")).toBe("critical");
    expect(idx.get("agent-1|tool-1|CAN_EXFILTRATE_VIA")).toBe("critical");
    expect(idx.get("tool-1|tool-1|POISONED_DESCRIPTION")).toBe("high");
  });

  it("keeps the highest severity for duplicate keys", () => {
    const idx = buildFindingIndex([
      { ...FIXTURE_FINDINGS[0]!, severity: "low" },
      { ...FIXTURE_FINDINGS[0]!, severity: "critical" },
      { ...FIXTURE_FINDINGS[0]!, severity: "medium" },
    ]);
    expect(idx.get("agent-1|resource-1|CAN_REACH")).toBe("critical");
  });
});

describe("isCrossProtocolEdge", () => {
  it("detects A2A → MCP boundary crossings", () => {
    const edge = e("a2a-1", "server-1", "DELEGATES_TO");
    expect(isCrossProtocolEdge(edge, "A2AAgent", "MCPServer")).toBe(true);
  });

  it("detects MCP → A2A boundary crossings", () => {
    const edge = e("server-1", "a2a-1", "PROVIDES_TOOL");
    expect(isCrossProtocolEdge(edge, "MCPServer", "A2AAgent")).toBe(true);
  });

  it("does not flag same-domain edges", () => {
    const edge = e("agent-1", "server-1", "TRUSTS_SERVER");
    expect(isCrossProtocolEdge(edge, "AgentInstance", "MCPServer")).toBe(false);
  });

  it("respects explicit cross_protocol flag", () => {
    const edge = e("x", "y", "CAN_REACH", { cross_protocol: true });
    expect(isCrossProtocolEdge(edge, "AgentInstance", "MCPResource")).toBe(true);
  });
});

describe("buildExplorerGraph", () => {
  it("Topology lens renders only raw structural edges", () => {
    const lens = getLens("topology");
    const result = buildExplorerGraph(
      { nodes: FIXTURE_NODES, edges: FIXTURE_EDGES },
      {
        lens,
        activeLensId: "topology",
        subPresets: [...lens.edgeKinds],
        findings: FIXTURE_FINDINGS,
      },
    );
    const kinds = new Set(
      result.edges.flatMap((e) => {
        const data = e.data!;
        return data.bundledKinds ?? [data.kind];
      }),
    );
    expect(kinds.has("TRUSTS_SERVER")).toBe(true);
    expect(kinds.has("PROVIDES_TOOL")).toBe(true);
    expect(kinds.has("RUNS_ON")).toBe(true);
    expect(kinds.has("DELEGATES_TO")).toBe(true);
    expect(kinds.has("SAME_AUTH_DOMAIN")).toBe(true);
    expect(kinds.has("EXPOSES")).toBe(true);
    expect(kinds.has("PROVIDES_MODEL")).toBe(true);
    expect(kinds.has("EXTRACTED_FROM")).toBe(true);
    expect(kinds.has("CAN_REACH")).toBe(false);
    expect(kinds.has("HAS_ACCESS_TO")).toBe(false);
  });

  it("Attack Surface lens renders only composite edges", () => {
    const lens = getLens("attack-surface");
    const result = buildExplorerGraph(
      { nodes: FIXTURE_NODES, edges: FIXTURE_EDGES },
      {
        lens,
        activeLensId: "attack-surface",
        subPresets: [...lens.edgeKinds],
        findings: FIXTURE_FINDINGS,
      },
    );
    const kinds = new Set(result.edges.map((e) => e.data!.kind));
    expect(kinds.has("HAS_ACCESS_TO")).toBe(true);
    expect(kinds.has("CAN_REACH")).toBe(true);
    expect(kinds.has("CAN_EXFILTRATE_VIA")).toBe(true);
    expect(kinds.has("CAN_IMPERSONATE")).toBe(true);
    expect(kinds.has("TRUSTS_SERVER")).toBe(false);
  });

  for (const [kind, lensId, source, target] of [
    ["INGESTS_UNTRUSTED", "attack-surface", "tool-1", "resource-1"],
    ["CONFUSED_DEPUTY", "attack-surface", "a2a-1", "a2a-2"],
    ["TAINTS", "poisoning", "tool-1", "tool-1"],
    ["IFC_VIOLATION", "attack-surface", "tool-1", "tool-1"],
    ["POISONS_CONTEXT", "poisoning", "tool-1", "tool-1"],
  ] as const satisfies ReadonlyArray<
    readonly [EdgeKind, "attack-surface" | "poisoning", string, string]
  >) {
    it(`${kind} renders in its ordinary ${lensId} lens`, () => {
      const lens = getLens(lensId);
      const result = buildExplorerGraph(
        { nodes: FIXTURE_NODES, edges: [e(source, target, kind)] },
        {
          lens,
          activeLensId: lensId,
          subPresets: [kind],
          findings: [],
        },
      );
      expect(result.edges).toHaveLength(1);
      expect(result.edges[0]?.data?.kind).toBe(kind);
    });
  }

  it("Critical lens only includes edges present in critical findings", () => {
    const lens = getLens("critical");
    const result = buildExplorerGraph(
      { nodes: FIXTURE_NODES, edges: FIXTURE_EDGES },
      {
        lens,
        activeLensId: "critical",
        subPresets: [],
        findings: FIXTURE_FINDINGS,
      },
    );
    // Only CAN_REACH (f1) and CAN_EXFILTRATE_VIA (f2) are critical; the
    // high-severity POISONED_DESCRIPTION (f3) should NOT appear.
    const kinds = new Set(result.edges.map((e) => e.data!.kind));
    expect(kinds.has("CAN_REACH")).toBe(true);
    expect(kinds.has("CAN_EXFILTRATE_VIA")).toBe(true);
    expect(kinds.has("POISONED_DESCRIPTION")).toBe(false);
    expect(kinds.has("TRUSTS_SERVER")).toBe(false);
  });

  it("Credentials lens renders credential flow and exposure edges", () => {
    const lens = getLens("credentials");
    const result = buildExplorerGraph(
      { nodes: FIXTURE_NODES, edges: FIXTURE_EDGES },
      {
        lens,
        activeLensId: "credentials",
        subPresets: [...lens.edgeKinds],
        findings: FIXTURE_FINDINGS,
      },
    );
    const kinds = new Set(result.edges.map((e) => e.data!.kind));
    expect(kinds.has("AUTHENTICATES_WITH")).toBe(true);
    expect(kinds.has("USES_CREDENTIAL")).toBe(true);
    expect(kinds.has("HAS_ENV_VAR")).toBe(true);
    expect(kinds.has("EXPOSES_CREDENTIAL")).toBe(true);
    expect(kinds.has("CAN_REACH")).toBe(false);
  });

  it("Poisoning lens tags self-loops with type='self-loop'", () => {
    const lens = getLens("poisoning");
    const result = buildExplorerGraph(
      { nodes: FIXTURE_NODES, edges: FIXTURE_EDGES },
      {
        lens,
        activeLensId: "poisoning",
        subPresets: [...lens.edgeKinds],
        findings: FIXTURE_FINDINGS,
      },
    );
    const selfLoop = result.edges.find((e) => e.source === e.target);
    expect(selfLoop).toBeDefined();
    expect(selfLoop?.type).toBe("self-loop");
  });

  it("sub-preset filtering narrows the visible edge kinds", () => {
    const lens = getLens("topology");
    const result = buildExplorerGraph(
      { nodes: FIXTURE_NODES, edges: FIXTURE_EDGES },
      {
        lens,
        activeLensId: "topology",
        subPresets: ["TRUSTS_SERVER"],
        findings: FIXTURE_FINDINGS,
      },
    );
    const kinds = new Set(result.edges.map((e) => e.data!.kind));
    expect(kinds.has("TRUSTS_SERVER")).toBe(true);
    expect(kinds.has("PROVIDES_TOOL")).toBe(false);
  });

  it("treats an empty sub-preset selection as no visible edges", () => {
    const lens = getLens("topology");
    const result = buildExplorerGraph(
      { nodes: FIXTURE_NODES, edges: FIXTURE_EDGES },
      {
        lens,
        activeLensId: "topology",
        subPresets: [],
        findings: FIXTURE_FINDINGS,
      },
    );
    expect(result.edges).toHaveLength(0);
    expect(result.metrics.visibleEdgeCount).toBe(0);
  });

  it("highlights only exact directional relationship keys", () => {
    const lens = getLens("topology");
    const nodes = [n("a", "AgentInstance"), n("b", "MCPServer")];
    const edges = [
      e("a", "b", "TRUSTS_SERVER"),
      e("a", "b", "RUNS_ON"),
      e("b", "a", "TRUSTS_SERVER"),
    ];
    const result = buildExplorerGraph(
      { nodes, edges },
      {
        lens,
        activeLensId: "topology",
        subPresets: ["TRUSTS_SERVER", "RUNS_ON"],
        findings: [],
        highlight: {
          nodeIds: new Set(["a", "b"]),
          edgeIds: new Set(["a|b|TRUSTS_SERVER"]),
        },
      },
    );

    const highlighted = result.edges.filter((edge) => !edge.data?.dim);
    expect(highlighted).toHaveLength(1);
    expect(highlighted[0]?.source).toBe("a");
    expect(highlighted[0]?.target).toBe("b");
    expect(highlighted[0]?.data?.bundledKinds).toEqual(["TRUSTS_SERVER"]);
    expect(
      result.edges.find(
        (edge) =>
          edge.source === "b" &&
          edge.target === "a" &&
          edge.data?.kind === "TRUSTS_SERVER",
      )?.data?.dim,
    ).toBe(true);
    expect(
      result.edges.find((edge) => edge.data?.kind === "RUNS_ON")?.data?.dim,
    ).toBe(true);
  });

  it("overlays exact deep-link evidence without broadening the active lens", () => {
    const lens = getLens("attack-surface");
    const nodes = [
      n("agent", "AgentInstance"),
      n("server", "MCPServer"),
      n("resource", "MCPResource"),
      n("host", "Host"),
    ];
    const edges = [
      e("agent", "resource", "CAN_REACH"),
      e("agent", "server", "TRUSTS_SERVER"),
      e("server", "host", "RUNS_ON"),
    ];
    const result = buildExplorerGraph(
      { nodes, edges },
      {
        lens,
        activeLensId: "attack-surface",
        subPresets: ["CAN_REACH"],
        findings: [],
        highlight: {
          nodeIds: new Set(["agent", "resource", "server"]),
          edgeIds: new Set([
            "agent|resource|CAN_REACH",
            "agent|server|TRUSTS_SERVER",
          ]),
        },
      },
    );

    expect(result.edges.map((edge) => edge.data?.kind)).toEqual([
      "CAN_REACH",
      "TRUSTS_SERVER",
    ]);
    expect(result.edges.every((edge) => edge.data?.dim === false)).toBe(true);
    expect(result.edges.some((edge) => edge.data?.kind === "RUNS_ON")).toBe(
      false,
    );
  });

  it("bundles parallel edges and emits a bundledCount", () => {
    const edges: APIEdge[] = [
      ...FIXTURE_EDGES,
      e("agent-1", "server-1", "TRUSTS_SERVER", { confidence: 0.5 }),
      e("agent-1", "server-1", "TRUSTS_SERVER", { confidence: 0.6 }),
    ];
    const lens = getLens("topology");
    const result = buildExplorerGraph(
      { nodes: FIXTURE_NODES, edges },
      {
        lens,
        activeLensId: "topology",
        subPresets: [...lens.edgeKinds],
        findings: FIXTURE_FINDINGS,
      },
    );
    const bundle = result.edges.find(
      (e) => e.source === "agent-1" && e.target === "server-1",
    );
    expect(bundle).toBeDefined();
    expect((bundle?.data as { bundledCount: number }).bundledCount).toBeGreaterThanOrEqual(3);
  });

  it("computes metrics including per-severity counts", () => {
    const lens = getLens("attack-surface");
    const result = buildExplorerGraph(
      { nodes: FIXTURE_NODES, edges: FIXTURE_EDGES },
      {
        lens,
        activeLensId: "attack-surface",
        subPresets: [...lens.edgeKinds],
        findings: FIXTURE_FINDINGS,
      },
    );
    expect(result.metrics.visibleEdgeCount).toBeGreaterThan(0);
    expect(result.metrics.criticalCount).toBeGreaterThanOrEqual(2);
  });

  it("hides orphans by default in non-dim lenses and reports orphanCount", () => {
    const orphan = n("isolated-tool", "MCPTool");
    const nodes = [...FIXTURE_NODES, orphan];
    const lens = getLens("attack-surface");
    const result = buildExplorerGraph(
      { nodes, edges: FIXTURE_EDGES },
      {
        lens,
        activeLensId: "attack-surface",
        subPresets: [...lens.edgeKinds],
        findings: FIXTURE_FINDINGS,
      },
    );
    // Orphan should not appear as an individual hex
    const hexNodeIds = result.nodes
      .filter((n) => n.type === "hex")
      .map((n) => n.id);
    expect(hexNodeIds).not.toContain("isolated-tool");
    // Metrics should count the orphan
    expect(result.metrics.orphanCount).toBeGreaterThanOrEqual(1);
    expect(result.metrics.orphanByKind["MCPTool"]).toBeGreaterThanOrEqual(1);
    // No cluster emitted when showOrphans=false
    const clusters = result.nodes.filter((n) => n.type === "orphan-cluster");
    expect(clusters.length).toBe(0);
  });

  it("emits one cluster node per kind when showOrphans is true", () => {
    const nodes = [
      ...FIXTURE_NODES,
      n("isolated-tool-1", "MCPTool"),
      n("isolated-tool-2", "MCPTool"),
      n("isolated-host-1", "Host"),
    ];
    const lens = getLens("attack-surface");
    const result = buildExplorerGraph(
      { nodes, edges: FIXTURE_EDGES },
      {
        lens,
        activeLensId: "attack-surface",
        subPresets: [...lens.edgeKinds],
        findings: FIXTURE_FINDINGS,
        showOrphans: true,
      },
    );
    const clusters = result.nodes.filter((n) => n.type === "orphan-cluster");
    const clusterKinds = clusters.map(
      (c) => (c.data as { kind: string }).kind,
    );
    // Should have clusters for MCPTool and Host at minimum, not two Tool clusters
    expect(clusterKinds).toContain("MCPTool");
    expect(clusterKinds).toContain("Host");
    // One cluster per kind, not one per node
    const toolClusters = clusters.filter(
      (c) => (c.data as { kind: string }).kind === "MCPTool",
    );
    expect(toolClusters.length).toBe(1);
    // Cluster carries the correct member count
    const toolCluster = toolClusters[0]!;
    expect((toolCluster.data as { count: number }).count).toBe(2);
    // Cluster contains the orphan node ids for drill-in
    const orphanIds = (
      toolCluster.data as { orphanNodes: Array<{ id: string }> }
    ).orphanNodes.map((o) => o.id);
    expect(orphanIds).toContain("isolated-tool-1");
    expect(orphanIds).toContain("isolated-tool-2");
  });

  it("does not cluster orphans in dim-others lenses (Critical)", () => {
    const nodes = [...FIXTURE_NODES, n("isolated-tool", "MCPTool")];
    const lens = getLens("critical");
    const result = buildExplorerGraph(
      { nodes, edges: FIXTURE_EDGES },
      {
        lens,
        activeLensId: "critical",
        subPresets: [],
        findings: FIXTURE_FINDINGS,
        showOrphans: true,
      },
    );
    // Critical uses dim-others behavior, no clustering
    const clusters = result.nodes.filter((n) => n.type === "orphan-cluster");
    expect(clusters.length).toBe(0);
  });

  it("handles empty graph data without crashing", () => {
    const lens = getLens("topology");
    const result = buildExplorerGraph(
      { nodes: [], edges: [] },
      {
        lens,
        activeLensId: "topology",
        subPresets: [...lens.edgeKinds],
        findings: [],
      },
    );
    expect(result.nodes).toHaveLength(0);
    expect(result.edges).toHaveLength(0);
    expect(result.metrics.visibleNodeCount).toBe(0);
    expect(result.metrics.visibleEdgeCount).toBe(0);
    expect(result.metrics.orphanCount).toBe(0);
    expect(result.metrics.criticalCount).toBe(0);
  });

  it("marks configured backends unverified until direct probe evidence exists", () => {
    const lens = getLens("topology");
    const configured = n("ollama-configured", "OllamaInstance", {
      configuration_observed: true,
      configured_via: "openwebui",
      probe_status: "configured_unverified",
    });
    const verified = n("ollama-verified", "OllamaInstance", {
      configuration_observed: true,
      probe_status: "verified",
    });
    const source = n("webui", "OpenWebUIInstance");
    const result = buildExplorerGraph(
      {
        nodes: [source, configured, verified],
        edges: [
          e("webui", "ollama-configured", "EXPOSES"),
          e("webui", "ollama-verified", "EXPOSES"),
        ],
      },
      {
        lens,
        activeLensId: "topology",
        subPresets: [...lens.edgeKinds],
        findings: [],
      },
    );
    const statusByID = new Map(
      result.nodes.map((node) => [
        node.id,
        (node.data as { evidenceStatus?: string | null }).evidenceStatus,
      ]),
    );
    expect(statusByID.get("ollama-configured")).toBe("configured-unverified");
    expect(statusByID.get("ollama-verified")).toBe("verified");
  });
});
