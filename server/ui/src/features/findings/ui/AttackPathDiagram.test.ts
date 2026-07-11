import { describe, expect, it } from "vitest";
import type { AttackPath } from "@entities/finding/model";
import { resolveLinearEvidence } from "./AttackPathDiagram";

function linearPath(): AttackPath {
  return {
    nodes: [
      { id: "a", kinds: ["AgentInstance"], properties: {} },
      { id: "b", kinds: ["MCPServer"], properties: {} },
      { id: "c", kinds: ["MCPTool"], properties: {} },
    ],
    edges: [
      {
        source: "a",
        target: "b",
        kind: "TRUSTS_SERVER",
        properties: { risk_weight: 0.1 },
        synthetic: false,
      },
      {
        source: "b",
        target: "c",
        kind: "PROVIDES_TOOL",
        properties: { risk_weight: 0.1 },
        synthetic: false,
      },
    ],
    shape: "linear",
    continuity: {
      state: "continuous",
      component_count: 1,
      missing_node_ids: [],
    },
    direction: "forward",
    completeness: { state: "complete", reasons: [] },
    linearization: {
      node_ids: ["a", "b", "c"],
      edge_indexes: [0, 1],
    },
    cost: {
      state: "complete",
      value: 0.2,
      reasons: [],
      missing_weight_edge_indexes: [],
    },
    total_risk_weight: 0.2,
  };
}

describe("safe finding evidence linearization", () => {
  it("accepts a complete directed path covering every node and edge", () => {
    const linear = resolveLinearEvidence(linearPath());
    expect(linear?.nodes.map((node) => node.id)).toEqual(["a", "b", "c"]);
    expect(linear?.edges.map(({ index }) => index)).toEqual([0, 1]);
  });

  it("withholds path rendering for non-linear evidence", () => {
    const path = linearPath();
    path.shape = "branched";
    path.direction = "non_linear";
    path.linearization = undefined;
    expect(resolveLinearEvidence(path)).toBeNull();
  });

  it("rejects a claimed linearization that invents continuity", () => {
    const path = linearPath();
    path.linearization = {
      node_ids: ["a", "c", "b"],
      edge_indexes: [0, 1],
    };
    expect(resolveLinearEvidence(path)).toBeNull();
  });

  it("withholds a numeric verdict when path evidence is incomplete", () => {
    const path = linearPath();
    path.completeness = {
      state: "incomplete",
      reasons: ["edge_target_missing_node_1"],
    };
    expect(resolveLinearEvidence(path)).toBeNull();
  });
});
