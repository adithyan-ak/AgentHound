import { describe, it, expect } from "vitest";
import { buildPathSpine } from "../attack-path-spine";
import type { AttackPath, AttackPathNode } from "@entities/finding/model";

const src: AttackPathNode = { id: "s", kinds: ["Agent"], properties: { name: "src" } };
const tgt: AttackPathNode = { id: "t", kinds: ["Credential"], properties: { name: "tgt" } };
const fallback = { source: src, target: tgt };

function node(id: string): AttackPathNode {
  return { id, kinds: ["MCPServer"], properties: { name: id } };
}

describe("buildPathSpine", () => {
  it("renders a single continuous chain in edge order with no gaps", () => {
    const path: AttackPath = {
      nodes: [src, node("m"), tgt],
      edges: [
        { source: "s", target: "m", kind: "CAN_REACH", properties: {} },
        { source: "m", target: "t", kind: "HAS_ACCESS_TO", properties: {} },
      ],
      total_risk_weight: 1.5,
    };
    const spine = buildPathSpine(path, fallback);
    expect(spine.hasPath).toBe(true);
    expect(spine.continuous).toBe(true);
    expect(spine.segments).toBe(1);
    expect(spine.hopCount).toBe(2);
    // node, edge(0), node, edge(1), node
    expect(spine.items.map((i) => i.kind)).toEqual([
      "node",
      "edge",
      "node",
      "edge",
      "node",
    ]);
    // Edge indices stay aligned with path.edges for the shared hop focus.
    const edgeItems = spine.items.filter((i) => i.kind === "edge");
    expect(edgeItems.map((e) => (e.kind === "edge" ? e.index : -1))).toEqual([0, 1]);
    // No gap markers are inserted.
    expect(spine.items.some((i) => i.kind === "gap")).toBe(false);
  });

  it("discloses a break instead of inventing a hop when edges are disconnected", () => {
    const path: AttackPath = {
      nodes: [src, node("m"), node("x"), tgt],
      edges: [
        { source: "s", target: "m", kind: "CAN_REACH", properties: {} },
        // Discontinuity: previous edge ended at "m", this one starts at "x".
        { source: "x", target: "t", kind: "HAS_ACCESS_TO", properties: {} },
      ],
      total_risk_weight: null,
    };
    const spine = buildPathSpine(path, fallback);
    expect(spine.continuous).toBe(false);
    expect(spine.segments).toBe(2);
    expect(spine.items.some((i) => i.kind === "gap")).toBe(true);
    // Edge indices are still 0 and 1 (array order preserved).
    const edgeItems = spine.items.filter((i) => i.kind === "edge");
    expect(edgeItems.map((e) => (e.kind === "edge" ? e.index : -1))).toEqual([0, 1]);
  });

  it("never fabricates an edge between endpoints when there is no path", () => {
    const spine = buildPathSpine(null, fallback);
    expect(spine.hasPath).toBe(false);
    expect(spine.hopCount).toBe(0);
    expect(spine.continuous).toBe(false);
    // Two endpoints separated by an explicit gap — never an edge item.
    expect(spine.items.map((i) => i.kind)).toEqual(["node", "gap", "node"]);
    expect(spine.items.some((i) => i.kind === "edge")).toBe(false);
  });

  it("treats a path with nodes but no edges as unresolved endpoints", () => {
    const path: AttackPath = {
      nodes: [src, tgt],
      edges: [],
      total_risk_weight: null,
    };
    const spine = buildPathSpine(path, fallback);
    expect(spine.hasPath).toBe(false);
    expect(spine.items.some((i) => i.kind === "edge")).toBe(false);
    expect(spine.items.filter((i) => i.kind === "gap")).toHaveLength(1);
  });
});
