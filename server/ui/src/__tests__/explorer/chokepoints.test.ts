import { describe, it, expect } from "vitest";
import {
  computeChokepoints,
  chokepointsToSizeMap,
} from "@/lib/explorer/chokepoints";
import type { APIEdge } from "@/api/types";

function edge(source: string, target: string, kind = "TRUSTS_SERVER"): APIEdge {
  return {
    source,
    target,
    kind,
    properties: {},
  };
}

describe("computeChokepoints", () => {
  it("returns empty list for empty input", () => {
    expect(computeChokepoints([])).toEqual([]);
  });

  it("ranks nodes by combined degree descending", () => {
    const edges: APIEdge[] = [
      edge("a", "hub"),
      edge("b", "hub"),
      edge("c", "hub"),
      edge("hub", "x"),
      edge("hub", "y"),
      edge("a", "x"),
    ];
    const result = computeChokepoints(edges);
    expect(result[0]?.nodeId).toBe("hub");
    expect(result[0]?.inDegree).toBe(3);
    expect(result[0]?.outDegree).toBe(2);
    expect(result[0]?.total).toBe(5);
  });

  it("normalizes score to max total degree", () => {
    const edges: APIEdge[] = [
      edge("a", "hub"),
      edge("b", "hub"),
      edge("c", "leaf"),
    ];
    const result = computeChokepoints(edges);
    const hub = result.find((r) => r.nodeId === "hub")!;
    const leaf = result.find((r) => r.nodeId === "leaf")!;
    expect(hub.score).toBe(1);
    expect(leaf.score).toBe(0.5);
  });

  it("respects topN limit", () => {
    const edges: APIEdge[] = [
      edge("a", "b"),
      edge("c", "d"),
      edge("e", "f"),
      edge("g", "h"),
      edge("i", "j"),
    ];
    const result = computeChokepoints(edges, 3);
    expect(result.length).toBeLessThanOrEqual(3);
  });

  it("ignores self-loops for degree computation", () => {
    const edges: APIEdge[] = [
      edge("self", "self"),
      edge("a", "b"),
    ];
    const result = computeChokepoints(edges);
    const self = result.find((r) => r.nodeId === "self");
    expect(self?.inDegree ?? 0).toBe(0);
    expect(self?.outDegree ?? 0).toBe(0);
  });
});

describe("chokepointsToSizeMap", () => {
  it("maps highest-score node to the largest multiplier", () => {
    const edges: APIEdge[] = [
      edge("a", "hub"),
      edge("b", "hub"),
      edge("c", "hub"),
      edge("c", "leaf"),
    ];
    const scores = computeChokepoints(edges);
    const map = chokepointsToSizeMap(scores);
    expect(map.get("hub")).toBeCloseTo(2.2, 1);
  });

  it("returns an empty map for empty input", () => {
    expect(chokepointsToSizeMap([]).size).toBe(0);
  });
});
