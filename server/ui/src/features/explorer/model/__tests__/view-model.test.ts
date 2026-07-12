import { describe, it, expect } from "vitest";
import {
  computeTotals,
  buildRenderGraph,
  buildLensMetrics,
} from "../view-model";
import { buildExplorerGraph, type HexNodeData } from "../graph";
import { getLens } from "../lens-config";
import type { ExplorerRawData } from "../useExplorerGraph";
import type { BlastRadiusData } from "../useBlastRadius";
import type { APIEdge, APINode } from "@entities/graph/dto";
import type { Finding } from "@entities/finding/model";

function n(id: string, kind: string): APINode {
  return { id, kinds: [kind], properties: { name: id } };
}

function e(
  source: string,
  target: string,
  kind: string,
  props: Record<string, unknown> = {},
): APIEdge {
  return { source, target, kind, properties: props };
}

const NODES: APINode[] = [
  n("agent-1", "AgentInstance"),
  n("server-1", "MCPServer"),
  n("tool-1", "MCPTool"),
  n("resource-1", "MCPResource"),
];

const EDGES: APIEdge[] = [
  e("agent-1", "server-1", "TRUSTS_SERVER"),
  e("server-1", "tool-1", "PROVIDES_TOOL"),
  e("agent-1", "resource-1", "CAN_REACH", { is_composite: true, confidence: 0.95 }),
  e("tool-1", "resource-1", "HAS_ACCESS_TO", { is_composite: true, confidence: 0.9 }),
];

const FINDINGS: Finding[] = [
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
    owasp_map: [],
  },
];

const DATA: ExplorerRawData = { nodes: NODES, edges: EDGES, findings: FINDINGS };

const ATTACK = getLens("attack-surface");
const ATTACK_PRESETS = [...ATTACK.edgeKinds];

function hexById(nodes: { id: string; data: unknown }[], id: string) {
  return nodes.find((node) => node.id === id)?.data as HexNodeData | undefined;
}

describe("explorer view-model — three distinct shapes", () => {
  // ---- (1) raw totals ----
  describe("computeTotals", () => {
    it("returns raw node/edge/finding counts", () => {
      expect(computeTotals(DATA)).toEqual({
        nodeCount: 4,
        edgeCount: 4,
        findingCount: 1,
        truncated: false,
      });
    });

    it("is zero-safe when data has not loaded", () => {
      expect(computeTotals(undefined)).toEqual({
        nodeCount: 0,
        edgeCount: 0,
        findingCount: 0,
        truncated: false,
      });
    });

    it("does not depend on the active lens", () => {
      // Totals are inventory counts; switching lenses can't change them.
      expect(computeTotals(DATA)).toEqual({
        nodeCount: 4,
        edgeCount: 4,
        findingCount: 1,
        truncated: false,
      });
    });
  });

  // ---- (3) lens-only metrics for InfoCard ----
  describe("buildLensMetrics", () => {
    it("equals the lens-only graph build's metrics exactly", () => {
      const metrics = buildLensMetrics(DATA, {
        activeLens: "attack-surface",
        subPresets: ATTACK_PRESETS,
        blastData: undefined,
        blastRadiusSourceId: null,
        showOrphans: false,
      });
      const direct = buildExplorerGraph(
        { nodes: NODES, edges: EDGES },
        {
          lens: ATTACK,
          activeLensId: "attack-surface",
          subPresets: ATTACK_PRESETS,
          findings: FINDINGS,
          showOrphans: false,
        },
      ).metrics;
      expect(metrics).toEqual(direct);
    });

    it("pins the attack-surface lens numbers (2 composite edges, 1 critical)", () => {
      const metrics = buildLensMetrics(DATA, {
        activeLens: "attack-surface",
        subPresets: ATTACK_PRESETS,
        blastData: undefined,
        blastRadiusSourceId: null,
        showOrphans: false,
      });
      expect(metrics.visibleEdgeCount).toBe(2);
      expect(metrics.criticalCount).toBe(1);
    });

    it("reflects blast-radius scope so the InfoCard tracks the canvas", () => {
      // The card is blast-radius-aware: with a blast source + data it counts
      // the in-scope subgraph edges (matching buildRenderGraph's metrics)
      // instead of reading 0 on the blast-radius lens.
      const blastData = {
        nodes: [],
        edges: [],
        rings: {},
        nodeIdSet: new Set(["agent-1", "resource-1"]),
        edgeKeySet: new Set(["agent-1|resource-1|CAN_REACH"]),
      } as unknown as BlastRadiusData;

      const metrics = buildLensMetrics(DATA, {
        activeLens: "blast-radius",
        subPresets: [],
        blastData,
        blastRadiusSourceId: "agent-1",
        showOrphans: false,
      });
      expect(metrics.visibleEdgeCount).toBe(1);
    });

    it("selects no edges on the blast-radius lens until blast data loads", () => {
      // Without blast data the scope is undefined, so the build can't select
      // any in-scope edges yet — the card reads 0 only in this transient state.
      const metrics = buildLensMetrics(DATA, {
        activeLens: "blast-radius",
        subPresets: [],
        blastData: undefined,
        blastRadiusSourceId: "agent-1",
        showOrphans: false,
      });
      expect(metrics.visibleEdgeCount).toBe(0);
    });
  });

  // ---- (2) full-option render graph for the canvas ----
  describe("buildRenderGraph", () => {
    it("reflects the owned mark while the lens-only build does not", () => {
      const render = buildRenderGraph(DATA, {
        activeLens: "attack-surface",
        subPresets: ATTACK_PRESETS,
        blastData: undefined,
        blastRadiusSourceId: null,
        showOrphans: false,
        ownedSet: new Set(["resource-1"]),
        highValueSet: new Set(),
        highlight: null,
      });
      expect(hexById(render.nodes, "resource-1")?.owned).toBe(true);

      // The InfoCard build never receives the marks, so the same node is
      // un-owned there — proving the two shapes are genuinely distinct.
      const lensOnly = buildExplorerGraph(
        { nodes: NODES, edges: EDGES },
        {
          lens: ATTACK,
          activeLensId: "attack-surface",
          subPresets: ATTACK_PRESETS,
          findings: FINDINGS,
        },
      );
      expect(hexById(lensOnly.nodes, "resource-1")?.owned).toBe(false);
    });

    it("reflects blast-radius scope when blast data is present", () => {
      const blastData = {
        nodes: [],
        edges: [],
        rings: {},
        nodeIdSet: new Set(["agent-1", "resource-1"]),
        edgeKeySet: new Set(["agent-1|resource-1|CAN_REACH"]),
      } as unknown as BlastRadiusData;

      const render = buildRenderGraph(DATA, {
        activeLens: "blast-radius",
        subPresets: [],
        blastData,
        blastRadiusSourceId: "agent-1",
        showOrphans: false,
        ownedSet: new Set(),
        highValueSet: new Set(),
        highlight: null,
      });

      // The single in-scope edge is rendered and visible — whereas the
      // lens-only metrics for blast-radius reported 0.
      expect(render.metrics.visibleEdgeCount).toBe(1);
      expect(hexById(render.nodes, "agent-1")?.emphasized).toBe(true);
    });

    it("applies the highlight scope (canvas-only), dimming non-highlighted nodes", () => {
      const render = buildRenderGraph(DATA, {
        activeLens: "attack-surface",
        subPresets: ATTACK_PRESETS,
        blastData: undefined,
        blastRadiusSourceId: null,
        showOrphans: false,
        ownedSet: new Set(),
        highValueSet: new Set(),
        highlight: { nodeIds: new Set(["agent-1"]), edgeIds: new Set() },
      });
      // agent-1 stays bright; resource-1 is dimmed by the highlight.
      expect(hexById(render.nodes, "agent-1")?.dim).toBe(false);
      expect(hexById(render.nodes, "resource-1")?.dim).toBe(true);
    });
  });
});
