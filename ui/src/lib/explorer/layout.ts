import ELK, { type ElkNode, type ElkExtendedEdge } from "elkjs/lib/elk-api.js";
import ElkWorker from "elkjs/lib/elk-worker.min.js?worker";
import type { Node, Edge } from "@xyflow/react";
import { HEX_NODE_WIDTH, HEX_TOTAL_HEIGHT } from "./hex-config";

const elk = new ELK({
  workerFactory: () => new ElkWorker() as unknown as Worker,
});

/**
 * ELK options for top-to-bottom flow. Layers are horizontal ROWS; nodes
 * at the same depth spread horizontally within each row. No forced
 * partitioning — ELK assigns layers based on edge topology, so nodes
 * from different subgraphs land side-by-side in the same row, making
 * the graph wide and short instead of tall and narrow.
 */
const ELK_OPTIONS: Record<string, string> = {
  "elk.algorithm": "layered",
  "elk.direction": "DOWN",
  "elk.layered.layering.strategy": "NETWORK_SIMPLEX",
  "elk.layered.nodePlacement.strategy": "NETWORK_SIMPLEX",
  "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
  "elk.spacing.nodeNode": "40",
  "elk.layered.spacing.nodeNodeBetweenLayers": "120",
  "elk.layered.spacing.edgeNodeBetweenLayers": "30",
  "elk.spacing.edgeNode": "16",
};

export interface LayoutResult<T extends Node = Node> {
  nodes: T[];
  bounds: { width: number; height: number };
}

/**
 * Gap between the bottom of the connected graph and the cluster strip.
 */
const CLUSTER_STRIP_GAP = 120;

/**
 * Horizontal spacing between cluster hexes inside the bottom strip.
 * Larger than normal column spacing to give the labels room to breathe.
 */
const CLUSTER_STRIP_SPACING = 150;

/**
 * Compute left-to-right column layout for hex nodes, with orphan-cluster
 * nodes placed in a dedicated horizontal strip BELOW the main graph.
 *
 * Connected (type="hex") nodes are laid out by ELK's layered algorithm
 * with per-kind partitioning so they land in strict left-to-right
 * columns. Orphan-cluster (type="orphan-cluster") nodes are removed
 * from the ELK input entirely and manually positioned in a horizontal
 * strip anchored to the bottom of the connected graph's bounding box.
 * This keeps the main graph layout stable when showOrphans is toggled
 * on/off, and gives the unconnected nodes a clear visual "parking lot"
 * separate from the active attack graph.
 */
export async function computeExplorerLayout<T extends Node = Node>(
  nodes: T[],
  edges: Edge[],
): Promise<LayoutResult<T>> {
  if (nodes.length === 0) return { nodes, bounds: { width: 0, height: 0 } };

  const connectedNodes: T[] = [];
  const clusterNodes: T[] = [];
  for (const n of nodes) {
    if (n.type === "orphan-cluster") clusterNodes.push(n);
    else connectedNodes.push(n);
  }

  const positions = new Map<string, { x: number; y: number }>();
  let mainMaxX = 0;
  let mainMaxY = 0;
  let mainMinX = Number.POSITIVE_INFINITY;

  if (connectedNodes.length > 0) {
    const elkChildren: ElkNode[] = connectedNodes.map((n) => ({
      id: n.id,
      width: HEX_NODE_WIDTH,
      height: HEX_TOTAL_HEIGHT,
    }));

    const connectedIds = new Set(connectedNodes.map((n) => n.id));
    const elkEdges: ElkExtendedEdge[] = [];
    const seen = new Set<string>();
    for (const e of edges) {
      if (!connectedIds.has(e.source) || !connectedIds.has(e.target)) continue;
      const key = `${e.source}->${e.target}`;
      if (seen.has(key)) continue;
      seen.add(key);
      elkEdges.push({
        id: e.id,
        sources: [e.source],
        targets: [e.target],
      });
    }

    const result = await elk.layout({
      id: "explorer-root",
      layoutOptions: ELK_OPTIONS,
      children: elkChildren,
      edges: elkEdges,
    });

    for (const child of result.children ?? []) {
      const x = child.x ?? 0;
      const y = child.y ?? 0;
      positions.set(child.id, { x, y });
      if (x < mainMinX) mainMinX = x;
      if (x + HEX_NODE_WIDTH > mainMaxX) mainMaxX = x + HEX_NODE_WIDTH;
      if (y + HEX_TOTAL_HEIGHT > mainMaxY) mainMaxY = y + HEX_TOTAL_HEIGHT;
    }
  } else {
    mainMinX = 0;
    mainMaxX = 0;
    mainMaxY = 0;
  }

  // Place cluster nodes in a horizontal strip below the connected graph.
  // The strip is horizontally centered on the connected graph's midpoint
  // so it reads as "unconnected inventory" sitting directly under the
  // active graph.
  let finalMaxX = mainMaxX;
  let finalMaxY = mainMaxY;
  if (clusterNodes.length > 0) {
    const stripY = mainMaxY + CLUSTER_STRIP_GAP;
    const stripTotalWidth = clusterNodes.length * CLUSTER_STRIP_SPACING;
    const mainMidX = (mainMinX + mainMaxX) / 2;
    const stripStartX = mainMidX - stripTotalWidth / 2;
    for (let i = 0; i < clusterNodes.length; i++) {
      const n = clusterNodes[i]!;
      const x = stripStartX + i * CLUSTER_STRIP_SPACING;
      positions.set(n.id, { x, y: stripY });
      if (x + HEX_NODE_WIDTH > finalMaxX) {
        finalMaxX = x + HEX_NODE_WIDTH;
      }
    }
    finalMaxY = stripY + HEX_TOTAL_HEIGHT;
  }

  const positioned = nodes.map((n) => {
    const pos = positions.get(n.id);
    if (!pos) return n;
    return { ...n, position: pos };
  });

  return {
    nodes: positioned,
    bounds: { width: finalMaxX, height: finalMaxY },
  };
}
