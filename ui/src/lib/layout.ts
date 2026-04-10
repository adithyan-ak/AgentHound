import ELK, { type ElkNode, type ElkExtendedEdge } from "elkjs/lib/elk.bundled.js";
import type { Node, Edge } from "@xyflow/react";

const elk = new ELK();

const ZONE_OPTIONS: Record<string, string> = {
  "elk.algorithm": "layered",
  "elk.direction": "RIGHT",
  "elk.layered.layering.strategy": "NETWORK_SIMPLEX",
  "elk.layered.nodePlacement.strategy": "NETWORK_SIMPLEX",
  "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
  "elk.spacing.nodeNode": "30",
  "elk.spacing.edgeNode": "15",
  "elk.layered.spacing.nodeNodeBetweenLayers": "70",
};

const ZONE_PADDING = { top: 50, left: 30, bottom: 30, right: 30 };
const ZONE_GAP = 300;
const NODE_W = 200;
const NODE_H = 50;

export async function computeLayout(
  nodes: Node[],
  edges: Edge[],
): Promise<Node[]> {
  const zoneNodes = nodes.filter((n) => n.type === "agentZone");
  const childNodes = nodes.filter((n) => n.parentId);

  if (zoneNodes.length === 0) return nodes;

  const zoneChildren = new Map<string, Node[]>();
  for (const zone of zoneNodes) zoneChildren.set(zone.id, []);
  for (const child of childNodes) {
    const list = zoneChildren.get(child.parentId!);
    if (list) list.push(child);
  }

  const nodeParentMap = new Map<string, string>();
  for (const n of nodes) {
    if (n.parentId) nodeParentMap.set(n.id, n.parentId);
  }

  const zoneEdgeMap = new Map<string, Edge[]>();
  for (const zone of zoneNodes) zoneEdgeMap.set(zone.id, []);
  for (const edge of edges) {
    const srcZone = nodeParentMap.get(edge.source);
    const tgtZone = nodeParentMap.get(edge.target);
    if (srcZone && srcZone === tgtZone) {
      zoneEdgeMap.get(srcZone)!.push(edge);
    }
  }

  const positioned = new Map<string, { x: number; y: number }>();
  const zoneDims = new Map<string, { w: number; h: number }>();

  for (const zone of zoneNodes) {
    const children = zoneChildren.get(zone.id) ?? [];
    if (children.length === 0) {
      zoneDims.set(zone.id, { w: 250, h: 100 });
      continue;
    }

    const elkChildren: ElkNode[] = children.map((c) => ({
      id: c.id,
      width: NODE_W,
      height: NODE_H,
    }));

    const elkEdges: ElkExtendedEdge[] = [];
    const seen = new Set<string>();
    for (const e of zoneEdgeMap.get(zone.id) ?? []) {
      const key = `${e.source}->${e.target}`;
      if (seen.has(key)) continue;
      seen.add(key);
      elkEdges.push({ id: e.id, sources: [e.source], targets: [e.target] });
    }

    const result = await elk.layout({
      id: zone.id,
      layoutOptions: ZONE_OPTIONS,
      children: elkChildren,
      edges: elkEdges,
    });

    let maxX = 0;
    let maxY = 0;
    for (const child of result.children ?? []) {
      const x = (child.x ?? 0) + ZONE_PADDING.left;
      const y = (child.y ?? 0) + ZONE_PADDING.top;
      positioned.set(child.id, { x, y });
      maxX = Math.max(maxX, x + (child.width ?? NODE_W));
      maxY = Math.max(maxY, y + (child.height ?? NODE_H));
    }

    zoneDims.set(zone.id, {
      w: maxX + ZONE_PADDING.right,
      h: maxY + ZONE_PADDING.bottom,
    });
  }

  const attackSources = new Set<string>();
  const attackTargets = new Set<string>();
  for (const edge of edges) {
    if (edge.type !== "attack") continue;
    const srcZone = nodeParentMap.get(edge.source);
    const tgtZone = nodeParentMap.get(edge.target);
    if (srcZone && tgtZone && srcZone !== tgtZone) {
      attackSources.add(srcZone);
      attackTargets.add(tgtZone);
    }
  }

  const sortedZones = [...zoneNodes].sort((a, b) => {
    if (a.id === "orphan") return 1;
    if (b.id === "orphan") return -1;
    const aSource = attackSources.has(a.id) && !attackTargets.has(a.id);
    const bSource = attackSources.has(b.id) && !attackTargets.has(b.id);
    if (aSource && !bSource) return -1;
    if (!aSource && bSource) return 1;
    return (zoneChildren.get(b.id)?.length ?? 0) - (zoneChildren.get(a.id)?.length ?? 0);
  });

  let xOffset = 0;
  const zonePositions = new Map<string, { x: number; y: number }>();
  for (const zone of sortedZones) {
    zonePositions.set(zone.id, { x: xOffset, y: 0 });
    const dims = zoneDims.get(zone.id) ?? { w: 300, h: 200 };
    xOffset += dims.w + ZONE_GAP;
  }

  return nodes.map((node) => {
    if (node.type === "agentZone") {
      const pos = zonePositions.get(node.id) ?? { x: 0, y: 0 };
      const dims = zoneDims.get(node.id) ?? { w: 400, h: 300 };
      return {
        ...node,
        position: pos,
        style: { ...node.style, width: dims.w, height: dims.h },
      };
    }
    if (node.parentId) {
      const pos = positioned.get(node.id) ?? { x: 20, y: 50 };
      return { ...node, position: pos };
    }
    return node;
  });
}
