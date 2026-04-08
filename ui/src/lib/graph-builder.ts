import { MultiDirectedGraph } from "graphology";
import type { APINode, APIEdge } from "@/api/types";
import { getNodeColor, getNodeSize, getNodeLabel } from "./node-styles";
import { getEdgeColor, getEdgeSize } from "./edge-styles";

export function buildGraph(
  nodes: APINode[],
  edges: APIEdge[],
): MultiDirectedGraph {
  const graph = new MultiDirectedGraph();

  for (const node of nodes) {
    graph.addNode(node.id, {
      label: getNodeLabel(node),
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: getNodeSize(node),
      color: getNodeColor(node.kinds),
      _kind: node.kinds[0] ?? "Unknown",
      _kinds: node.kinds,
      _riskScore: Number(node.properties.risk_score ?? 0),
      _properties: node.properties,
    });
  }

  const edgeCounts = new Map<string, number>();

  for (const edge of edges) {
    if (!graph.hasNode(edge.source) || !graph.hasNode(edge.target)) continue;

    const baseKey = `${edge.source}-${edge.kind}-${edge.target}`;
    const count = edgeCounts.get(baseKey) ?? 0;
    edgeCounts.set(baseKey, count + 1);
    const edgeKey = `${baseKey}-${count}`;

    graph.addEdgeWithKey(edgeKey, edge.source, edge.target, {
      label: edge.kind,
      color: getEdgeColor(edge.kind),
      size: getEdgeSize(edge),
      _kind: edge.kind,
      _properties: edge.properties,
    });
  }

  return graph;
}
