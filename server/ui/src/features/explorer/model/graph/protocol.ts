import type { APIEdge } from "@entities/graph/dto";

/**
 * The single source of truth for protocol-domain classification. Both the
 * graph builder's cross-protocol detection and the click-highlight traversal
 * resolve a node kind to its protocol domain through here.
 */
export const MCP_NODE_KINDS = new Set([
  "MCPServer",
  "MCPTool",
  "MCPResource",
  "MCPPrompt",
]);

export const A2A_NODE_KINDS = new Set(["A2AAgent", "A2ASkill"]);

export function protocolDomain(kind: string): "MCP" | "A2A" | "OTHER" {
  if (MCP_NODE_KINDS.has(kind)) return "MCP";
  if (A2A_NODE_KINDS.has(kind)) return "A2A";
  return "OTHER";
}

/**
 * Determine whether an edge crosses the A2A ↔ MCP protocol boundary.
 * Derives the boundary from endpoint kinds rather than a summary marker.
 */
export function isCrossProtocolEdge(
  e: APIEdge,
  sourceKind: string,
  targetKind: string,
): boolean {
  // Explicit marker from the post-processor takes precedence if set.
  if (e.properties?.cross_protocol === true) return true;
  const src = protocolDomain(sourceKind);
  const tgt = protocolDomain(targetKind);
  if (src === "OTHER" || tgt === "OTHER") return false;
  return src !== tgt;
}
