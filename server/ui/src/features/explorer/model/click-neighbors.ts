import type { APIEdge } from "@entities/graph/dto";
import type { HighlightState } from "./store";
import {
  buildAdjacencyIndex,
  bfsFrom,
  type TraversalDirection,
} from "@shared/lib/graph/traverse";

export interface ClickScope {
  /** Exact directional `${source}|${target}|${kind}` keys rendered by the lens. */
  edgeIds: ReadonlySet<string>;
  maxHops?: number;
  direction?: TraversalDirection;
}

/**
 * Compute the click-highlight scope for a node under the current lens.
 *
 * Returns the set of node IDs and edge keys that should stay bright when
 * the user clicks a node. Everything else is dimmed to ~8% opacity.
 *
 * Scope comes directly from the relationships rendered after lens and
 * sub-preset filtering. This avoids a second hand-maintained allowlist that can
 * silently omit supported kinds or highlight hidden relationships.
 */
export function computeClickNeighbors(
  nodeId: string,
  edges: APIEdge[],
  scope: ClickScope,
): HighlightState {
  const maxHops = scope.maxHops ?? 1;
  const direction = scope.direction ?? "both";

  const index = buildAdjacencyIndex(edges);
  const { nodeIds, edgeKeys } = bfsFrom(nodeId, index, {
    maxHops,
    direction,
    edgeKey: (e) => `${e.source}|${e.target}|${e.kind}`,
    includeEdge: (e) =>
      scope.edgeIds.has(`${e.source}|${e.target}|${e.kind}`),
  });

  return {
    nodeIds: Array.from(nodeIds),
    edgeIds: Array.from(edgeKeys),
    title: `Connected · ${nodeIds.size - 1} neighbor${nodeIds.size === 2 ? "" : "s"}`,
  };
}
