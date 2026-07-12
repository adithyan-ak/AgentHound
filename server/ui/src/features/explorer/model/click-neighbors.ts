import type { APIEdge } from "@entities/graph/dto";
import type { LensId, HighlightState } from "./store";
import { protocolDomain } from "./graph/protocol";
import {
  buildAdjacencyIndex,
  bfsFrom,
  type TraversalDirection,
} from "@shared/lib/graph/traverse";

/**
 * Edge kinds that each lens considers "connected" for the click-highlight.
 * Lenses not listed here use ALL edge kinds (same as Topology).
 */
const LENS_EDGE_FILTER: Partial<Record<LensId, Set<string>>> = {
  topology: undefined, // all edges
  "attack-surface": new Set([
    "HAS_ACCESS_TO",
    "CAN_EXECUTE",
    "CAN_REACH",
    "CAN_REACH_CROSS_PROTOCOL",
    "CAN_EXFILTRATE_VIA",
    "CAN_IMPERSONATE",
    "CONFUSED_DEPUTY",
  ]),
  critical: new Set([
    "CAN_REACH",
    "CAN_REACH_CROSS_PROTOCOL",
    "CAN_EXFILTRATE_VIA",
    "POISONED_DESCRIPTION",
    "SHADOWS",
  ]),
  "cross-protocol": undefined, // cross-protocol detection is runtime, not kind-based
  credentials: new Set([
    "AUTHENTICATES_WITH",
    "USES_CREDENTIAL",
    "HAS_ENV_VAR",
    "EXPOSES_CREDENTIAL",
    "CAN_REACH_CREDENTIAL_CHAIN",
  ]),
  poisoning: new Set([
    "SHADOWS",
    "POISONED_DESCRIPTION",
    "POISONED_INSTRUCTIONS",
    "INGESTS_UNTRUSTED",
    "TAINTS",
    "IFC_VIOLATION",
    "POISONS_CONTEXT",
  ]),
  "blast-radius": undefined,
  chokepoints: undefined,
};

/**
 * Number of BFS hops per lens. Credentials uses 2 hops to trace the full
 * server → identity → credential chain. Everything else is 1-hop (direct
 * neighbors only).
 */
const LENS_MAX_HOPS: Partial<Record<LensId, number>> = {
  credentials: 2,
};

/**
 * Compute the click-highlight scope for a node under the current lens.
 *
 * Returns the set of node IDs and edge keys that should stay bright when
 * the user clicks a node. Everything else is dimmed to ~8% opacity.
 *
 * The neighbor set is lens-aware:
 * - Topology: all direct raw edges
 * - Attack Surface: only composite edges (what can this node exploit?)
 * - Critical: only high-severity composite edges
 * - Cross-Protocol: only edges crossing protocol boundaries
 * - Credentials: 2-hop chain (server → identity → credential)
 * - Poisoning: only shadowing / poisoned edges
 * - Blast Radius: all outbound edges (reinforces the blast semantics)
 * - Chokepoints: all edges (shows the full congestion)
 */
export function computeClickNeighbors(
  nodeId: string,
  edges: APIEdge[],
  activeLens: LensId,
): HighlightState {
  const maxHops = LENS_MAX_HOPS[activeLens] ?? 1;
  const edgeFilter = LENS_EDGE_FILTER[activeLens];
  // Blast radius follows outbound edges only; every other lens is bidirectional.
  const direction: TraversalDirection =
    activeLens === "blast-radius" ? "out" : "both";

  const index = buildAdjacencyIndex(edges);
  const { nodeIds, edgeKeys } = bfsFrom(nodeId, index, {
    maxHops,
    direction,
    edgeKey: (e) => `${e.source}|${e.target}|${e.kind}`,
    includeEdge: (e) => {
      if (edgeFilter && !edgeFilter.has(e.kind)) return false;
      // Cross-protocol lens: only include edges crossing protocol domains.
      if (activeLens === "cross-protocol") {
        const srcDomain = protocolDomain(e.source_kind ?? "");
        const tgtDomain = protocolDomain(e.target_kind ?? "");
        const isCross =
          e.properties?.cross_protocol === true ||
          (srcDomain !== "OTHER" &&
            tgtDomain !== "OTHER" &&
            srcDomain !== tgtDomain);
        if (!isCross) return false;
      }
      return true;
    },
  });

  return {
    nodeIds: Array.from(nodeIds),
    edgeIds: Array.from(edgeKeys),
    title: `Connected · ${nodeIds.size - 1} neighbor${nodeIds.size === 2 ? "" : "s"}`,
  };
}
