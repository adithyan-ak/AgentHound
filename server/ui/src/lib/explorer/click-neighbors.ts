import type { APIEdge } from "@/api/types";
import type { LensId } from "@/store/explorer";
import type { HighlightState } from "@/store/explorer";

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
    "CAN_EXFILTRATE_VIA",
  ]),
  critical: new Set([
    "CAN_REACH",
    "CAN_EXFILTRATE_VIA",
    "POISONED_DESCRIPTION",
    "SHADOWS",
  ]),
  "cross-protocol": undefined, // cross-protocol detection is runtime, not kind-based
  credentials: new Set(["AUTHENTICATES_WITH", "USES_CREDENTIAL", "HAS_ENV_VAR"]),
  poisoning: new Set(["SHADOWS", "POISONED_DESCRIPTION", "POISONED_INSTRUCTIONS"]),
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

  const visitedNodes = new Set<string>([nodeId]);
  const visitedEdges: string[] = [];
  let frontier = [nodeId];

  for (let hop = 0; hop < maxHops && frontier.length > 0; hop++) {
    const next: string[] = [];
    for (const current of frontier) {
      for (const e of edges) {
        if (edgeFilter && !edgeFilter.has(e.kind)) continue;

        // Cross-protocol lens: only include edges crossing protocol domains
        if (activeLens === "cross-protocol") {
          const srcDomain = protocolDomain(e.source_kind ?? "");
          const tgtDomain = protocolDomain(e.target_kind ?? "");
          const isCross =
            e.properties?.cross_protocol === true ||
            (srcDomain !== "OTHER" &&
              tgtDomain !== "OTHER" &&
              srcDomain !== tgtDomain);
          if (!isCross) continue;
        }

        const edgeKey = `${e.source}|${e.target}|${e.kind}`;

        // Outbound from current
        if (e.source === current && !visitedNodes.has(e.target)) {
          visitedNodes.add(e.target);
          visitedEdges.push(edgeKey);
          next.push(e.target);
        } else if (e.source === current && visitedNodes.has(e.target)) {
          visitedEdges.push(edgeKey);
        }

        // Inbound to current (bidirectional for all lenses except blast-radius)
        if (activeLens !== "blast-radius") {
          if (e.target === current && !visitedNodes.has(e.source)) {
            visitedNodes.add(e.source);
            visitedEdges.push(edgeKey);
            next.push(e.source);
          } else if (e.target === current && visitedNodes.has(e.source)) {
            visitedEdges.push(edgeKey);
          }
        }
      }
    }
    frontier = next;
  }

  return {
    nodeIds: Array.from(visitedNodes),
    edgeIds: visitedEdges,
    title: `Connected · ${visitedNodes.size - 1} neighbor${visitedNodes.size === 2 ? "" : "s"}`,
  };
}

const MCP_KINDS = new Set([
  "MCPServer",
  "MCPTool",
  "MCPResource",
  "MCPPrompt",
]);
const A2A_KINDS = new Set(["A2AAgent", "A2ASkill"]);

function protocolDomain(kind: string): "MCP" | "A2A" | "OTHER" {
  if (MCP_KINDS.has(kind)) return "MCP";
  if (A2A_KINDS.has(kind)) return "A2A";
  return "OTHER";
}
