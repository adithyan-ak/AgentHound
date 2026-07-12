import type { AttackPath, AttackPathNode } from "@entities/finding/model";

// A spine item is one visual segment of the attack-path strip. Nodes and edges
// are emitted in the server's edge-array order so the hop index stays in lock-
// step with the Hop Evidence timeline (which keys off `path.edges[i]`). A `gap`
// is an explicit discontinuity marker — rendered when two consecutive evidence
// edges do not share an endpoint, or when no path was reconstructed at all. A
// gap is NEVER a fabricated edge: it discloses a missing join rather than
// inventing a hop the graph did not observe.
export type SpineItem =
  | { kind: "node"; node: AttackPathNode; key: string }
  | { kind: "edge"; edgeKind: string; index: number; key: string }
  | { kind: "gap"; key: string };

export interface PathSpine {
  items: SpineItem[];
  /** Number of real evidence edges (= `path.edges.length`). */
  hopCount: number;
  /**
   * True only when the evidence forms one continuous chain — every consecutive
   * edge shares an endpoint and at least one edge exists. When false the strip
   * discloses that the path is not a single proven chain.
   */
  continuous: boolean;
  /** True when there is at least one evidence edge to render. */
  hasPath: boolean;
  /** Distinct disconnected segments implied by the edge list (>=1). */
  segments: number;
}

/**
 * Build a faithful visual spine from a finding's attack path.
 *
 * Honesty rules:
 *  - Edges are rendered in their observed array order; nodes are never
 *    re-linearized in a way that silently drops branch members.
 *  - When consecutive edges do not connect (target !== next source) an explicit
 *    `gap` is inserted — the diagram shows a break, not an invented hop.
 *  - When no edges exist, the source and target are shown as two endpoints
 *    separated by a `gap`; no "—" edge is fabricated between them.
 */
export function buildPathSpine(
  path: AttackPath | null,
  fallback: { source: AttackPathNode; target: AttackPathNode },
): PathSpine {
  const nodeMap = new Map<string, AttackPathNode>(
    (path?.nodes ?? []).map((n) => [n.id, n]),
  );

  const resolve = (id: string): AttackPathNode =>
    nodeMap.get(id) ??
    (id === fallback.source.id
      ? fallback.source
      : id === fallback.target.id
        ? fallback.target
        : { id, kinds: [], properties: {} });

  const edges = path?.edges ?? [];

  // No hop evidence: show the two endpoints with an explicit unresolved gap.
  // Never draw a labeled edge between them — the intermediate path is unknown.
  if (edges.length === 0) {
    const endpoints =
      path && path.nodes.length > 0 ? path.nodes : [fallback.source, fallback.target];
    const items: SpineItem[] = [];
    endpoints.forEach((node, i) => {
      if (i > 0) items.push({ kind: "gap", key: `gap-${i}` });
      items.push({ kind: "node", node, key: `node-${node.id}-${i}` });
    });
    return {
      items,
      hopCount: 0,
      continuous: false,
      hasPath: false,
      segments: endpoints.length > 0 ? endpoints.length : 0,
    };
  }

  const items: SpineItem[] = [];
  let segments = 1;
  let continuous = true;

  const first = resolve(edges[0]!.source);
  items.push({ kind: "node", node: first, key: `node-${first.id}-0` });

  edges.forEach((edge, i) => {
    if (i > 0 && edges[i - 1]!.target !== edge.source) {
      // Discontinuity: the previous edge did not end where this one begins.
      // Disclose the break and start a new node rather than pretend continuity.
      continuous = false;
      segments++;
      items.push({ kind: "gap", key: `gap-${i}` });
      const src = resolve(edge.source);
      items.push({ kind: "node", node: src, key: `node-${src.id}-${i}-s` });
    }
    items.push({ kind: "edge", edgeKind: edge.kind, index: i, key: `edge-${i}` });
    const tgt = resolve(edge.target);
    items.push({ kind: "node", node: tgt, key: `node-${tgt.id}-${i}-t` });
  });

  return { items, hopCount: edges.length, continuous, hasPath: true, segments };
}
