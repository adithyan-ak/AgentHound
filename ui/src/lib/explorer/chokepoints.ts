import type { APIEdge } from "@/api/types";

export interface ChokepointScore {
  nodeId: string;
  inDegree: number;
  outDegree: number;
  total: number;
  score: number; // normalized 0..1
}

/**
 * Pure function: compute chokepoint scores from an edge list.
 *
 * A chokepoint is a node with high combined in/out degree — compromising it
 * breaks the most paths in the graph. Score is `in + out` normalized to the
 * maximum observed. Returns the top N (default 20) sorted descending by
 * total degree.
 */
export function computeChokepoints(
  edges: APIEdge[],
  topN = 20,
): ChokepointScore[] {
  const inDeg = new Map<string, number>();
  const outDeg = new Map<string, number>();
  const ids = new Set<string>();

  for (const e of edges) {
    // Self-loops contribute only one unit so degenerate nodes don't
    // dominate the ranking.
    if (e.source === e.target) {
      ids.add(e.source);
      continue;
    }
    ids.add(e.source);
    ids.add(e.target);
    outDeg.set(e.source, (outDeg.get(e.source) ?? 0) + 1);
    inDeg.set(e.target, (inDeg.get(e.target) ?? 0) + 1);
  }

  const scored: ChokepointScore[] = [];
  for (const id of ids) {
    const i = inDeg.get(id) ?? 0;
    const o = outDeg.get(id) ?? 0;
    scored.push({
      nodeId: id,
      inDegree: i,
      outDegree: o,
      total: i + o,
      score: 0,
    });
  }

  scored.sort((a, b) => b.total - a.total);
  const maxTotal = scored[0]?.total ?? 1;
  for (const s of scored) {
    s.score = maxTotal === 0 ? 0 : s.total / maxTotal;
  }

  return scored.slice(0, topN);
}

/**
 * Convert chokepoint scores into a `Map<nodeId, sizeMultiplier>` consumable
 * by the graph builder. Size multiplier ranges from 1.0 (lowest) to 2.2
 * (highest), providing a visible but bounded size difference between the
 * most central nodes and everything else.
 */
export function chokepointsToSizeMap(
  chokepoints: ChokepointScore[],
): Map<string, number> {
  const map = new Map<string, number>();
  for (const c of chokepoints) {
    map.set(c.nodeId, 1 + c.score * 1.2);
  }
  return map;
}
