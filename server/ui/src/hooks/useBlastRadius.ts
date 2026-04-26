import { useQuery } from "@tanstack/react-query";
import { fetchBlastRadius, type BlastRadiusResponse } from "@/api/explorer";
import type { BlastDirection } from "@/store/explorer";

export interface BlastRadiusData extends BlastRadiusResponse {
  nodeIdSet: Set<string>;
  edgeKeySet: Set<string>;
}

/**
 * Fetch the blast radius subgraph for a given source node from the backend
 * endpoint added in Phase A. The result is augmented with Set<string>
 * indices for O(1) membership checks during graph rendering.
 */
export function useBlastRadius(
  sourceId: string | null,
  direction: BlastDirection,
  maxHops: number,
) {
  return useQuery({
    queryKey: ["explorer", "blast-radius", sourceId, direction, maxHops],
    queryFn: async (): Promise<BlastRadiusData> => {
      if (!sourceId) throw new Error("no source id");
      const raw = await fetchBlastRadius(sourceId, {
        direction,
        maxHops,
      });
      const nodeIdSet = new Set(raw.nodes.map((n) => n.id));
      const edgeKeySet = new Set(
        raw.edges.map((e) => `${e.source}|${e.target}|${e.kind}`),
      );
      return { ...raw, nodeIdSet, edgeKeySet };
    },
    enabled: sourceId !== null,
    staleTime: 30_000,
  });
}
