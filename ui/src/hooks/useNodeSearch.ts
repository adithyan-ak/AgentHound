import { useMemo, useCallback } from "react";
import { useSigma } from "@react-sigma/core";
import type { MultiDirectedGraph } from "graphology";

export interface SearchResult {
  id: string;
  name: string;
  kind: string;
}

export function useNodeSearch(graph: MultiDirectedGraph | null) {
  const sigma = useSigma();

  const search = useCallback(
    (query: string): SearchResult[] => {
      if (!graph || !query || query.length < 2) return [];

      const lower = query.toLowerCase();
      const results: SearchResult[] = [];

      graph.forEachNode((id, attrs) => {
        if (results.length >= 20) return;
        const label = String(attrs.label ?? "").toLowerCase();
        const kind = String(attrs._kind ?? "").toLowerCase();
        if (label.includes(lower) || kind.includes(lower)) {
          results.push({
            id,
            name: String(attrs.label ?? id),
            kind: String(attrs._kind ?? "Unknown"),
          });
        }
      });

      return results;
    },
    [graph],
  );

  const focusNode = useCallback(
    (nodeId: string) => {
      if (!graph?.hasNode(nodeId)) return;
      const attrs = graph.getNodeAttributes(nodeId);
      const camera = sigma.getCamera();
      camera.animate(
        { x: attrs.x as number, y: attrs.y as number, ratio: 0.1 },
        { duration: 500 },
      );
    },
    [graph, sigma],
  );

  return useMemo(() => ({ search, focusNode }), [search, focusNode]);
}
